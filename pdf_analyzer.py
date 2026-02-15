# -*- coding: utf-8 -*-
"""
PDF Document Analyzer Module.
Extracts text from PDF files, identifies IOCs (IPs, domains, hashes, URLs, CVEs),
detects threat actors, attack types, target sectors, and MITRE techniques.
Stores results in the database and prepares data for Neo4j graph analysis.
"""

import json
import logging
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone

from models import UploadedDocument, IOCIndicator
from database import get_session
from config import (
    UPLOAD_DIR, THREAT_ACTORS, ATTACK_TYPE_KEYWORDS,
    SECTOR_KEYWORDS, MITRE_TECHNIQUE_PATTERNS,
    UKRAINE_KEYWORDS,
)

logger = logging.getLogger(__name__)

# ==================== IOC Regex Patterns ====================

# IPv4 address (with word boundaries to avoid false positives)
RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)

# IPv6 address (simplified)
RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
)

# Domain names (excluding common false positives)
RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|ru|ua|info|biz|xyz|top|cc|tk|pw|su|cn|de|uk|fr|'
    r'pro|me|live|online|site|tech|space|link|club|win|work|onion)\b',
    re.IGNORECASE
)

# URLs
RE_URL = re.compile(
    r'https?://[^\s<>"\')\]}{,]+',
    re.IGNORECASE
)

# Defanged IOCs: hxxp, [.], [:]
RE_DEFANGED_URL = re.compile(
    r'hxxps?://[^\s<>"\')\]}{,]+',
    re.IGNORECASE
)
RE_DEFANGED_DOT = re.compile(r'\[\.\]')
RE_DEFANGED_COLON = re.compile(r'\[:\]')

# Hash patterns
RE_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
RE_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')

# CVE
RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

# Email
RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

# MITRE ATT&CK Technique IDs
RE_MITRE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

# Common false positive domains to exclude
DOMAIN_EXCLUDE = {
    'example.com', 'example.org', 'example.net',
    'google.com', 'microsoft.com', 'apple.com',
    'github.com', 'wikipedia.org',
    'w3.org', 'w3schools.com', 'mozilla.org',
    'schema.org', 'doi.org', 'ietf.org',
    'creativecommons.org', 'arxiv.org',
}

# Common false-positive words that look like hex hashes
HASH_EXCLUDE_WORDS = {
    'abcdefabcdefabcdefabcdefabcdefab',  # too uniform
}


def extract_text_from_pdf(filepath):
    """
    Extract text from a PDF file using PyMuPDF (fitz).
    Returns (text, page_count).
    """
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(filepath)
        page_count = len(doc)
        text_parts = []
        for page in doc:
            text_parts.append(page.get_text())
        doc.close()
        return '\n'.join(text_parts), page_count
    except Exception as e:
        logger.error(f"PyMuPDF failed for {filepath}: {e}")
        # Fallback to PyPDF2
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(filepath)
            page_count = len(reader.pages)
            text_parts = []
            for page in reader.pages:
                t = page.extract_text()
                if t:
                    text_parts.append(t)
            return '\n'.join(text_parts), page_count
        except Exception as e2:
            logger.error(f"PyPDF2 also failed for {filepath}: {e2}")
            return '', 0


def extract_text_from_txt(filepath):
    """Extract text from a plain text file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read()
        lines = text.count('\n') + 1
        return text, lines
    except Exception as e:
        logger.error(f"Failed to read text file {filepath}: {e}")
        return '', 0


def _refang_text(text):
    """Convert defanged IOCs to normal form for analysis."""
    text = RE_DEFANGED_URL.sub(lambda m: m.group(0).replace('hxxp', 'http'), text)
    text = RE_DEFANGED_DOT.sub('.', text)
    text = RE_DEFANGED_COLON.sub(':', text)
    return text


def extract_iocs(text):
    """
    Extract IOC indicators from text.
    Returns dict: {type: [list of values]}
    """
    # Refang defanged IOCs
    clean_text = _refang_text(text)

    iocs = {
        'ipv4': [],
        'ipv6': [],
        'domains': [],
        'urls': [],
        'md5': [],
        'sha1': [],
        'sha256': [],
        'cve': [],
        'emails': [],
    }

    # Extract URLs first (to avoid domain false positives from URLs)
    urls = set(RE_URL.findall(clean_text))
    iocs['urls'] = sorted(urls)[:200]

    # Extract domains (exclude those already in URLs)
    url_domains = set()
    for u in urls:
        try:
            # Extract domain from URL
            from urllib.parse import urlparse
            parsed = urlparse(u)
            if parsed.hostname:
                url_domains.add(parsed.hostname.lower())
        except Exception:
            pass

    domains = set(RE_DOMAIN.findall(clean_text))
    domains = {d.lower() for d in domains}
    domains -= url_domains
    domains -= DOMAIN_EXCLUDE
    # Remove common file extensions misidentified as domains
    domains = {d for d in domains if not d.endswith(('.pdf.com', '.doc.com', '.exe.com'))}
    iocs['domains'] = sorted(domains)[:200]

    # Extract IPs
    ips = set(RE_IPV4.findall(clean_text))
    # Filter out private IPs and common false positives
    filtered_ips = set()
    for ip in ips:
        parts = ip.split('.')
        first = int(parts[0])
        # Skip private ranges (10.x, 127.x, 192.168.x, 172.16-31.x)
        if first == 10 or first == 127:
            continue
        if first == 192 and int(parts[1]) == 168:
            continue
        if first == 172 and 16 <= int(parts[1]) <= 31:
            continue
        if first == 0 or first == 255:
            continue
        filtered_ips.add(ip)
    iocs['ipv4'] = sorted(filtered_ips)[:200]

    # IPv6
    ipv6s = set(RE_IPV6.findall(clean_text))
    iocs['ipv6'] = sorted(ipv6s)[:50]

    # Hashes (SHA256 > SHA1 > MD5, exclude overlaps)
    sha256s = set(RE_SHA256.findall(clean_text))
    sha256s -= HASH_EXCLUDE_WORDS
    iocs['sha256'] = sorted(sha256s)[:200]

    sha1s = set(RE_SHA1.findall(clean_text))
    # Remove SHA1s that are substrings of SHA256s
    sha256_str = ' '.join(sha256s)
    sha1s = {h for h in sha1s if h not in sha256_str}
    iocs['sha1'] = sorted(sha1s)[:200]

    md5s = set(RE_MD5.findall(clean_text))
    # Remove MD5s that are substrings of SHA1 or SHA256
    all_longer = sha256_str + ' ' + ' '.join(sha1s)
    md5s = {h for h in md5s if h not in all_longer}
    # Filter out common hex words that aren't hashes
    md5s = {h for h in md5s if not h.isalpha()}  # pure letters = not a hash
    iocs['md5'] = sorted(md5s)[:200]

    # CVEs
    cves = set(RE_CVE.findall(clean_text))
    iocs['cve'] = sorted(cves)[:100]

    # Emails
    emails = set(RE_EMAIL.findall(clean_text))
    emails = {e for e in emails if not e.endswith(('.png', '.jpg', '.gif', '.svg'))}
    iocs['emails'] = sorted(emails)[:100]

    return iocs


def detect_threat_actors(text):
    """Detect known threat actors in text."""
    text_lower = text.lower()
    found = set()

    for keyword, actor_name in THREAT_ACTORS.items():
        if keyword.lower() in text_lower:
            found.add(actor_name)

    # Additional well-known actors not in the base config
    extra_actors = {
        'cozy bear': 'APT29 (Cozy Bear)',
        'apt29': 'APT29 (Cozy Bear)',
        'lazarus': 'Lazarus Group',
        'kimsuky': 'Kimsuky',
        'nobelium': 'Nobelium (APT29)',
        'conti': 'Conti',
        'lockbit': 'LockBit',
        'cl0p': 'Cl0p',
        'clop': 'Cl0p',
        'blackcat': 'BlackCat (ALPHV)',
        'alphv': 'BlackCat (ALPHV)',
        'muddywater': 'MuddyWater',
        'apt41': 'APT41 (Winnti)',
        'hafnium': 'Hafnium',
        'volt typhoon': 'Volt Typhoon',
        'darkside': 'DarkSide',
        'revil': 'REvil',
        'fin7': 'FIN7',
        'ember bear': 'Ember Bear (UAC-0056)',
        'uac-0056': 'Ember Bear (UAC-0056)',
        'ghostwriter': 'Ghostwriter (UNC1151)',
        'unc1151': 'Ghostwriter (UNC1151)',
        'cadet blizzard': 'Cadet Blizzard',
        'seashell blizzard': 'Seashell Blizzard (Sandworm)',
        'forest blizzard': 'Forest Blizzard (APT28)',
    }

    for keyword, actor_name in extra_actors.items():
        if keyword in text_lower:
            found.add(actor_name)

    return sorted(found)


def detect_attack_types(text):
    """Detect attack types mentioned in text."""
    text_lower = text.lower()
    found = set()

    for attack_type, keywords in ATTACK_TYPE_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                found.add(attack_type)
                break

    return sorted(found)


def detect_sectors(text):
    """Detect target sectors mentioned in text."""
    text_lower = text.lower()
    found = set()

    for sector, keywords in SECTOR_KEYWORDS.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                found.add(sector)
                break

    return sorted(found)


def detect_mitre_techniques(text):
    """Extract MITRE ATT&CK technique IDs from text."""
    found = set(RE_MITRE.findall(text))
    # Also check for known technique IDs from config
    for tid in MITRE_TECHNIQUE_PATTERNS:
        if tid in text:
            found.add(tid)
    return sorted(found)


def extract_keywords(text, top_n=30):
    """
    Extract top keywords from text (simple frequency-based).
    Focuses on cybersecurity-relevant terms.
    """
    # Cybersecurity relevant terms to boost
    cyber_terms = {
        'malware', 'ransomware', 'phishing', 'exploit', 'vulnerability',
        'backdoor', 'trojan', 'botnet', 'ddos', 'c2', 'command',
        'control', 'exfiltration', 'lateral', 'movement', 'persistence',
        'privilege', 'escalation', 'credential', 'encryption',
        'decryption', 'payload', 'dropper', 'loader', 'shellcode',
        'obfuscation', 'sandbox', 'evasion', 'detection', 'firewall',
        'intrusion', 'reconnaissance', 'spearphishing', 'watering',
        'supply', 'chain', 'zero-day', 'apt', 'threat', 'attack',
        'breach', 'compromise', 'indicator', 'infrastructure',
        'campaign', 'operation', 'target', 'victim', 'attacker',
        # Ukrainian cyber terms
        'кібератака', 'зловмисник', 'шкідливе', 'фішинг', 'вразливість',
        'шифрування', 'бекдор', 'експлойт', 'загроза', 'інцидент',
    }

    # Tokenize
    words = re.findall(r'\b[a-zA-Zа-яА-ЯіїєґІЇЄҐ]{3,}\b', text.lower())
    # Filter common stop words
    stop_words = {
        'the', 'and', 'for', 'was', 'are', 'with', 'that', 'this',
        'from', 'have', 'has', 'had', 'not', 'but', 'can', 'will',
        'been', 'were', 'they', 'their', 'which', 'when', 'what',
        'there', 'would', 'could', 'should', 'about', 'more', 'than',
        'other', 'into', 'also', 'may', 'its', 'use', 'used', 'using',
        # Ukrainian stop words
        'що', 'які', 'для', 'або', 'яка', 'при', 'цей', 'цього',
        'також', 'після', 'між', 'через', 'може', 'було', 'буде',
        'якщо', 'інші', 'вони', 'його', 'який', 'їхн', 'наш',
    }

    filtered = [w for w in words if w not in stop_words and len(w) > 2]
    counter = Counter(filtered)

    # Boost cybersecurity terms
    for term in cyber_terms:
        if term in counter:
            counter[term] *= 3

    return dict(counter.most_common(top_n))


def detect_language(text):
    """Simple language detection based on character frequency."""
    if not text:
        return 'unknown'

    # Count Ukrainian-specific characters
    uk_chars = len(re.findall(r'[іїєґІЇЄҐ]', text))
    # Count Cyrillic characters
    cyrillic = len(re.findall(r'[а-яА-ЯёЁ]', text))
    # Count Latin characters
    latin = len(re.findall(r'[a-zA-Z]', text))

    total = cyrillic + latin
    if total == 0:
        return 'unknown'

    if uk_chars > 20:
        return 'uk'
    elif cyrillic > latin:
        return 'ru'
    else:
        return 'en'


def generate_summary(text, iocs, actors, attacks, sectors, max_len=500):
    """Generate a brief summary of the document analysis."""
    parts = []

    # IOC summary
    ioc_total = sum(len(v) for v in iocs.values())
    if ioc_total > 0:
        ioc_parts = []
        for ioc_type, values in iocs.items():
            if values:
                type_labels = {
                    'ipv4': 'IP-адрес', 'ipv6': 'IPv6', 'domains': 'доменів',
                    'urls': 'URL', 'md5': 'MD5', 'sha1': 'SHA1',
                    'sha256': 'SHA256', 'cve': 'CVE', 'emails': 'email',
                }
                ioc_parts.append(f"{len(values)} {type_labels.get(ioc_type, ioc_type)}")
        parts.append(f"Знайдено {ioc_total} IOC індикаторів: {', '.join(ioc_parts)}.")

    if actors:
        parts.append(f"Виявлені загрозливі актори: {', '.join(actors)}.")

    if attacks:
        parts.append(f"Типи атак: {', '.join(attacks)}.")

    if sectors:
        parts.append(f"Цільові сектори: {', '.join(sectors)}.")

    if not parts:
        parts.append("Документ не містить явних індикаторів кіберзагроз.")

    summary = ' '.join(parts)
    return summary[:max_len]


def analyze_document(filepath, original_name, doc_type='pdf'):
    """
    Full document analysis pipeline:
    1. Extract text
    2. Identify IOCs
    3. Detect threat actors, attack types, sectors
    4. Extract MITRE techniques
    5. Generate summary
    6. Store in database
    Returns the UploadedDocument object.
    """
    logger.info(f"Analyzing document: {original_name} ({doc_type})")

    # 1. Extract text
    if doc_type == 'pdf':
        text, page_count = extract_text_from_pdf(filepath)
    elif doc_type in ('txt', 'csv'):
        text, page_count = extract_text_from_txt(filepath)
    else:
        text, page_count = '', 0

    if not text:
        logger.warning(f"No text extracted from {original_name}")

    # 2. Extract IOCs
    iocs = extract_iocs(text) if text else {}
    ioc_count = sum(len(v) for v in iocs.values())

    # 3. Detect threat intelligence entities
    actors = detect_threat_actors(text) if text else []
    attacks = detect_attack_types(text) if text else []
    sectors = detect_sectors(text) if text else []
    mitre = detect_mitre_techniques(text) if text else []

    # 4. Keywords
    keywords = extract_keywords(text) if text else {}

    # 5. Language detection
    language = detect_language(text)

    # 6. Summary
    summary = generate_summary(text, iocs, actors, attacks, sectors)

    # 7. File info
    file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0

    # 8. Generate title from filename or first line
    title = original_name
    if text:
        first_line = text.strip().split('\n')[0].strip()[:200]
        if first_line and len(first_line) > 10:
            title = first_line

    # 9. Store in database
    session = get_session()
    try:
        doc_record = UploadedDocument(
            filename=os.path.basename(filepath),
            original_name=original_name,
            file_size=file_size,
            page_count=page_count,
            doc_type=doc_type,
            title=title[:500] if title else original_name,
            description=summary,
            extracted_text=text[:100000] if text else None,  # Limit to 100K chars
            language=language,
            ioc_data=json.dumps(iocs, ensure_ascii=False) if iocs else None,
            ioc_count=ioc_count,
            threat_actors=', '.join(actors) if actors else None,
            attack_types=', '.join(attacks) if attacks else None,
            target_sectors=', '.join(sectors) if sectors else None,
            mitre_techniques=', '.join(mitre) if mitre else None,
            keywords=json.dumps(keywords, ensure_ascii=False) if keywords else None,
            summary=summary,
        )
        session.add(doc_record)
        session.commit()

        # 10. Also store extracted IOCs in the IOC feed table
        _store_document_iocs(session, doc_record.id, iocs, original_name)

        logger.info(
            f"Document analyzed: {original_name} — "
            f"{ioc_count} IOCs, {len(actors)} actors, "
            f"{len(attacks)} attack types, {page_count} pages"
        )

        # Expunge so it can be used after session close
        session.expunge(doc_record)
        return doc_record

    except Exception as e:
        session.rollback()
        logger.error(f"Failed to store document analysis: {e}")
        raise
    finally:
        session.close()


def _store_document_iocs(session, doc_id, iocs, doc_name):
    """Store extracted IOCs from document into the IOC indicators table."""
    type_mapping = {
        'ipv4': 'ipv4',
        'ipv6': 'ipv6',
        'domains': 'domain',
        'urls': 'url',
        'md5': 'hash_md5',
        'sha1': 'hash_sha1',
        'sha256': 'hash_sha256',
        'cve': 'cve',
        'emails': 'email',
    }

    added = 0
    source_name = f"PDF: {doc_name[:150]}"

    for ioc_key, values in iocs.items():
        ioc_type = type_mapping.get(ioc_key)
        if not ioc_type:
            continue

        for value in values[:50]:  # Limit 50 per type per document
            try:
                existing = session.query(IOCIndicator).filter_by(
                    value=value, source=source_name
                ).first()

                if not existing:
                    ioc = IOCIndicator(
                        value=value,
                        ioc_type=ioc_type,
                        source=source_name,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        threat_level='medium',
                        tags=f"document:{doc_id}",
                        confidence=60,
                        description=f"Extracted from document: {doc_name}",
                    )
                    session.add(ioc)
                    added += 1
            except Exception as e:
                logger.warning(f"Failed to store IOC {value}: {e}")
                continue

    if added > 0:
        try:
            session.commit()
        except Exception as e:
            session.rollback()
            logger.warning(f"Failed to commit document IOCs: {e}")

    logger.info(f"Stored {added} IOCs from document {doc_name}")
    return added


def save_uploaded_file(file_storage, upload_dir=None):
    """
    Save an uploaded file to disk.
    Returns (filepath, original_name, doc_type).
    """
    if upload_dir is None:
        upload_dir = UPLOAD_DIR

    os.makedirs(upload_dir, exist_ok=True)

    original_name = file_storage.filename
    ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else 'pdf'

    # Generate unique filename
    unique_name = f"{uuid.uuid4().hex}_{original_name}"
    filepath = os.path.join(upload_dir, unique_name)
    file_storage.save(filepath)

    doc_type = ext if ext in ('pdf', 'txt', 'csv', 'docx') else 'pdf'

    return filepath, original_name, doc_type
