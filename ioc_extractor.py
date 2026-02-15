"""
IOC (Indicator of Compromise) Extractor Module.
Extracts IP addresses, domains, URLs, hashes, CVE IDs, MITRE ATT&CK IDs,
and email addresses from text using regex patterns.
"""

import re
import json
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# --- Regex Patterns ---

# IPv4 (including defanged with [.] notation)
RE_IPV4 = re.compile(
    r'\b(\d{1,3}(?:\[\.\]|\.)(?:\d{1,3})(?:\[\.\]|\.)(?:\d{1,3})(?:\[\.\]|\.)(?:\d{1,3}))\b'
)

# IPv6 (simplified — full and abbreviated forms)
RE_IPV6 = re.compile(
    r'\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})\b'
)

# Domain (including defanged hxxp and [.] forms)
RE_DOMAIN = re.compile(
    r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\[\.\]|\.))+(?:[a-zA-Z]{2,}))\b'
)

# URL (including hxxp/hxxps defanged)
RE_URL = re.compile(
    r'((?:hxxps?|https?|ftp)://[^\s<>\"\'\)\]]+)',
    re.IGNORECASE
)

# Hashes
RE_MD5 = re.compile(r'\b([a-fA-F0-9]{32})\b')
RE_SHA1 = re.compile(r'\b([a-fA-F0-9]{40})\b')
RE_SHA256 = re.compile(r'\b([a-fA-F0-9]{64})\b')

# CVE IDs
RE_CVE = re.compile(r'\b(CVE-\d{4}-\d{4,})\b', re.IGNORECASE)

# MITRE ATT&CK Technique IDs (T1234, T1234.001)
RE_MITRE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')

# Email addresses
RE_EMAIL = re.compile(
    r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b'
)

# --- False Positive Filters ---

# Private/reserved IP ranges
PRIVATE_IP_PREFIXES = [
    '10.', '127.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
    '192.168.', '0.0.', '255.255.',
]

# Common/popular domains to exclude (not IOCs)
COMMON_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'linkedin.com', 'instagram.com', 'wikipedia.org', 'reddit.com',
    'cloudflare.com', 'googleapis.com', 'gstatic.com',
    'w3.org', 'schema.org', 'jquery.com', 'jsdelivr.net',
    'bootstrapcdn.com', 'fontawesome.com', 'example.com',
    'mitre.org', 'attack.mitre.org', 'cve.org', 'nvd.nist.gov',
    'cert.gov.ua', 'bleepingcomputer.com', 'thehackernews.com',
    'therecord.media', 'securityweek.com', 'virustotal.com',
    'recordedfuture.com', 'mandiant.com', 'cisco.com', 'cisa.gov',
    't.co', 'bit.ly', 'tinyurl.com', 'feedburner.com',
}

# Trivial hashes (all zeros, all f's, etc.)
TRIVIAL_HASHES = {
    '0' * 32, 'f' * 32, 'd41d8cd98f00b204e9800998ecf8427e',  # md5 of empty
    '0' * 40, 'f' * 40, 'da39a3ee5e6b4b0d3255bfef95601890afd80709',  # sha1 of empty
    '0' * 64, 'f' * 64,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # sha256 of empty
}


def refang(text):
    """Convert defanged IOCs back to normal form."""
    text = text.replace('[.]', '.')
    text = text.replace('hxxp://', 'http://')
    text = text.replace('hxxps://', 'https://')
    text = text.replace('[:]', ':')
    text = text.replace('[at]', '@')
    return text


def _is_private_ip(ip):
    """Check if IP is private/reserved."""
    clean_ip = refang(ip)
    return any(clean_ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)


def _is_valid_ip(ip):
    """Validate that IP octets are in range 0-255."""
    clean_ip = refang(ip)
    try:
        parts = clean_ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, IndexError):
        return False


def _is_common_domain(domain):
    """Check if domain is a common/popular site (not an IOC)."""
    clean = refang(domain).lower().rstrip('.')
    # Check exact match and parent domain
    parts = clean.split('.')
    for i in range(len(parts) - 1):
        check = '.'.join(parts[i:])
        if check in COMMON_DOMAINS:
            return True
    return False


def _is_trivial_hash(h):
    """Check if hash is trivial (empty file hash, all zeros, etc.)."""
    return h.lower() in TRIVIAL_HASHES


def _deduplicate_hashes(md5_list, sha1_list, sha256_list):
    """
    Remove shorter hashes that are substrings of longer ones.
    SHA256 > SHA1 > MD5 priority.
    """
    sha256_set = set(sha256_list)
    sha1_set = set(sha1_list)
    md5_set = set(md5_list)

    # Remove SHA1 values that are prefixes of SHA256
    sha1_clean = set()
    for s1 in sha1_set:
        if not any(s256.startswith(s1) or s256.endswith(s1) for s256 in sha256_set):
            sha1_clean.add(s1)

    # Remove MD5 values that are prefixes of SHA1 or SHA256
    md5_clean = set()
    for m in md5_set:
        if not any(s.startswith(m) or s.endswith(m) for s in sha1_set | sha256_set):
            md5_clean.add(m)

    return list(md5_clean), list(sha1_clean), list(sha256_set)


def extract_iocs(text):
    """
    Extract IOCs from text.

    Returns dict with keys:
    - ipv4: List[str]
    - ipv6: List[str]
    - domains: List[str]
    - urls: List[str]
    - md5: List[str]
    - sha1: List[str]
    - sha256: List[str]
    - cve: List[str]
    - mitre: List[str]
    - emails: List[str]
    """
    if not text or not text.strip():
        return {
            'ipv4': [], 'ipv6': [], 'domains': [], 'urls': [],
            'md5': [], 'sha1': [], 'sha256': [],
            'cve': [], 'mitre': [], 'emails': [],
        }

    # --- Extract raw matches ---

    # IPv4
    ipv4_raw = RE_IPV4.findall(text)
    ipv4 = []
    seen_ip = set()
    for ip in ipv4_raw:
        clean = refang(ip)
        if clean not in seen_ip and _is_valid_ip(ip) and not _is_private_ip(ip):
            seen_ip.add(clean)
            ipv4.append(clean)

    # IPv6
    ipv6_raw = RE_IPV6.findall(text)
    ipv6 = list(set(ipv6_raw))

    # URLs
    urls_raw = RE_URL.findall(text)
    urls = []
    seen_url = set()
    for u in urls_raw:
        clean = refang(u).rstrip('.,;:)')
        if clean not in seen_url:
            seen_url.add(clean)
            urls.append(clean)

    # Domains (extract from URLs too, but filter common ones)
    domains_raw = RE_DOMAIN.findall(text)
    domains = []
    seen_dom = set()
    for d in domains_raw:
        clean = refang(d).lower().rstrip('.')
        # Must have at least one dot and valid TLD
        if '.' not in clean:
            continue
        tld = clean.split('.')[-1]
        if len(tld) < 2 or tld.isdigit():
            continue
        if clean not in seen_dom and not _is_common_domain(clean):
            seen_dom.add(clean)
            domains.append(clean)

    # Hashes — extract in order: SHA256 first (longest), then SHA1, then MD5
    sha256_raw = list(set(RE_SHA256.findall(text)))
    sha256 = [h for h in sha256_raw if not _is_trivial_hash(h)]

    sha1_raw = list(set(RE_SHA1.findall(text)))
    sha1 = [h for h in sha1_raw if not _is_trivial_hash(h)]

    md5_raw = list(set(RE_MD5.findall(text)))
    md5 = [h for h in md5_raw if not _is_trivial_hash(h)]

    # Deduplicate substring hashes
    md5, sha1, sha256 = _deduplicate_hashes(md5, sha1, sha256)

    # CVE IDs
    cve_raw = RE_CVE.findall(text)
    cve = list(set(c.upper() for c in cve_raw))

    # MITRE ATT&CK
    mitre_raw = RE_MITRE.findall(text)
    mitre = list(set(mitre_raw))

    # Emails
    emails_raw = RE_EMAIL.findall(text)
    emails = list(set(e.lower() for e in emails_raw
                       if not _is_common_domain(e.split('@')[1])))

    result = {
        'ipv4': sorted(ipv4),
        'ipv6': sorted(ipv6),
        'domains': sorted(domains),
        'urls': sorted(urls),
        'md5': sorted(md5),
        'sha1': sorted(sha1),
        'sha256': sorted(sha256),
        'cve': sorted(cve),
        'mitre': sorted(mitre),
        'emails': sorted(emails),
    }

    # Log summary
    total = sum(len(v) for v in result.values())
    if total > 0:
        summary = ', '.join(f"{k}={len(v)}" for k, v in result.items() if v)
        logger.debug(f"Extracted {total} IOCs: {summary}")

    return result


def iocs_to_json(iocs_dict):
    """Convert IOC dict to JSON string for storage."""
    # Only include non-empty categories
    filtered = {k: v for k, v in iocs_dict.items() if v}
    if not filtered:
        return None
    return json.dumps(filtered, ensure_ascii=False)


def merge_ioc_json(existing_json, new_iocs_dict):
    """
    Merge new IOCs into existing JSON string.
    Returns updated JSON string or None if empty.
    """
    existing = {}
    if existing_json:
        try:
            existing = json.loads(existing_json)
        except (json.JSONDecodeError, TypeError):
            pass

    for key, values in new_iocs_dict.items():
        if values:
            existing_set = set(existing.get(key, []))
            existing_set.update(values)
            existing[key] = sorted(existing_set)

    filtered = {k: v for k, v in existing.items() if v}
    if not filtered:
        return None
    return json.dumps(filtered, ensure_ascii=False)


def format_iocs_display(ioc_json):
    """
    Format IOC JSON for display in templates.
    Returns list of (category_name, items_list) tuples.
    """
    if not ioc_json:
        return []

    try:
        data = json.loads(ioc_json)
    except (json.JSONDecodeError, TypeError):
        return []

    CATEGORY_NAMES = {
        'ipv4': 'IPv4 адреси',
        'ipv6': 'IPv6 адреси',
        'domains': 'Домени',
        'urls': 'URL-адреси',
        'md5': 'MD5 хеші',
        'sha1': 'SHA1 хеші',
        'sha256': 'SHA256 хеші',
        'cve': 'CVE вразливості',
        'mitre': 'MITRE ATT&CK',
        'emails': 'Email адреси',
    }

    result = []
    for key in ['ipv4', 'ipv6', 'domains', 'urls', 'md5', 'sha1', 'sha256', 'cve', 'mitre', 'emails']:
        items = data.get(key, [])
        if items:
            result.append((CATEGORY_NAMES.get(key, key), items))

    return result
