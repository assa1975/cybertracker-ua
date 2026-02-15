import re
import logging
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import feedparser
from sqlalchemy.exc import IntegrityError

from models import Incident, FetchLog
from database import get_session
from config import (
    RSS_FEEDS, UKRAINE_KEYWORDS, ATTACK_TYPE_KEYWORDS,
    SECTOR_KEYWORDS, THREAT_ACTORS,
)
from ioc_extractor import extract_iocs, iocs_to_json

logger = logging.getLogger(__name__)

# Tracking params to strip for URL normalization
TRACKING_PARAMS = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term', 'ref', 'source'}


def fetch_all_feeds():
    """Fetch all configured RSS feeds. Returns summary dict."""
    total_found = 0
    total_added = 0
    feed_results = []

    for feed_config in RSS_FEEDS:
        try:
            found, added = fetch_single_feed(feed_config)
            total_found += found
            total_added += added
            feed_results.append({
                'name': feed_config['name'],
                'found': found,
                'added': added,
                'status': 'success',
            })
        except Exception as e:
            logger.error(f"Error fetching {feed_config['name']}: {e}")
            feed_results.append({
                'name': feed_config['name'],
                'found': 0,
                'added': 0,
                'status': 'error',
                'error': str(e),
            })
            # Log the error to DB
            session = get_session()
            try:
                log = FetchLog(
                    feed_name=feed_config['name'],
                    entries_found=0,
                    entries_added=0,
                    status='error',
                    error_message=str(e),
                )
                session.add(log)
                session.commit()
            except Exception:
                session.rollback()
            finally:
                session.close()

    return {
        'total_found': total_found,
        'total_added': total_added,
        'feeds': feed_results,
    }


def fetch_single_feed(feed_config):
    """Fetch and process a single RSS feed. Returns (entries_found, entries_added)."""
    logger.info(f"Fetching feed: {feed_config['name']} from {feed_config['url']}")

    feed = feedparser.parse(
        feed_config['url'],
        request_headers={'User-Agent': 'CyberTrackerUA/1.0'}
    )

    if feed.bozo and not feed.entries:
        raise Exception(f"Feed parse error: {feed.bozo_exception}")

    entries_found = 0
    entries_added = 0

    for entry in feed.entries:
        incident_data = parse_entry(entry, feed_config)
        if incident_data is None:
            continue

        entries_found += 1
        if store_incident(incident_data):
            entries_added += 1

    # Log the fetch
    session = get_session()
    try:
        log = FetchLog(
            feed_name=feed_config['name'],
            entries_found=entries_found,
            entries_added=entries_added,
            status='success',
        )
        session.add(log)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()

    logger.info(f"Feed {feed_config['name']}: {entries_added} added of {entries_found} relevant")
    return entries_found, entries_added


def parse_entry(entry, feed_config):
    """Parse a feedparser entry into an incident dict. Returns None if not relevant."""
    title = entry.get('title', '').strip()
    if not title:
        return None

    description = strip_html(entry.get('summary', '') or entry.get('description', '') or '')
    source_url = entry.get('link', '').strip()
    if not source_url:
        return None

    # Extract tags
    tags = []
    if 'tags' in entry:
        tags = [t.get('term', '') for t in entry.tags if t.get('term')]

    # Check Ukraine relevance
    if not feed_config.get('always_relevant', False):
        combined = f"{title} {description} {' '.join(tags)}"
        if not is_ukraine_relevant(combined):
            return None

    # Parse date
    date = None
    if entry.get('published_parsed'):
        try:
            date = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        except Exception:
            pass
    if date is None and entry.get('updated_parsed'):
        try:
            date = datetime(*entry.updated_parsed[:6], tzinfo=timezone.utc)
        except Exception:
            pass
    if date is None:
        date = datetime.now(timezone.utc)

    # Classify
    combined_text = f"{title} {description} {' '.join(tags)}".lower()
    attack_type = classify_attack_type(combined_text)
    target_sector = classify_target_sector(combined_text)
    threat_actor = identify_threat_actor(combined_text)
    severity = assign_severity(attack_type, threat_actor)

    # Extract IOCs from description
    iocs = extract_iocs(f"{title} {description}")
    ioc_json = iocs_to_json(iocs)

    # Extract MITRE technique ID from IOCs if not found by keyword
    mitre_id = None
    if iocs.get('mitre'):
        mitre_id = iocs['mitre'][0]  # Take first MITRE technique

    return {
        'title': title[:500],
        'description': description[:5000] if description else None,
        'date': date,
        'source': feed_config['name'],
        'source_url': normalize_url(source_url),
        'attack_type': attack_type,
        'target_sector': target_sector,
        'threat_actor': threat_actor,
        'severity': severity,
        'ioc_indicators': ioc_json,
        'mitre_technique_id': mitre_id,
    }


def is_ukraine_relevant(text):
    """Check if text contains Ukraine-related keywords."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in UKRAINE_KEYWORDS)


def classify_attack_type(text):
    """Classify attack type by keyword matching."""
    for label, keywords in ATTACK_TYPE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return label
    return None


def classify_target_sector(text):
    """Classify target sector by keyword matching."""
    for label, keywords in SECTOR_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return label
    return None


def identify_threat_actor(text):
    """Identify threat actor by keyword matching."""
    # Check UAC-XXXX pattern first
    uac_match = re.search(r'uac-\d{4}', text)
    if uac_match:
        uac_id = uac_match.group(0)
        if uac_id in THREAT_ACTORS:
            return THREAT_ACTORS[uac_id]
        return uac_id.upper()

    for key, name in THREAT_ACTORS.items():
        if key in text:
            return name
    return None


def assign_severity(attack_type, threat_actor):
    """Heuristic severity assignment."""
    if attack_type == 'Wiper' or threat_actor:
        return 'Критичний'
    if attack_type in ('Програма-вимагач', 'Експлойт', 'Supply Chain'):
        return 'Високий'
    if attack_type in ('Фішинг', 'Шкідливе ПЗ', 'Шпигунство'):
        return 'Середній'
    if attack_type in ('DDoS', 'Дефейс'):
        return 'Середній'
    return 'Низький'


def strip_html(html_text):
    """Remove HTML tags from text."""
    clean = re.sub(r'<[^>]+>', '', html_text)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean


def normalize_url(url):
    """Normalize URL by removing tracking params and trailing slashes."""
    try:
        parsed = urlparse(url)
        # Remove tracking params
        params = parse_qs(parsed.query, keep_blank_values=False)
        filtered = {k: v for k, v in params.items() if k.lower() not in TRACKING_PARAMS}
        new_query = urlencode(filtered, doseq=True) if filtered else ''
        # Rebuild URL
        normalized = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip('/'),
            parsed.params,
            new_query,
            '',  # strip fragment
        ))
        return normalized
    except Exception:
        return url


def is_title_duplicate(session, incident_data):
    """Check if a similar title exists from the same source within 2 days."""
    if not incident_data.get('date'):
        return False

    from datetime import timedelta
    date = incident_data['date']
    source = incident_data['source']
    title = incident_data['title']

    existing = (
        session.query(Incident)
        .filter(
            Incident.source == source,
            Incident.date.between(date - timedelta(days=2), date + timedelta(days=2))
        )
        .all()
    )

    for inc in existing:
        ratio = SequenceMatcher(None, title.lower(), inc.title.lower()).ratio()
        if ratio > 0.85:
            return True
    return False


def store_incident(incident_data):
    """Store incident in DB. Returns True if inserted, False if duplicate."""
    session = get_session()
    try:
        if is_title_duplicate(session, incident_data):
            return False

        incident = Incident(**incident_data)
        session.add(incident)
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        return False
    except Exception as e:
        session.rollback()
        logger.error(f"Error storing incident: {e}")
        return False
    finally:
        session.close()
