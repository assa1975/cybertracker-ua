"""
LinkedIn Post Fetcher Module.
Monitors cybersecurity content on LinkedIn related to Ukraine.
Uses Google Custom Search JSON API to find publicly indexed LinkedIn posts.
"""

import re
import logging
import time
from datetime import datetime, timezone

import requests
from sqlalchemy.exc import IntegrityError

from models import Incident, FetchLog
from database import get_session
from config import (
    GOOGLE_CSE_API_KEY, GOOGLE_CSE_ID, LINKEDIN_ENABLED,
    LINKEDIN_SEARCH_QUERIES, LINKEDIN_RESULTS_PER_QUERY,
    LINKEDIN_DATE_RESTRICT,
    UKRAINE_KEYWORDS, ATTACK_TYPE_KEYWORDS, SECTOR_KEYWORDS, THREAT_ACTORS,
)
from ioc_extractor import extract_iocs, iocs_to_json

logger = logging.getLogger(__name__)

GOOGLE_CSE_ENDPOINT = 'https://www.googleapis.com/customsearch/v1'


def _search_linkedin_posts(query, num_results=10, date_restrict='d3'):
    """
    Search Google CSE for LinkedIn posts matching query.
    Returns list of result dicts with keys: title, snippet, link, og_description.
    """
    if not GOOGLE_CSE_API_KEY or not GOOGLE_CSE_ID:
        raise RuntimeError("Google CSE not configured")

    params = {
        'key': GOOGLE_CSE_API_KEY,
        'cx': GOOGLE_CSE_ID,
        'q': query,
        'num': min(num_results, 10),  # API max is 10 per request
        'dateRestrict': date_restrict,
    }

    try:
        resp = requests.get(GOOGLE_CSE_ENDPOINT, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logger.error(f"Google CSE request failed: {e}")
        return []

    # Check for API errors
    if 'error' in data:
        logger.error(f"Google CSE API error: {data['error'].get('message', '')}")
        return []

    results = []
    for item in data.get('items', []):
        # Extract Open Graph description if available (longer than snippet)
        og_desc = ''
        metatags = item.get('pagemap', {}).get('metatags', [])
        if metatags:
            og_desc = metatags[0].get('og:description', '')

        results.append({
            'title': item.get('title', ''),
            'snippet': item.get('snippet', ''),
            'link': item.get('link', ''),
            'og_description': og_desc,
        })

    return results


def _clean_title(title):
    """Remove LinkedIn suffixes from title."""
    title = re.sub(r'\s*[|\-\u2013\u2014]\s*LinkedIn\s*$', '', title, flags=re.IGNORECASE)
    return title.strip()


def is_ukraine_relevant(text):
    """Check if text contains Ukraine-related keywords."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in UKRAINE_KEYWORDS)


def classify_attack_type(text):
    """Classify attack type by keyword matching."""
    text_lower = text.lower()
    for label, keywords in ATTACK_TYPE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return label
    return None


def classify_target_sector(text):
    """Classify target sector by keyword matching."""
    text_lower = text.lower()
    for label, keywords in SECTOR_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return label
    return None


def identify_threat_actor(text):
    """Identify threat actor by keyword matching."""
    text_lower = text.lower()
    uac_match = re.search(r'uac-\d{4}', text_lower)
    if uac_match:
        uac_id = uac_match.group(0)
        if uac_id in THREAT_ACTORS:
            return THREAT_ACTORS[uac_id]
        return uac_id.upper()

    for key, name in THREAT_ACTORS.items():
        if key in text_lower:
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


def process_search_result(result_data):
    """
    Process a Google CSE result and return incident dict if relevant.
    Returns None if not relevant to Ukraine.
    """
    title = _clean_title(result_data['title'])
    link = result_data['link']

    if not title or not link:
        return None

    # Use the longest available description
    description = result_data.get('og_description', '') or result_data.get('snippet', '')

    # Combined text for analysis
    combined_text = f"{title} {description}"

    # Check Ukraine relevance
    if not is_ukraine_relevant(combined_text):
        return None

    # Classify
    attack_type = classify_attack_type(combined_text)
    target_sector = classify_target_sector(combined_text)
    threat_actor = identify_threat_actor(combined_text)
    severity = assign_severity(attack_type, threat_actor)

    # Extract IOCs
    iocs = extract_iocs(combined_text)
    ioc_json = iocs_to_json(iocs)

    mitre_id = None
    if iocs.get('mitre'):
        mitre_id = iocs['mitre'][0]

    # Truncate title if needed
    if len(title) > 200:
        title = title[:197] + '...'

    return {
        'title': title,
        'description': description[:5000] if description else None,
        'date': datetime.now(timezone.utc),
        'source': 'LinkedIn',
        'source_url': link,
        'attack_type': attack_type,
        'target_sector': target_sector,
        'threat_actor': threat_actor,
        'severity': severity,
        'ioc_indicators': ioc_json,
        'mitre_technique_id': mitre_id,
    }


def store_linkedin_incident(incident_data):
    """Store LinkedIn-sourced incident in DB. Returns True if inserted."""
    session = get_session()
    try:
        incident = Incident(**incident_data)
        session.add(incident)
        session.commit()
        return True
    except IntegrityError:
        session.rollback()
        return False  # Duplicate URL
    except Exception as e:
        session.rollback()
        logger.error(f"Error storing LinkedIn incident: {e}")
        return False
    finally:
        session.close()


def fetch_all_linkedin():
    """
    Search Google CSE for LinkedIn posts matching all configured queries.
    Returns summary dict with stats.
    """
    if not LINKEDIN_ENABLED:
        return {
            'total_found': 0,
            'total_added': 0,
            'status': 'disabled',
            'message': 'LinkedIn monitoring not configured (set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID in .env)',
        }

    total_found = 0
    total_added = 0

    for query in LINKEDIN_SEARCH_QUERIES:
        try:
            results = _search_linkedin_posts(
                query=query,
                num_results=LINKEDIN_RESULTS_PER_QUERY,
                date_restrict=LINKEDIN_DATE_RESTRICT,
            )
            logger.info(f"LinkedIn search '{query[:50]}...': {len(results)} results")

            for result_data in results:
                incident_data = process_search_result(result_data)
                if incident_data is None:
                    continue

                total_found += 1
                if store_linkedin_incident(incident_data):
                    total_added += 1

            # Rate limit: Google CSE free tier = 100/day
            time.sleep(1)

        except Exception as e:
            logger.error(f"Error in LinkedIn search '{query[:50]}': {e}")

    # Log the fetch
    session = get_session()
    try:
        log = FetchLog(
            feed_name='LinkedIn',
            entries_found=total_found,
            entries_added=total_added,
            status='success',
        )
        session.add(log)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()

    logger.info(f"LinkedIn fetch: {total_added} added of {total_found} relevant")
    return {
        'total_found': total_found,
        'total_added': total_added,
        'status': 'success',
    }
