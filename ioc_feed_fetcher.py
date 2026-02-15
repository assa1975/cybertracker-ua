# -*- coding: utf-8 -*-
"""
IOC Feed Fetcher Module.
Fetches IOC indicators from free threat intelligence feeds:
- Abuse.ch ThreatFox (JSON API)
- Abuse.ch URLhaus (JSON API)
- Abuse.ch Feodo Tracker (JSON blocklist)
"""

import json
import logging
import time
from datetime import datetime, timezone

import requests

from models import IOCIndicator, FetchLog
from database import get_session

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30
USER_AGENT = 'CyberTrackerUA/1.0'


def fetch_all_ioc_feeds():
    """Fetch IOCs from all configured threat intelligence feeds."""
    total_found = 0
    total_added = 0
    feeds_results = []

    feeds = [
        ('ThreatFox', _fetch_threatfox),
        ('URLhaus', _fetch_urlhaus),
        ('Feodo Tracker', _fetch_feodo),
    ]

    for feed_name, fetcher_fn in feeds:
        try:
            result = fetcher_fn()
            total_found += result.get('found', 0)
            total_added += result.get('added', 0)
            feeds_results.append({
                'name': feed_name,
                'found': result.get('found', 0),
                'added': result.get('added', 0),
                'status': 'ok',
            })
            # Log to FetchLog
            session = get_session()
            try:
                log = FetchLog(
                    feed_name=feed_name,
                    entries_found=result.get('found', 0),
                    entries_added=result.get('added', 0),
                )
                session.add(log)
                session.commit()
            finally:
                session.close()

            logger.info(f"IOC feed {feed_name}: {result.get('added', 0)} new / {result.get('found', 0)} found")
        except Exception as e:
            logger.error(f"IOC feed {feed_name} failed: {e}")
            feeds_results.append({
                'name': feed_name,
                'found': 0,
                'added': 0,
                'status': f'error: {e}',
            })

    return {
        'total_found': total_found,
        'total_added': total_added,
        'feeds': feeds_results,
    }


def _fetch_threatfox():
    """Fetch IOCs from Abuse.ch ThreatFox public export (JSON)."""
    url = 'https://threatfox.abuse.ch/export/json/recent/'

    resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                        headers={'User-Agent': USER_AGENT})
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict):
        return {'found': 0, 'added': 0}

    found = 0
    added = 0

    # Data format: dict keyed by ID, each value is a list with one entry dict
    for entry_id, entry_list in data.items():
        if not isinstance(entry_list, list) or not entry_list:
            continue
        entry = entry_list[0] if isinstance(entry_list[0], dict) else {}
        if not entry:
            continue

        found += 1
        ioc_value = entry.get('ioc_value', '').strip()
        if not ioc_value:
            continue

        raw_type = entry.get('ioc_type', '')
        ioc_type = _normalize_ioc_type(raw_type, ioc_value)

        # Strip port from ip:port format
        if raw_type == 'ip:port' and ':' in ioc_value:
            ioc_value = ioc_value.rsplit(':', 1)[0]

        confidence = entry.get('confidence_level', 0) or 0
        if isinstance(confidence, str):
            try:
                confidence = int(confidence)
            except ValueError:
                confidence = 0
        threat_level = _map_threat_level(confidence)

        malware = entry.get('malware_printable') or entry.get('malware') or ''
        tags_raw = entry.get('tags')
        if isinstance(tags_raw, str):
            tags_list = [t.strip() for t in tags_raw.split(',') if t.strip()]
        elif isinstance(tags_raw, list):
            tags_list = tags_raw
        else:
            tags_list = []
        if malware and malware not in tags_list:
            tags_list.insert(0, malware)
        tags = ', '.join(str(t) for t in tags_list if t)

        first_seen = _parse_datetime(entry.get('first_seen_utc'))
        last_seen = _parse_datetime(entry.get('last_seen_utc'))

        description = entry.get('threat_type', '')

        if _store_ioc(ioc_value, ioc_type, 'ThreatFox', first_seen, last_seen,
                       threat_level, tags, confidence, description):
            added += 1

        # Limit to 500 entries per fetch
        if found >= 500:
            break

    return {'found': found, 'added': added}


def _fetch_urlhaus():
    """Fetch recent malicious URLs from Abuse.ch URLhaus public export."""
    url = 'https://urlhaus.abuse.ch/downloads/json_recent/'

    resp = requests.get(url, timeout=60,
                        headers={'User-Agent': USER_AGENT})
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, dict):
        return {'found': 0, 'added': 0}

    found = 0
    added = 0

    # Data format: dict keyed by ID, each value is a list with one entry dict
    for entry_id, entry_list in data.items():
        if not isinstance(entry_list, list) or not entry_list:
            continue
        entry = entry_list[0] if isinstance(entry_list[0], dict) else {}
        if not entry:
            continue

        found += 1
        ioc_value = entry.get('url', '').strip()
        if not ioc_value:
            continue

        status = entry.get('url_status', '')
        threat_level = 'high' if status == 'online' else 'medium'
        confidence = 80 if status == 'online' else 50

        tags_raw = entry.get('tags')
        if isinstance(tags_raw, list):
            tags_list = tags_raw
        elif isinstance(tags_raw, str):
            tags_list = [t.strip() for t in tags_raw.split(',') if t.strip()]
        else:
            tags_list = []
        tags = ', '.join(str(t) for t in tags_list if t)

        threat = entry.get('threat', '')
        if threat and threat not in tags:
            tags = f"{threat}, {tags}" if tags else threat

        first_seen = _parse_datetime(entry.get('dateadded'))
        last_online = _parse_datetime(entry.get('last_online'))

        description = f"URL status: {status}" if status else ''

        if _store_ioc(ioc_value, 'url', 'URLhaus', first_seen, last_online or first_seen,
                       threat_level, tags, confidence, description):
            added += 1

        # Limit to 500 entries per fetch
        if found >= 500:
            break

    return {'found': found, 'added': added}


def _fetch_feodo():
    """Fetch C2 IP blocklist from Abuse.ch Feodo Tracker."""
    url = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json'

    resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                        headers={'User-Agent': USER_AGENT})
    resp.raise_for_status()
    data = resp.json()

    if not isinstance(data, list):
        return {'found': 0, 'added': 0}

    found = 0
    added = 0

    for entry in data:
        found += 1
        ip = entry.get('ip_address', '').strip()
        if not ip:
            continue

        status = entry.get('status', '')
        threat_level = 'critical' if status == 'online' else 'high'
        confidence = 90 if status == 'online' else 70

        port = entry.get('port', '')
        country = entry.get('country', '')
        as_name = entry.get('as_name', '')
        tags_parts = []
        if port:
            tags_parts.append(f"port:{port}")
        if country:
            tags_parts.append(country)
        if as_name:
            tags_parts.append(as_name)
        tags = ', '.join(tags_parts)

        first_seen = _parse_date(entry.get('first_seen'))
        last_seen = _parse_date(entry.get('last_online'))

        description = f"Feodo C2 ({status})" if status else 'Feodo C2'

        if _store_ioc(ip, 'ipv4', 'Feodo Tracker', first_seen, last_seen,
                       threat_level, tags, confidence, description):
            added += 1

    return {'found': found, 'added': added}


def _store_ioc(value, ioc_type, source, first_seen, last_seen,
               threat_level, tags, confidence, description):
    """Store or update IOC indicator in database. Returns True if new."""
    session = get_session()
    try:
        existing = session.query(IOCIndicator).filter_by(
            value=value, source=source
        ).first()

        if existing:
            # Update last_seen if newer (handle timezone-naive vs aware)
            if last_seen:
                existing_ls = existing.last_seen
                if existing_ls and existing_ls.tzinfo is None:
                    existing_ls = existing_ls.replace(tzinfo=timezone.utc)
                if not existing_ls or last_seen > existing_ls:
                    existing.last_seen = last_seen
            # Update threat_level if higher priority
            levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
            if levels.get(threat_level, 0) > levels.get(existing.threat_level, 0):
                existing.threat_level = threat_level
            if confidence > (existing.confidence or 0):
                existing.confidence = confidence
            session.commit()
            return False
        else:
            ioc = IOCIndicator(
                value=value,
                ioc_type=ioc_type,
                source=source,
                first_seen=first_seen,
                last_seen=last_seen or first_seen,
                threat_level=threat_level,
                tags=tags[:1000] if tags else None,
                confidence=confidence,
                description=description[:500] if description else None,
            )
            session.add(ioc)
            session.commit()
            return True
    except Exception as e:
        session.rollback()
        logger.warning(f"Failed to store IOC {value}: {e}")
        return False
    finally:
        session.close()


def _normalize_ioc_type(raw_type, value):
    """Map feed-specific type to standardized type."""
    type_map = {
        'ip:port': 'ipv4',
        'domain': 'domain',
        'url': 'url',
        'md5_hash': 'hash_md5',
        'sha256_hash': 'hash_sha256',
        'sha1_hash': 'hash_sha1',
    }
    return type_map.get(raw_type, 'domain')


def _map_threat_level(confidence, status=None):
    """Map confidence score to threat level."""
    if status == 'online':
        return 'critical' if confidence >= 75 else 'high'
    if confidence >= 75:
        return 'critical'
    if confidence >= 50:
        return 'high'
    if confidence >= 25:
        return 'medium'
    return 'low'


def _parse_datetime(dt_str):
    """Parse datetime string from feed APIs."""
    if not dt_str:
        return None
    for fmt in ('%Y-%m-%d %H:%M:%S UTC', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(dt_str.strip(), fmt).replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue
    return None


def _parse_date(date_str):
    """Parse date-only string."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str.strip(), '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except (ValueError, AttributeError):
        return None
