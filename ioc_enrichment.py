"""
IOC Enrichment Module.
Enriches IOC indicators using VirusTotal and AbuseIPDB APIs.
"""

import json
import logging
import time

import requests

from models import Incident
from database import get_session
from config import (
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_ENABLED,
    ABUSEIPDB_API_KEY, ABUSEIPDB_ENABLED,
)

logger = logging.getLogger(__name__)

# Rate limiting
VT_DELAY = 0.5     # VirusTotal: ~4 requests/min for free tier
ABUSE_DELAY = 0.5   # AbuseIPDB: reasonable rate

# Max IOCs to enrich per type per incident
MAX_IOCS_PER_TYPE = 5


def enrich_ip_virustotal(ip):
    """
    Query VirusTotal API v3 for IP address info.
    Returns dict with reputation data or None.
    """
    if not VIRUSTOTAL_ENABLED:
        return None

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {
                'source': 'VirusTotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'country': data.get('country', ''),
                'as_owner': data.get('as_owner', ''),
                'reputation': data.get('reputation', 0),
            }
        elif resp.status_code == 404:
            return {'source': 'VirusTotal', 'status': 'not_found'}
        else:
            logger.warning(f"VT IP lookup failed ({resp.status_code}): {ip}")
            return None
    except Exception as e:
        logger.error(f"VT IP error for {ip}: {e}")
        return None


def enrich_hash_virustotal(file_hash):
    """
    Query VirusTotal API v3 for file hash info.
    Returns dict with detection data or None.
    """
    if not VIRUSTOTAL_ENABLED:
        return None

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {
                'source': 'VirusTotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'type_description': data.get('type_description', ''),
                'popular_threat_label': data.get('popular_threat_classification', {}).get('suggested_threat_label', ''),
                'reputation': data.get('reputation', 0),
            }
        elif resp.status_code == 404:
            return {'source': 'VirusTotal', 'status': 'not_found'}
        else:
            logger.warning(f"VT hash lookup failed ({resp.status_code}): {file_hash}")
            return None
    except Exception as e:
        logger.error(f"VT hash error for {file_hash}: {e}")
        return None


def enrich_domain_virustotal(domain):
    """
    Query VirusTotal API v3 for domain info.
    Returns dict with reputation data or None.
    """
    if not VIRUSTOTAL_ENABLED:
        return None

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {
                'source': 'VirusTotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': data.get('reputation', 0),
                'registrar': data.get('registrar', ''),
            }
        elif resp.status_code == 404:
            return {'source': 'VirusTotal', 'status': 'not_found'}
        else:
            logger.warning(f"VT domain lookup failed ({resp.status_code}): {domain}")
            return None
    except Exception as e:
        logger.error(f"VT domain error for {domain}: {e}")
        return None


def enrich_ip_abuseipdb(ip):
    """
    Query AbuseIPDB for IP address info.
    Returns dict with abuse data or None.
    """
    if not ABUSEIPDB_ENABLED:
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {
                'source': 'AbuseIPDB',
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'country': data.get('countryCode', ''),
                'isp': data.get('isp', ''),
                'domain': data.get('domain', ''),
                'is_tor': data.get('isTor', False),
                'total_reports': data.get('totalReports', 0),
                'usage_type': data.get('usageType', ''),
            }
        else:
            logger.warning(f"AbuseIPDB lookup failed ({resp.status_code}): {ip}")
            return None
    except Exception as e:
        logger.error(f"AbuseIPDB error for {ip}: {e}")
        return None


def enrich_incident_iocs(incident_id):
    """
    Enrich IOC indicators for a single incident.
    Updates the ioc_indicators JSON field with enrichment data.
    Returns dict with stats.
    """
    session = get_session()
    try:
        incident = session.query(Incident).get(incident_id)
        if not incident or not incident.ioc_indicators:
            return {'enriched': 0, 'total': 0}

        try:
            iocs = json.loads(incident.ioc_indicators)
        except (json.JSONDecodeError, TypeError):
            return {'enriched': 0, 'total': 0}

        enrichments = {}
        enriched_count = 0

        # Enrich IPs
        ips = iocs.get('ipv4', [])[:MAX_IOCS_PER_TYPE]
        for ip in ips:
            ip_enrichment = {}

            # VirusTotal
            if VIRUSTOTAL_ENABLED:
                vt_result = enrich_ip_virustotal(ip)
                if vt_result:
                    ip_enrichment['virustotal'] = vt_result
                    enriched_count += 1
                time.sleep(VT_DELAY)

            # AbuseIPDB
            if ABUSEIPDB_ENABLED:
                abuse_result = enrich_ip_abuseipdb(ip)
                if abuse_result:
                    ip_enrichment['abuseipdb'] = abuse_result
                    enriched_count += 1
                time.sleep(ABUSE_DELAY)

            if ip_enrichment:
                enrichments[ip] = ip_enrichment

        # Enrich domains
        domains = iocs.get('domains', [])[:MAX_IOCS_PER_TYPE]
        for domain in domains:
            if VIRUSTOTAL_ENABLED:
                vt_result = enrich_domain_virustotal(domain)
                if vt_result:
                    enrichments[domain] = {'virustotal': vt_result}
                    enriched_count += 1
                time.sleep(VT_DELAY)

        # Enrich hashes (SHA256 preferred)
        hashes = iocs.get('sha256', [])[:MAX_IOCS_PER_TYPE]
        if not hashes:
            hashes = iocs.get('sha1', [])[:MAX_IOCS_PER_TYPE]
        if not hashes:
            hashes = iocs.get('md5', [])[:MAX_IOCS_PER_TYPE]

        for file_hash in hashes:
            if VIRUSTOTAL_ENABLED:
                vt_result = enrich_hash_virustotal(file_hash)
                if vt_result:
                    enrichments[file_hash] = {'virustotal': vt_result}
                    enriched_count += 1
                time.sleep(VT_DELAY)

        # Save enrichments into IOC data
        if enrichments:
            iocs['enrichments'] = enrichments
            incident.ioc_indicators = json.dumps(iocs, ensure_ascii=False)
            session.commit()
            logger.info(f"Enriched incident #{incident_id}: {enriched_count} lookups")

        return {'enriched': enriched_count, 'total': len(ips) + len(domains) + len(hashes)}

    except Exception as e:
        session.rollback()
        logger.error(f"Error enriching incident #{incident_id}: {e}")
        return {'enriched': 0, 'total': 0, 'error': str(e)}
    finally:
        session.close()


def enrich_all_unenriched():
    """
    Find incidents with IOC indicators but no enrichment data.
    Enrich them with VirusTotal and AbuseIPDB.
    """
    if not VIRUSTOTAL_ENABLED and not ABUSEIPDB_ENABLED:
        return {
            'total': 0,
            'enriched': 0,
            'status': 'disabled',
            'message': 'No enrichment APIs configured',
        }

    session = get_session()
    try:
        # Find incidents with IOCs but no enrichment
        candidates = (
            session.query(Incident.id, Incident.ioc_indicators)
            .filter(Incident.ioc_indicators.isnot(None))
            .order_by(Incident.date.desc())
            .limit(50)
            .all()
        )
    finally:
        session.close()

    # Filter to only those without enrichment data
    unenriched_ids = []
    for inc_id, ioc_json in candidates:
        try:
            data = json.loads(ioc_json)
            if 'enrichments' not in data:
                unenriched_ids.append(inc_id)
        except (json.JSONDecodeError, TypeError):
            continue

    total = len(unenriched_ids)
    enriched = 0

    logger.info(f"Found {total} incidents to enrich")

    for inc_id in unenriched_ids:
        try:
            result = enrich_incident_iocs(inc_id)
            if result.get('enriched', 0) > 0:
                enriched += 1
        except Exception as e:
            logger.error(f"Failed to enrich incident #{inc_id}: {e}")

    logger.info(f"Enriched {enriched} of {total} incidents")
    return {'total': total, 'enriched': enriched, 'status': 'success'}
