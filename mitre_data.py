import json
import os
import logging
import requests

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
LOCAL_CACHE = os.path.join(DATA_DIR, 'attack_techniques.json')

MITRE_ATTACK_JSON_URL = (
    'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/'
    'master/enterprise-attack/enterprise-attack.json'
)

_techniques_cache = None


def load_techniques():
    """Load MITRE ATT&CK technique ID -> name mapping."""
    global _techniques_cache
    if _techniques_cache is not None:
        return _techniques_cache

    # Try local cache first
    if os.path.exists(LOCAL_CACHE):
        try:
            with open(LOCAL_CACHE, 'r', encoding='utf-8') as f:
                _techniques_cache = json.load(f)
                logger.info(f"Loaded {len(_techniques_cache)} MITRE techniques from cache")
                return _techniques_cache
        except Exception as e:
            logger.warning(f"Failed to read MITRE cache: {e}")

    # Download from GitHub
    try:
        _techniques_cache = download_and_cache_techniques()
        return _techniques_cache
    except Exception as e:
        logger.error(f"Failed to download MITRE data: {e}")
        _techniques_cache = {}
        return _techniques_cache


def download_and_cache_techniques():
    """Download STIX bundle, extract technique mappings, cache to file."""
    logger.info("Downloading MITRE ATT&CK data...")
    resp = requests.get(MITRE_ATTACK_JSON_URL, timeout=60)
    resp.raise_for_status()

    stix_bundle = resp.json()
    techniques = {}

    for obj in stix_bundle.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        if obj.get('revoked', False) or obj.get('x_mitre_deprecated', False):
            continue

        ext_refs = obj.get('external_references', [])
        for ref in ext_refs:
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id', '')
                if tech_id.startswith('T'):
                    techniques[tech_id] = obj.get('name', '')
                    break

    # Save cache
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(LOCAL_CACHE, 'w', encoding='utf-8') as f:
        json.dump(techniques, f, ensure_ascii=False, indent=2)

    logger.info(f"Cached {len(techniques)} MITRE techniques")
    return techniques


def get_technique_name(technique_id):
    """Lookup a single technique ID, return its name or None."""
    if not technique_id:
        return None
    techniques = load_techniques()
    return techniques.get(technique_id)
