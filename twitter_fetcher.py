"""
Twitter/X API Fetcher Module.
Monitors cybersecurity accounts for Ukraine-related tweets.
Uses Twitter API v2 via tweepy.
"""

import re
import logging
import time
from datetime import datetime, timezone, timedelta

from sqlalchemy.exc import IntegrityError

from models import Incident, FetchLog
from database import get_session
from config import (
    TWITTER_BEARER_TOKEN, TWITTER_ENABLED, TWITTER_ACCOUNTS,
    UKRAINE_KEYWORDS, ATTACK_TYPE_KEYWORDS, SECTOR_KEYWORDS, THREAT_ACTORS,
)
from ioc_extractor import extract_iocs, iocs_to_json

logger = logging.getLogger(__name__)


def _get_client():
    """Create tweepy Client with Bearer Token."""
    if not TWITTER_ENABLED:
        raise RuntimeError("Twitter API is not configured. Set TWITTER_BEARER_TOKEN in .env")

    import tweepy
    return tweepy.Client(
        bearer_token=TWITTER_BEARER_TOKEN,
        wait_on_rate_limit=True,
    )


def is_ukraine_relevant(text):
    """Check if tweet text contains Ukraine-related keywords."""
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


def fetch_user_tweets(client, username, since_hours=24):
    """
    Fetch recent tweets from a specific user.
    Returns list of tweet dicts.
    """
    try:
        # Get user ID first
        user = client.get_user(username=username)
        if not user or not user.data:
            logger.warning(f"Twitter user not found: {username}")
            return []

        user_id = user.data.id
        since_time = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        # Get tweets
        tweets = client.get_users_tweets(
            id=user_id,
            start_time=since_time,
            max_results=20,
            tweet_fields=['created_at', 'text', 'entities', 'public_metrics'],
            exclude=['retweets', 'replies'],
        )

        if not tweets or not tweets.data:
            return []

        results = []
        for tweet in tweets.data:
            results.append({
                'id': tweet.id,
                'text': tweet.text,
                'created_at': tweet.created_at,
                'username': username,
                'url': f"https://x.com/{username}/status/{tweet.id}",
                'metrics': tweet.public_metrics if hasattr(tweet, 'public_metrics') else {},
            })

        return results

    except Exception as e:
        logger.error(f"Error fetching tweets from {username}: {e}")
        return []


def process_tweet(tweet_data):
    """
    Process a single tweet and return incident dict if relevant.
    Returns None if not relevant to Ukraine.
    """
    text = tweet_data['text']

    # Check Ukraine relevance
    if not is_ukraine_relevant(text):
        return None

    # Classify
    attack_type = classify_attack_type(text)
    target_sector = classify_target_sector(text)
    threat_actor = identify_threat_actor(text)
    severity = assign_severity(attack_type, threat_actor)

    # Extract IOCs
    iocs = extract_iocs(text)
    ioc_json = iocs_to_json(iocs)

    # MITRE technique from IOCs
    mitre_id = None
    if iocs.get('mitre'):
        mitre_id = iocs['mitre'][0]

    # Title: first 200 chars of tweet
    title = text[:200].replace('\n', ' ').strip()
    if len(text) > 200:
        title = title[:197] + '...'

    return {
        'title': title,
        'description': text,
        'date': tweet_data.get('created_at') or datetime.now(timezone.utc),
        'source': f"Twitter/@{tweet_data['username']}",
        'source_url': tweet_data['url'],
        'attack_type': attack_type,
        'target_sector': target_sector,
        'threat_actor': threat_actor,
        'severity': severity,
        'ioc_indicators': ioc_json,
        'mitre_technique_id': mitre_id,
    }


def store_twitter_incident(incident_data):
    """Store Twitter-sourced incident in DB. Returns True if inserted."""
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
        logger.error(f"Error storing Twitter incident: {e}")
        return False
    finally:
        session.close()


def fetch_all_twitter():
    """
    Fetch tweets from all monitored accounts.
    Returns summary dict with stats.
    """
    if not TWITTER_ENABLED:
        return {
            'total_found': 0,
            'total_added': 0,
            'status': 'disabled',
            'message': 'Twitter API not configured',
        }

    try:
        client = _get_client()
    except Exception as e:
        logger.error(f"Failed to create Twitter client: {e}")
        return {
            'total_found': 0,
            'total_added': 0,
            'status': 'error',
            'message': str(e),
        }

    total_found = 0
    total_added = 0

    for username in TWITTER_ACCOUNTS:
        try:
            tweets = fetch_user_tweets(client, username, since_hours=24)
            logger.info(f"Twitter @{username}: fetched {len(tweets)} tweets")

            for tweet_data in tweets:
                incident_data = process_tweet(tweet_data)
                if incident_data is None:
                    continue

                total_found += 1
                if store_twitter_incident(incident_data):
                    total_added += 1

            time.sleep(1)  # Rate limit courtesy

        except Exception as e:
            logger.error(f"Error processing Twitter @{username}: {e}")

    # Log the fetch
    session = get_session()
    try:
        log = FetchLog(
            feed_name='Twitter/X',
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

    logger.info(f"Twitter fetch: {total_added} added of {total_found} relevant")
    return {
        'total_found': total_found,
        'total_added': total_added,
        'status': 'success',
    }
