import os
import json
import logging
import re
import time
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from models import Incident
from database import get_session
from config import BASE_DIR
from ioc_extractor import extract_iocs, iocs_to_json, merge_ioc_json

logger = logging.getLogger(__name__)

IMAGES_DIR = os.path.join(BASE_DIR, 'data', 'images')
HEADERS = {'User-Agent': 'CyberTrackerUA/1.0 (article scraper)'}

# Content selectors per source (priority order)
CONTENT_SELECTORS = [
    # Specific sites (original)
    {'domain': 'cert.gov.ua', 'selectors': ['.article-content', '.news-detail', 'article']},
    {'domain': 'bleepingcomputer.com', 'selectors': ['.articleBody', '.article_section']},
    {'domain': 'therecord.media', 'selectors': ['.article-content', 'article .content']},
    {'domain': 'securityweek.com', 'selectors': ['.article-content', '.entry-content']},
    {'domain': 'thehackernews.com', 'selectors': ['.articlebody', '#articlebody', '.storycontent']},
    # New threat intel sources
    {'domain': 'recordedfuture.com', 'selectors': ['.entry-content', '.post-content', 'article']},
    {'domain': 'blog.google', 'selectors': ['.article-body', '.post-content', 'article']},
    {'domain': 'microsoft.com', 'selectors': ['.entry-content', '.article-content', '.content-body', 'article']},
    {'domain': 'cisa.gov', 'selectors': ['.c-field--type-text-long', '.l-full__main', 'article', 'main']},
    {'domain': 'talosintelligence.com', 'selectors': ['.post-body', '.entry-content', 'article']},
    {'domain': 'mandiant.com', 'selectors': ['.article-content', '.blog-content', '.entry-content', 'article']},
]

# Generic selectors (fallback)
GENERIC_SELECTORS = [
    'article',
    '[role="article"]',
    '.article-body',
    '.article-content',
    '.post-content',
    '.entry-content',
    '.story-body',
    '.content-body',
    'main',
]

# Minimum article length to consider valid
MIN_ARTICLE_LENGTH = 200

# Skip images smaller than this (likely icons/tracking pixels)
MIN_IMAGE_SIZE = 5000  # bytes


def scrape_article(url):
    """
    Scrape full article text and image URLs from a URL.
    Returns {'full_text': str, 'image_urls': [str]}
    """
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30, allow_redirects=True)
        resp.raise_for_status()
        resp.encoding = resp.apparent_encoding or 'utf-8'
        html = resp.text
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
        return None

    soup = BeautifulSoup(html, 'lxml')

    # Remove unwanted elements
    for tag in soup.find_all(['script', 'style', 'nav', 'header', 'footer',
                               'aside', 'form', 'iframe', 'noscript']):
        tag.decompose()

    # Remove ad/social divs
    for tag in soup.find_all(class_=re.compile(
        r'(social|share|comment|sidebar|related|newsletter|subscribe|ad-|ads-|popup|modal|cookie)',
        re.I
    )):
        tag.decompose()

    # Find content container
    content_el = _find_content(soup, url)
    if not content_el:
        logger.warning(f"Could not find article content for {url}")
        return None

    # Extract text
    full_text = _extract_text(content_el)
    if len(full_text) < MIN_ARTICLE_LENGTH:
        logger.warning(f"Article text too short ({len(full_text)} chars) for {url}")
        # Try broader search
        body = soup.find('body')
        if body:
            full_text = _extract_text(body)

    # Extract image URLs
    image_urls = _extract_images(content_el, url)

    return {
        'full_text': full_text,
        'image_urls': image_urls,
    }


def _find_content(soup, url):
    """Find the main content element using site-specific and generic selectors."""
    domain = urlparse(url).netloc.lower()

    # Try site-specific selectors first
    for config in CONTENT_SELECTORS:
        if config['domain'] in domain:
            for selector in config['selectors']:
                el = soup.select_one(selector)
                if el and len(el.get_text(strip=True)) >= MIN_ARTICLE_LENGTH:
                    return el

    # Try generic selectors
    for selector in GENERIC_SELECTORS:
        el = soup.select_one(selector)
        if el and len(el.get_text(strip=True)) >= MIN_ARTICLE_LENGTH:
            return el

    return None


def _extract_text(element):
    """Extract clean text from HTML element, preserving paragraph structure."""
    paragraphs = []
    for tag in element.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'blockquote']):
        text = tag.get_text(strip=True)
        if text and len(text) > 10:
            paragraphs.append(text)

    if not paragraphs:
        # Fallback to all text
        return element.get_text(separator='\n', strip=True)

    return '\n\n'.join(paragraphs)


def _extract_images(element, base_url):
    """Extract image URLs from content element."""
    image_urls = []
    seen = set()

    for img in element.find_all('img'):
        src = img.get('src') or img.get('data-src') or img.get('data-lazy-src')
        if not src:
            continue

        # Make absolute URL
        src = urljoin(base_url, src)

        # Skip duplicates, data URIs, tracking pixels, SVGs
        if src in seen:
            continue
        if src.startswith('data:'):
            continue
        if '.svg' in src.lower():
            continue
        if any(x in src.lower() for x in ['pixel', 'tracking', 'beacon', 'spacer', '1x1']):
            continue

        seen.add(src)
        image_urls.append(src)

    return image_urls


def download_images(image_urls, incident_id):
    """Download images to data/images/{incident_id}/. Returns list of local paths."""
    if not image_urls:
        return []

    img_dir = os.path.join(IMAGES_DIR, str(incident_id))
    os.makedirs(img_dir, exist_ok=True)

    saved_paths = []
    for i, url in enumerate(image_urls[:10]):  # Max 10 images per article
        try:
            resp = requests.get(url, headers=HEADERS, timeout=20, stream=True)
            resp.raise_for_status()

            # Check content type
            content_type = resp.headers.get('content-type', '')
            if 'image' not in content_type:
                continue

            # Determine extension
            ext = '.jpg'
            if 'png' in content_type:
                ext = '.png'
            elif 'gif' in content_type:
                ext = '.gif'
            elif 'webp' in content_type:
                ext = '.webp'

            filepath = os.path.join(img_dir, f'img_{i+1:03d}{ext}')

            # Download
            content = resp.content
            if len(content) < MIN_IMAGE_SIZE:
                continue  # Skip tiny images

            with open(filepath, 'wb') as f:
                f.write(content)

            saved_paths.append(filepath)
            logger.info(f"Downloaded image: {filepath}")

        except Exception as e:
            logger.warning(f"Failed to download image {url}: {e}")
            continue

    return saved_paths


def scrape_and_save(incident_id):
    """Scrape full article for an incident and save to DB."""
    session = get_session()
    try:
        incident = session.query(Incident).get(incident_id)
        if not incident or not incident.source_url:
            return False

        result = scrape_article(incident.source_url)
        if not result:
            return False

        # Save full text
        incident.full_text = result['full_text']

        # Download and save images
        image_paths = download_images(result['image_urls'], incident.id)
        if image_paths:
            incident.images = json.dumps(image_paths)

        # Extract IOCs from full text and merge with existing
        iocs = extract_iocs(result['full_text'])
        ioc_json = iocs_to_json(iocs)
        if ioc_json:
            incident.ioc_indicators = merge_ioc_json(incident.ioc_indicators, iocs)
            logger.info(f"Extracted IOCs from incident #{incident.id}: {sum(len(v) for v in iocs.values() if v)} indicators")

        # Extract MITRE technique if not already set
        if not incident.mitre_technique_id and iocs.get('mitre'):
            incident.mitre_technique_id = iocs['mitre'][0]

        session.commit()
        logger.info(f"Scraped incident #{incident.id}: {len(result['full_text'])} chars, {len(image_paths)} images")
        return True

    except Exception as e:
        session.rollback()
        logger.error(f"Error scraping incident #{incident.id}: {e}")
        return False
    finally:
        session.close()


def scrape_unscraped():
    """Find incidents without full_text and scrape them."""
    session = get_session()
    try:
        unscraped_ids = [
            r[0] for r in
            session.query(Incident.id)
            .filter(Incident.full_text.is_(None))
            .filter(Incident.source_url.isnot(None))
            .order_by(Incident.date.desc())
            .all()
        ]
    finally:
        session.close()

    total = len(unscraped_ids)
    scraped = 0

    logger.info(f"Found {total} unscraped incidents")

    for inc_id in unscraped_ids:
        try:
            if scrape_and_save(inc_id):
                scraped += 1
        except Exception as e:
            logger.error(f"Failed to scrape incident #{inc_id}: {e}")
        time.sleep(2)  # Polite crawling delay

    logger.info(f"Scraped {scraped} of {total} incidents")
    return {'total': total, 'scraped': scraped}
