import logging
import time
from models import Incident
from database import get_session

logger = logging.getLogger(__name__)

CHUNK_SIZE = 4000  # googletrans limit ~5000, use 4000 for safety


def _create_translator():
    """Create a fresh Translator instance."""
    from googletrans import Translator
    return Translator()


def translate_text(text, src='auto', dest='uk'):
    """Translate text. Creates a fresh translator each time for reliability."""
    if not text or not text.strip():
        return text

    # Check if text is likely already Ukrainian (simple heuristic)
    ukrainian_chars = set('іїєґІЇЄҐ')
    if any(c in ukrainian_chars for c in text[:200]):
        return text

    try:
        translator = _create_translator()
        result = translator.translate(text[:4500], src=src, dest=dest)
        return result.text
    except Exception as e:
        logger.error(f"Translation error: {e}")
        return text


def translate_long_text(text, src='auto', dest='uk'):
    """Translate long text by splitting into chunks at paragraph boundaries."""
    if not text or not text.strip():
        return text

    # Check if text is likely already Ukrainian
    ukrainian_chars = set('іїєґІЇЄҐ')
    if any(c in ukrainian_chars for c in text[:200]):
        return text

    # If text is short enough, translate directly
    if len(text) <= CHUNK_SIZE:
        return translate_text(text, src, dest)

    # Split into chunks at paragraph boundaries
    chunks = _split_into_chunks(text, CHUNK_SIZE)
    translated_chunks = []

    for i, chunk in enumerate(chunks):
        try:
            translator = _create_translator()
            result = translator.translate(chunk, src=src, dest=dest)
            translated_chunks.append(result.text)
            if i < len(chunks) - 1:
                time.sleep(0.3)  # Small delay between chunks
        except Exception as e:
            logger.error(f"Translation error on chunk {i+1}/{len(chunks)}: {e}")
            translated_chunks.append(chunk)  # Keep original on error

    return '\n\n'.join(translated_chunks)


def _split_into_chunks(text, max_size):
    """Split text into chunks at paragraph boundaries."""
    paragraphs = text.split('\n\n')
    chunks = []
    current_chunk = []
    current_len = 0

    for para in paragraphs:
        para_len = len(para)
        if current_len + para_len + 2 > max_size and current_chunk:
            chunks.append('\n\n'.join(current_chunk))
            current_chunk = [para]
            current_len = para_len
        else:
            current_chunk.append(para)
            current_len += para_len + 2

    if current_chunk:
        chunks.append('\n\n'.join(current_chunk))

    # If any chunk is still too large, force-split it
    final_chunks = []
    for chunk in chunks:
        if len(chunk) > max_size:
            for i in range(0, len(chunk), max_size):
                final_chunks.append(chunk[i:i + max_size])
        else:
            final_chunks.append(chunk)

    return final_chunks


def translate_incident(incident_id):
    """Translate a single incident by ID (title, description, full_text)."""
    session = get_session()
    try:
        incident = session.query(Incident).get(incident_id)
        if not incident:
            return False

        # Check if already Ukrainian using character heuristic
        ukrainian_chars = set('іїєґІЇЄҐ')
        title_is_uk = any(c in ukrainian_chars for c in (incident.title or '')[:200])

        if title_is_uk:
            incident.title_uk = incident.title
            incident.description_uk = incident.description
            if incident.full_text:
                incident.full_text_uk = incident.full_text
        else:
            incident.title_uk = translate_text(incident.title)

            if incident.description:
                desc = incident.description[:4500]
                incident.description_uk = translate_text(desc)
            else:
                incident.description_uk = None

            # Translate full text with chunking
            if incident.full_text:
                incident.full_text_uk = translate_long_text(incident.full_text)
            else:
                incident.full_text_uk = None

        session.commit()
        logger.info(f"Translated incident #{incident.id}")
        return True
    except Exception as e:
        session.rollback()
        logger.error(f"Error translating incident #{incident.id}: {e}")
        return False
    finally:
        session.close()


def translate_untranslated():
    """Find and translate all incidents without Ukrainian translation."""
    session = get_session()
    try:
        untranslated_ids = [
            r[0] for r in
            session.query(Incident.id)
            .filter(Incident.title_uk.is_(None))
            .order_by(Incident.date.desc())
            .all()
        ]
    finally:
        session.close()

    total = len(untranslated_ids)
    translated = 0

    logger.info(f"Found {total} untranslated incidents")

    for inc_id in untranslated_ids:
        try:
            if translate_incident(inc_id):
                translated += 1
        except Exception as e:
            logger.error(f"Failed to translate incident #{inc_id}: {e}")
        time.sleep(0.5)

    logger.info(f"Translated {translated} of {total} incidents")
    return {'total': total, 'translated': translated}
