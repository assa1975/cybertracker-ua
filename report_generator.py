import os
import json
import logging
from datetime import datetime, timedelta, timezone

from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.style import WD_STYLE_TYPE

from models import Incident
from database import get_session
from config import BASE_DIR

logger = logging.getLogger(__name__)

REPORT_DIR = os.path.join(os.path.expanduser('~'), 'Desktop')
IMAGES_DIR = os.path.join(BASE_DIR, 'data', 'images')

# Max image width in the Word document (inches)
MAX_IMAGE_WIDTH = Inches(5.5)

# Ukrainian month names for formatting
MONTHS_UK = {
    1: 'січня', 2: 'лютого', 3: 'березня', 4: 'квітня',
    5: 'травня', 6: 'червня', 7: 'липня', 8: 'серпня',
    9: 'вересня', 10: 'жовтня', 11: 'листопада', 12: 'грудня',
}


def format_date_uk(dt):
    """Format datetime as '14 лютого 2026'."""
    if not dt:
        return ''
    return f"{dt.day} {MONTHS_UK.get(dt.month, '')} {dt.year}"


def _add_images_to_doc(doc, incident):
    """Add images from incident to the Word document."""
    if not incident.images:
        return

    try:
        image_paths = json.loads(incident.images)
    except (json.JSONDecodeError, TypeError):
        return

    added = 0
    for img_path in image_paths:
        if not os.path.isfile(img_path):
            continue
        try:
            doc.add_picture(img_path, width=MAX_IMAGE_WIDTH)
            # Center the image
            last_paragraph = doc.paragraphs[-1]
            last_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
            added += 1
        except Exception as e:
            logger.warning(f"Could not add image {img_path}: {e}")

    if added:
        doc.add_paragraph()  # spacer after images


def generate_daily_report(target_date=None):
    """
    Generate a Word report for incidents on target_date.
    If target_date is None, uses today.
    Returns the path to the generated file.
    """
    if target_date is None:
        target_date = datetime.now(timezone.utc).date()
    elif isinstance(target_date, datetime):
        target_date = target_date.date()

    session = get_session()
    try:
        # Query incidents for the target date
        date_start = datetime(target_date.year, target_date.month, target_date.day, tzinfo=timezone.utc)
        date_end = date_start + timedelta(days=1)

        incidents = (
            session.query(Incident)
            .filter(Incident.date >= date_start, Incident.date < date_end)
            .order_by(Incident.date.desc())
            .all()
        )

        # If no incidents for exact date, get all recent (last 7 days)
        if not incidents:
            week_ago = date_start - timedelta(days=7)
            incidents = (
                session.query(Incident)
                .filter(Incident.date >= week_ago, Incident.date < date_end)
                .order_by(Incident.date.desc())
                .all()
            )

        doc = Document()

        # Set default font
        style = doc.styles['Normal']
        font = style.font
        font.name = 'Calibri'
        font.size = Pt(11)

        # Title
        title = doc.add_heading(level=0)
        run = title.add_run(f"Звіт про кібератаки проти України")
        run.font.size = Pt(20)
        run.font.color.rgb = RGBColor(0, 91, 187)  # Ukrainian blue

        # Date subtitle
        date_str = format_date_uk(date_start)
        subtitle = doc.add_paragraph()
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = subtitle.add_run(date_str)
        run.font.size = Pt(14)
        run.font.color.rgb = RGBColor(100, 100, 100)

        # Summary
        doc.add_paragraph()
        summary = doc.add_paragraph()
        run = summary.add_run(f"Всього інцидентів у звіті: {len(incidents)}")
        run.bold = True
        run.font.size = Pt(12)

        doc.add_paragraph()  # spacer

        if not incidents:
            p = doc.add_paragraph()
            run = p.add_run("Інцидентів за вказану дату не знайдено.")
            run.italic = True
        else:
            for i, inc in enumerate(incidents, 1):
                # Incident header
                heading = doc.add_heading(level=2)
                run = heading.add_run(f"{i}. {inc.title}")
                run.font.size = Pt(14)

                # Ukrainian translation of title
                if inc.title_uk and inc.title_uk != inc.title:
                    p = doc.add_paragraph()
                    run = p.add_run(f"[UA] {inc.title_uk}")
                    run.bold = True
                    run.font.color.rgb = RGBColor(0, 91, 187)

                # Metadata table
                meta_items = []
                if inc.date:
                    meta_items.append(('Дата', format_date_uk(inc.date)))
                if inc.attack_type:
                    meta_items.append(('Тип атаки', inc.attack_type))
                if inc.target_sector:
                    meta_items.append(('Сектор', inc.target_sector))
                if inc.severity:
                    meta_items.append(('Критичність', inc.severity))
                if inc.threat_actor:
                    meta_items.append(('Загрозливий актор', inc.threat_actor))
                if inc.source:
                    meta_items.append(('Джерело', inc.source))

                if meta_items:
                    table = doc.add_table(rows=len(meta_items), cols=2)
                    table.style = 'Light Grid Accent 1'
                    for row_idx, (label, value) in enumerate(meta_items):
                        cells = table.rows[row_idx].cells
                        cells[0].text = label
                        cells[1].text = value
                        # Bold the label
                        for paragraph in cells[0].paragraphs:
                            for run in paragraph.runs:
                                run.bold = True

                doc.add_paragraph()  # spacer

                # Images from article
                _add_images_to_doc(doc, inc)

                # Full text (Ukrainian translation preferred, fallback to description)
                full_text = inc.full_text_uk or inc.full_text
                desc_text = inc.description_uk or inc.description

                if full_text:
                    p = doc.add_paragraph()
                    run = p.add_run("Повний текст статті:")
                    run.bold = True
                    # Split into paragraphs for better formatting
                    for para_text in full_text.split('\n\n'):
                        para_text = para_text.strip()
                        if para_text:
                            doc.add_paragraph(para_text[:5000])
                elif desc_text:
                    p = doc.add_paragraph()
                    run = p.add_run("Опис:")
                    run.bold = True
                    doc.add_paragraph(desc_text[:3000])

                # Source URL
                if inc.source_url:
                    p = doc.add_paragraph()
                    run = p.add_run("Джерело: ")
                    run.bold = True
                    p.add_run(inc.source_url)

                # Separator
                if i < len(incidents):
                    doc.add_paragraph('_' * 60)
                    doc.add_paragraph()

        # Footer
        doc.add_paragraph()
        footer = doc.add_paragraph()
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = footer.add_run("--- CyberTracker UA ---")
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(150, 150, 150)

        # Save
        filename = f"CyberTracker_Report_{target_date.strftime('%Y-%m-%d')}.docx"
        filepath = os.path.join(REPORT_DIR, filename)
        doc.save(filepath)

        logger.info(f"Report generated: {filepath} ({len(incidents)} incidents)")
        return filepath

    finally:
        session.close()
