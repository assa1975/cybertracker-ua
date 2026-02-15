import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from rss_parser import fetch_all_feeds
from config import FETCH_INTERVAL_MINUTES

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler()


def start_scheduler(app):
    """Start background RSS fetch and daily report schedulers."""

    def fetch_job():
        with app.app_context():
            try:
                result = fetch_all_feeds()
                logger.info(
                    f"Scheduled fetch: {result['total_added']} new "
                    f"of {result['total_found']} found"
                )
            except Exception as e:
                logger.error(f"Scheduled fetch failed: {e}")

    def daily_report_job():
        with app.app_context():
            try:
                from scraper import scrape_unscraped
                from translator import translate_untranslated
                from report_generator import generate_daily_report

                # 1. Fetch fresh RSS data
                fetch_all_feeds()

                # 2. Scrape full articles
                scrape_unscraped()

                # 3. Translate all untranslated
                translate_untranslated()

                # 4. Generate report for yesterday
                yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
                filepath = generate_daily_report(yesterday)
                logger.info(f"Daily report generated: {filepath}")
            except Exception as e:
                logger.error(f"Daily report job failed: {e}")

    # RSS fetch every N minutes
    scheduler.add_job(
        fetch_job,
        'interval',
        minutes=FETCH_INTERVAL_MINUTES,
        id='rss_fetch_job',
        replace_existing=True,
        next_run_time=None,
    )

    # Daily report at 08:00
    scheduler.add_job(
        daily_report_job,
        CronTrigger(hour=8, minute=0),
        id='daily_report_job',
        replace_existing=True,
    )

    scheduler.start()
    logger.info(f"Scheduler started: RSS every {FETCH_INTERVAL_MINUTES} min, report daily at 08:00")


def stop_scheduler():
    """Gracefully shut down the scheduler."""
    if scheduler.running:
        scheduler.shutdown()
