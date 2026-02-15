import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from rss_parser import fetch_all_feeds
from config import (
    FETCH_INTERVAL_MINUTES, TWITTER_ENABLED,
    TWITTER_FETCH_INTERVAL_MINUTES, NEO4J_ENABLED,
)

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler()


def start_scheduler(app):
    """Start background RSS fetch, Twitter fetch, and daily report schedulers."""

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

    def twitter_job():
        with app.app_context():
            try:
                from twitter_fetcher import fetch_all_twitter
                result = fetch_all_twitter()
                logger.info(
                    f"Twitter fetch: {result.get('total_added', 0)} new "
                    f"of {result.get('total_found', 0)} found"
                )
            except Exception as e:
                logger.error(f"Twitter fetch failed: {e}")

    def daily_report_job():
        with app.app_context():
            try:
                from scraper import scrape_unscraped
                from translator import translate_untranslated
                from report_generator import generate_daily_report

                # 1. Fetch fresh RSS data
                fetch_all_feeds()

                # 2. Fetch Twitter
                if TWITTER_ENABLED:
                    try:
                        from twitter_fetcher import fetch_all_twitter
                        fetch_all_twitter()
                    except Exception as e:
                        logger.error(f"Twitter fetch in daily pipeline failed: {e}")

                # 3. Scrape full articles
                scrape_unscraped()

                # 4. Translate all untranslated
                translate_untranslated()

                # 5. Sync to Neo4j
                if NEO4J_ENABLED:
                    try:
                        from graph_sync import sync_all_unsynced
                        sync_all_unsynced()
                    except Exception as e:
                        logger.error(f"Neo4j sync in daily pipeline failed: {e}")

                # 6. Generate report for yesterday
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

    # Twitter fetch every N minutes (if enabled)
    if TWITTER_ENABLED:
        scheduler.add_job(
            twitter_job,
            'interval',
            minutes=TWITTER_FETCH_INTERVAL_MINUTES,
            id='twitter_fetch_job',
            replace_existing=True,
            next_run_time=None,
        )
        logger.info(f"Twitter scheduler: every {TWITTER_FETCH_INTERVAL_MINUTES} min")

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
