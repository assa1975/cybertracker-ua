import logging
import atexit

from app import create_app
from database import init_db, migrate_db
from scheduler import start_scheduler
from graph_db import init_graph_schema, close_driver, is_available
from config import NEO4J_ENABLED, TWITTER_ENABLED, VIRUSTOTAL_ENABLED, ABUSEIPDB_ENABLED

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

if __name__ == '__main__':
    init_db()
    migrate_db()

    # Initialize Neo4j schema (graceful if unavailable)
    if NEO4J_ENABLED:
        init_graph_schema()
    atexit.register(close_driver)

    app = create_app()
    start_scheduler(app)

    print("\n=== Cyber Tracker UA ===")
    print("http://127.0.0.1:5000")
    print()

    # Status display
    print(f"  RSS feeds: {11} configured")
    print(f"  Neo4j:     {'Connected' if is_available() else 'Not available (set NEO4J_PASSWORD in .env)'}")
    print(f"  Twitter:   {'Enabled' if TWITTER_ENABLED else 'Disabled (set TWITTER_BEARER_TOKEN in .env)'}")
    print(f"  VirusTotal:{'Enabled' if VIRUSTOTAL_ENABLED else 'Disabled (set VIRUSTOTAL_API_KEY in .env)'}")
    print(f"  AbuseIPDB: {'Enabled' if ABUSEIPDB_ENABLED else 'Disabled (set ABUSEIPDB_API_KEY in .env)'}")
    print()
    print("Press Ctrl+C to stop\n")
    app.run(debug=True, use_reloader=False, host='127.0.0.1', port=5000)
