import logging
from app import create_app
from database import init_db, migrate_db
from scheduler import start_scheduler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)

if __name__ == '__main__':
    init_db()
    migrate_db()
    app = create_app()
    start_scheduler(app)
    print("\n=== CyberTracker UA ===")
    print("http://127.0.0.1:5000")
    print("Press Ctrl+C to stop\n")
    app.run(debug=True, use_reloader=False, host='127.0.0.1', port=5000)
