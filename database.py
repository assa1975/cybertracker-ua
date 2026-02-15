import os
import logging
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base
from config import DATABASE_PATH, DATABASE_URI

logger = logging.getLogger(__name__)

engine = create_engine(DATABASE_URI, echo=False)
Session = scoped_session(sessionmaker(bind=engine))


def init_db():
    """Create data/ directory and all tables."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    Base.metadata.create_all(engine)


def migrate_db():
    """Add new columns if they don't exist (for upgrades)."""
    inspector = inspect(engine)
    columns = [col['name'] for col in inspector.get_columns('incidents')]

    with engine.begin() as conn:
        if 'title_uk' not in columns:
            conn.execute(text('ALTER TABLE incidents ADD COLUMN title_uk VARCHAR(500)'))
            logger.info("Added column title_uk to incidents")
        if 'description_uk' not in columns:
            conn.execute(text('ALTER TABLE incidents ADD COLUMN description_uk TEXT'))
            logger.info("Added column description_uk to incidents")
        if 'full_text' not in columns:
            conn.execute(text('ALTER TABLE incidents ADD COLUMN full_text TEXT'))
            logger.info("Added column full_text to incidents")
        if 'full_text_uk' not in columns:
            conn.execute(text('ALTER TABLE incidents ADD COLUMN full_text_uk TEXT'))
            logger.info("Added column full_text_uk to incidents")
        if 'images' not in columns:
            conn.execute(text('ALTER TABLE incidents ADD COLUMN images TEXT'))
            logger.info("Added column images to incidents")


def get_session():
    """Return a scoped session."""
    return Session()
