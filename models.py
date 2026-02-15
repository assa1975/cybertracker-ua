from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Incident(Base):
    __tablename__ = 'incidents'

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    date = Column(DateTime, nullable=True)
    source = Column(String(200), nullable=True)
    source_url = Column(String(1000), nullable=True, unique=True)
    attack_type = Column(String(200), nullable=True)
    target_sector = Column(String(200), nullable=True)
    threat_actor = Column(String(200), nullable=True)
    ioc_indicators = Column(Text, nullable=True)
    severity = Column(String(50), nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)
    title_uk = Column(String(500), nullable=True)
    description_uk = Column(Text, nullable=True)
    full_text = Column(Text, nullable=True)
    full_text_uk = Column(Text, nullable=True)
    images = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_date', 'date'),
        Index('idx_source', 'source'),
        Index('idx_attack_type', 'attack_type'),
        Index('idx_severity', 'severity'),
        Index('idx_target_sector', 'target_sector'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'date': self.date.isoformat() if self.date else None,
            'source': self.source,
            'source_url': self.source_url,
            'attack_type': self.attack_type,
            'target_sector': self.target_sector,
            'threat_actor': self.threat_actor,
            'ioc_indicators': self.ioc_indicators,
            'severity': self.severity,
            'mitre_technique_id': self.mitre_technique_id,
            'title_uk': self.title_uk,
            'description_uk': self.description_uk,
            'full_text': self.full_text,
            'full_text_uk': self.full_text_uk,
            'images': self.images,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class FetchLog(Base):
    __tablename__ = 'fetch_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(String(200), nullable=False)
    fetched_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    entries_found = Column(Integer, default=0)
    entries_added = Column(Integer, default=0)
    status = Column(String(50), default='success')
    error_message = Column(Text, nullable=True)
