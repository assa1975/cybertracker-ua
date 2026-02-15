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
    neo4j_synced = Column(DateTime, nullable=True)
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
            'neo4j_synced': self.neo4j_synced.isoformat() if self.neo4j_synced else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ThreatPerson(Base):
    __tablename__ = 'threat_persons'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(300), nullable=False)
    aliases = Column(String(500), nullable=True)
    role = Column(String(200), nullable=True)
    organization = Column(String(300), nullable=True)
    country = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    operations = Column(Text, nullable=True)  # JSON list of operations
    status = Column(String(100), nullable=True)
    source_url = Column(String(1000), nullable=True)
    photo_url = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_person_name', 'name'),
        Index('idx_person_org', 'organization'),
        Index('idx_person_role', 'role'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'aliases': self.aliases,
            'role': self.role,
            'organization': self.organization,
            'country': self.country,
            'description': self.description,
            'operations': self.operations,
            'status': self.status,
            'source_url': self.source_url,
            'photo_url': self.photo_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ThreatOrganization(Base):
    __tablename__ = 'threat_organizations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(300), nullable=False)
    org_type = Column(String(200), nullable=True)
    aliases = Column(String(500), nullable=True)
    country = Column(String(100), nullable=True)
    parent_org = Column(String(300), nullable=True)
    description = Column(Text, nullable=True)
    known_operations = Column(Text, nullable=True)  # JSON list
    members_count = Column(Integer, nullable=True)
    source_url = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_org_name', 'name'),
        Index('idx_org_type', 'org_type'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'org_type': self.org_type,
            'aliases': self.aliases,
            'country': self.country,
            'parent_org': self.parent_org,
            'description': self.description,
            'known_operations': self.known_operations,
            'members_count': self.members_count,
            'source_url': self.source_url,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class IOCIndicator(Base):
    __tablename__ = 'ioc_indicators_feed'

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(2000), nullable=False)
    ioc_type = Column(String(50), nullable=False)
    source = Column(String(200), nullable=False)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    threat_level = Column(String(20), default='unknown')
    tags = Column(String(1000), nullable=True)
    confidence = Column(Integer, default=0)
    description = Column(Text, nullable=True)
    enrichment_data = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_ioc_value', 'value'),
        Index('idx_ioc_type', 'ioc_type'),
        Index('idx_ioc_source', 'source'),
        Index('idx_ioc_threat_level', 'threat_level'),
        Index('idx_ioc_first_seen', 'first_seen'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'value': self.value,
            'ioc_type': self.ioc_type,
            'source': self.source,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'threat_level': self.threat_level,
            'tags': self.tags,
            'confidence': self.confidence,
            'description': self.description,
            'enrichment_data': self.enrichment_data,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class UploadedDocument(Base):
    __tablename__ = 'uploaded_documents'

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(500), nullable=False)
    original_name = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)
    page_count = Column(Integer, default=0)
    doc_type = Column(String(50), default='pdf')  # pdf, txt, csv
    title = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    extracted_text = Column(Text, nullable=True)  # Full extracted text
    language = Column(String(10), nullable=True)  # detected language: uk, en, ru
    # Analysis results
    ioc_data = Column(Text, nullable=True)  # JSON: extracted IOCs
    ioc_count = Column(Integer, default=0)
    threat_actors = Column(String(1000), nullable=True)  # comma-separated
    attack_types = Column(String(1000), nullable=True)  # comma-separated
    target_sectors = Column(String(1000), nullable=True)  # comma-separated
    mitre_techniques = Column(String(500), nullable=True)  # comma-separated
    keywords = Column(Text, nullable=True)  # JSON: keyword frequency
    summary = Column(Text, nullable=True)  # Auto-generated summary
    # Neo4j sync
    neo4j_synced = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('idx_doc_filename', 'filename'),
        Index('idx_doc_type', 'doc_type'),
        Index('idx_doc_created', 'created_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_name': self.original_name,
            'file_size': self.file_size,
            'page_count': self.page_count,
            'doc_type': self.doc_type,
            'title': self.title,
            'description': self.description,
            'language': self.language,
            'ioc_count': self.ioc_count,
            'threat_actors': self.threat_actors,
            'attack_types': self.attack_types,
            'target_sectors': self.target_sectors,
            'mitre_techniques': self.mitre_techniques,
            'summary': self.summary,
            'neo4j_synced': self.neo4j_synced.isoformat() if self.neo4j_synced else None,
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
