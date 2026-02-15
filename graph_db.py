"""
Neo4j Graph Database Connection Manager.
Provides singleton driver, graceful degradation when Neo4j is unavailable,
and schema initialization (constraints + indexes).
"""

import logging
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_ENABLED

logger = logging.getLogger(__name__)

_driver = None


def get_driver():
    """Get or create Neo4j driver (singleton). Returns None if not configured."""
    global _driver
    if not NEO4J_ENABLED:
        return None

    if _driver is not None:
        return _driver

    try:
        from neo4j import GraphDatabase
        auth = (NEO4J_USER, NEO4J_PASSWORD) if NEO4J_PASSWORD else None
        _driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=auth,
            max_connection_lifetime=3600,
        )
        # Verify connectivity
        _driver.verify_connectivity()
        logger.info(f"Neo4j: Connected to {NEO4J_URI}")
        return _driver
    except Exception as e:
        logger.warning(f"Neo4j: Connection failed — {e}")
        _driver = None
        return None


def close_driver():
    """Close Neo4j driver gracefully."""
    global _driver
    if _driver:
        try:
            _driver.close()
            logger.info("Neo4j: Driver closed")
        except Exception as e:
            logger.warning(f"Neo4j: Error closing driver — {e}")
        _driver = None


def is_available():
    """Check if Neo4j is available."""
    driver = get_driver()
    if driver is None:
        return False
    try:
        driver.verify_connectivity()
        return True
    except Exception:
        return False


def execute_query(query, parameters=None, database="neo4j"):
    """
    Execute a Cypher query with graceful degradation.
    Returns list of records or empty list if Neo4j is unavailable.
    """
    driver = get_driver()
    if driver is None:
        return []

    try:
        records, summary, keys = driver.execute_query(
            query,
            parameters_=parameters or {},
            database_=database,
        )
        return records
    except Exception as e:
        error_name = type(e).__name__
        if 'ServiceUnavailable' in error_name or 'SessionExpired' in error_name:
            logger.warning(f"Neo4j unavailable: {e}")
            return []
        logger.error(f"Neo4j query error: {e}")
        return []


def execute_write(query, parameters=None, database="neo4j"):
    """
    Execute a write Cypher query.
    Returns True on success, False on failure.
    """
    driver = get_driver()
    if driver is None:
        return False

    try:
        driver.execute_query(
            query,
            parameters_=parameters or {},
            database_=database,
        )
        return True
    except Exception as e:
        error_name = type(e).__name__
        if 'ServiceUnavailable' in error_name or 'SessionExpired' in error_name:
            logger.warning(f"Neo4j unavailable for write: {e}")
        else:
            logger.error(f"Neo4j write error: {e}")
        return False


def init_graph_schema():
    """
    Initialize Neo4j schema with constraints and indexes.
    Call once on startup. Gracefully handles unavailability.
    """
    if not NEO4J_ENABLED:
        logger.info("Neo4j: Disabled (no password configured)")
        return False

    driver = get_driver()
    if driver is None:
        logger.info("Neo4j: Not available, skipping schema init")
        return False

    schema_queries = [
        # Uniqueness constraints
        "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE",
        "CREATE CONSTRAINT source_name IF NOT EXISTS FOR (s:Source) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT actor_name IF NOT EXISTS FOR (a:ThreatActor) REQUIRE a.name IS UNIQUE",
        "CREATE CONSTRAINT attack_type_name IF NOT EXISTS FOR (t:AttackType) REQUIRE t.name IS UNIQUE",
        "CREATE CONSTRAINT sector_name IF NOT EXISTS FOR (s:Sector) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT mitre_id IF NOT EXISTS FOR (m:MITRETechnique) REQUIRE m.technique_id IS UNIQUE",
        "CREATE CONSTRAINT ioc_value IF NOT EXISTS FOR (c:IOCIndicator) REQUIRE c.value IS UNIQUE",
        # New node types
        "CREATE CONSTRAINT person_name IF NOT EXISTS FOR (p:Person) REQUIRE p.name IS UNIQUE",
        "CREATE CONSTRAINT org_name IF NOT EXISTS FOR (o:Organization) REQUIRE o.name IS UNIQUE",
        "CREATE CONSTRAINT doc_id IF NOT EXISTS FOR (d:Document) REQUIRE d.doc_id IS UNIQUE",
        "CREATE CONSTRAINT country_name IF NOT EXISTS FOR (c:Country) REQUIRE c.name IS UNIQUE",
        "CREATE CONSTRAINT operation_name IF NOT EXISTS FOR (op:Operation) REQUIRE op.name IS UNIQUE",

        # Indexes for search
        "CREATE INDEX incident_date IF NOT EXISTS FOR (i:Incident) ON (i.date)",
        "CREATE INDEX incident_severity IF NOT EXISTS FOR (i:Incident) ON (i.severity)",
        "CREATE INDEX ioc_type IF NOT EXISTS FOR (c:IOCIndicator) ON (c.type)",
        "CREATE INDEX doc_type IF NOT EXISTS FOR (d:Document) ON (d.doc_type)",
        "CREATE INDEX person_role IF NOT EXISTS FOR (p:Person) ON (p.role)",
        "CREATE INDEX org_type IF NOT EXISTS FOR (o:Organization) ON (o.org_type)",
    ]

    success_count = 0
    for query in schema_queries:
        try:
            driver.execute_query(query, database_="neo4j")
            success_count += 1
        except Exception as e:
            # Constraint may already exist — that's OK
            if 'already exists' in str(e).lower() or 'equivalent' in str(e).lower():
                success_count += 1
            else:
                logger.warning(f"Neo4j schema query failed: {e}")

    logger.info(f"Neo4j: Schema initialized ({success_count}/{len(schema_queries)} constraints/indexes)")
    return True
