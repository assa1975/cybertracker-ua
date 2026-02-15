"""
Graph Sync Module.
Synchronizes incidents from SQLite to Neo4j graph database.
Creates nodes (Incident, Source, ThreatActor, AttackType, Sector,
MITRETechnique, IOCIndicator) and their relationships.
"""

import json
import logging
from datetime import datetime, timezone

from models import Incident
from database import get_session
from graph_db import execute_write, is_available

logger = logging.getLogger(__name__)


def sync_incident_to_graph(incident_id):
    """
    Sync a single incident to Neo4j.
    Creates/updates all related nodes and relationships.
    Returns True on success.
    """
    if not is_available():
        return False

    session = get_session()
    try:
        incident = session.query(Incident).get(incident_id)
        if not incident:
            return False

        # --- 1. Create Incident node ---
        inc_query = """
        MERGE (i:Incident {incident_id: $id})
        SET i.title = $title,
            i.title_uk = $title_uk,
            i.date = $date,
            i.severity = $severity,
            i.source_url = $source_url,
            i.updated_at = datetime()
        RETURN i
        """
        execute_write(inc_query, {
            'id': incident.id,
            'title': incident.title or '',
            'title_uk': incident.title_uk or '',
            'date': incident.date.isoformat() if incident.date else '',
            'severity': incident.severity or '',
            'source_url': incident.source_url or '',
        })

        # --- 2. Source node + relationship ---
        if incident.source:
            execute_write("""
                MERGE (s:Source {name: $name})
                WITH s
                MATCH (i:Incident {incident_id: $id})
                MERGE (i)-[:FROM]->(s)
            """, {'name': incident.source, 'id': incident.id})

        # --- 3. ThreatActor node + relationships ---
        if incident.threat_actor:
            execute_write("""
                MERGE (a:ThreatActor {name: $name})
                WITH a
                MATCH (i:Incident {incident_id: $id})
                MERGE (a)-[:ATTRIBUTED_TO]->(i)
            """, {'name': incident.threat_actor, 'id': incident.id})

            # Actor targets Sector
            if incident.target_sector:
                execute_write("""
                    MATCH (a:ThreatActor {name: $actor})
                    MERGE (s:Sector {name: $sector})
                    MERGE (a)-[:TARGETS]->(s)
                """, {'actor': incident.threat_actor, 'sector': incident.target_sector})

            # Actor uses MITRE Technique
            if incident.mitre_technique_id:
                execute_write("""
                    MATCH (a:ThreatActor {name: $actor})
                    MERGE (m:MITRETechnique {technique_id: $tid})
                    MERGE (a)-[:USES]->(m)
                """, {'actor': incident.threat_actor, 'tid': incident.mitre_technique_id})

        # --- 4. AttackType node + relationship ---
        if incident.attack_type:
            execute_write("""
                MERGE (t:AttackType {name: $name})
                WITH t
                MATCH (i:Incident {incident_id: $id})
                MERGE (i)-[:HAS_TYPE]->(t)
            """, {'name': incident.attack_type, 'id': incident.id})

        # --- 5. Sector node + relationship ---
        if incident.target_sector:
            execute_write("""
                MERGE (s:Sector {name: $name})
                WITH s
                MATCH (i:Incident {incident_id: $id})
                MERGE (i)-[:TARGETS]->(s)
            """, {'name': incident.target_sector, 'id': incident.id})

        # --- 6. MITRE Technique node + relationship ---
        if incident.mitre_technique_id:
            execute_write("""
                MERGE (m:MITRETechnique {technique_id: $tid})
                WITH m
                MATCH (i:Incident {incident_id: $id})
                MERGE (i)-[:USES]->(m)
            """, {'tid': incident.mitre_technique_id, 'id': incident.id})

        # --- 7. IOC Indicator nodes + relationships ---
        if incident.ioc_indicators:
            _sync_iocs(incident.id, incident.ioc_indicators, incident.threat_actor)

        # --- 8. Mark as synced in SQLite ---
        incident.neo4j_synced = datetime.now(timezone.utc)
        session.commit()

        logger.info(f"Synced incident #{incident.id} to Neo4j")
        return True

    except Exception as e:
        session.rollback()
        logger.error(f"Error syncing incident #{incident_id} to Neo4j: {e}")
        return False
    finally:
        session.close()


def _sync_iocs(incident_id, ioc_json, threat_actor=None):
    """Sync IOC indicators from JSON to Neo4j."""
    try:
        iocs = json.loads(ioc_json)
    except (json.JSONDecodeError, TypeError):
        return

    # IOC type mapping
    ioc_types = {
        'ipv4': 'IPv4',
        'ipv6': 'IPv6',
        'domains': 'Domain',
        'urls': 'URL',
        'md5': 'MD5',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'cve': 'CVE',
        'emails': 'Email',
    }

    for key, ioc_type in ioc_types.items():
        values = iocs.get(key, [])
        for value in values[:20]:  # Limit per type to avoid huge graphs
            # Create IOC node and link to Incident
            execute_write("""
                MERGE (c:IOCIndicator {value: $value})
                SET c.type = $type
                WITH c
                MATCH (i:Incident {incident_id: $id})
                MERGE (i)-[:CONTAINS]->(c)
            """, {'value': value, 'type': ioc_type, 'id': incident_id})

            # Link IOC to ThreatActor if known
            if threat_actor:
                execute_write("""
                    MATCH (c:IOCIndicator {value: $value})
                    MERGE (a:ThreatActor {name: $actor})
                    MERGE (c)-[:LINKED_TO]->(a)
                """, {'value': value, 'actor': threat_actor})


def sync_all_unsynced():
    """
    Sync all incidents that haven't been synced to Neo4j.
    Returns dict with stats.
    """
    if not is_available():
        return {
            'total': 0,
            'synced': 0,
            'status': 'unavailable',
            'message': 'Neo4j is not available',
        }

    session = get_session()
    try:
        unsynced_ids = [
            r[0] for r in
            session.query(Incident.id)
            .filter(Incident.neo4j_synced.is_(None))
            .order_by(Incident.date.desc())
            .all()
        ]
    finally:
        session.close()

    total = len(unsynced_ids)
    synced = 0

    logger.info(f"Found {total} unsynced incidents for Neo4j")

    for inc_id in unsynced_ids:
        try:
            if sync_incident_to_graph(inc_id):
                synced += 1
        except Exception as e:
            logger.error(f"Failed to sync incident #{inc_id}: {e}")

    logger.info(f"Synced {synced} of {total} incidents to Neo4j")
    return {'total': total, 'synced': synced, 'status': 'success'}


def get_graph_overview():
    """
    Get overview stats of the Neo4j graph.
    Returns dict with node/relationship counts.
    """
    from graph_db import execute_query

    if not is_available():
        return None

    try:
        # Node counts
        result = execute_query("""
            MATCH (n)
            WITH labels(n) AS types, count(n) AS cnt
            UNWIND types AS type
            RETURN type, sum(cnt) AS count
            ORDER BY count DESC
        """)
        node_counts = {r['type']: r['count'] for r in result}

        # Relationship counts
        result = execute_query("""
            MATCH ()-[r]->()
            RETURN type(r) AS type, count(r) AS count
            ORDER BY count DESC
        """)
        rel_counts = {r['type']: r['count'] for r in result}

        return {
            'nodes': node_counts,
            'relationships': rel_counts,
            'total_nodes': sum(node_counts.values()),
            'total_relationships': sum(rel_counts.values()),
        }
    except Exception as e:
        logger.error(f"Error getting graph overview: {e}")
        return None
