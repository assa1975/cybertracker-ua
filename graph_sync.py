"""
Graph Sync Module.
Synchronizes ALL data types from SQLite to Neo4j graph database:
- Incidents (with Source, ThreatActor, AttackType, Sector, MITRETechnique, IOCIndicator)
- ThreatPersons (with Organization links)
- ThreatOrganizations
- Uploaded Documents (with IOCs, actors, attacks, sectors, MITRE techniques)
- IOC Feed indicators
"""

import json
import logging
from datetime import datetime, timezone

from models import Incident, ThreatPerson, ThreatOrganization, UploadedDocument, IOCIndicator
from database import get_session
from graph_db import execute_write, is_available

logger = logging.getLogger(__name__)


# ==================== Incident Sync ====================

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


# ==================== Person Sync ====================

def sync_person_to_graph(person_id):
    """Sync a ThreatPerson to Neo4j with organization relationships."""
    if not is_available():
        return False

    session = get_session()
    try:
        person = session.query(ThreatPerson).get(person_id)
        if not person:
            return False

        # Create Person node
        execute_write("""
            MERGE (p:Person {name: $name})
            SET p.aliases = $aliases,
                p.role = $role,
                p.country = $country,
                p.status = $status,
                p.description = $description,
                p.photo_url = $photo_url,
                p.updated_at = datetime()
        """, {
            'name': person.name,
            'aliases': person.aliases or '',
            'role': person.role or '',
            'country': person.country or '',
            'status': person.status or '',
            'description': (person.description or '')[:500],
            'photo_url': person.photo_url or '',
        })

        # Link to Organization
        if person.organization:
            for org_name in person.organization.split(','):
                org_name = org_name.strip()
                if org_name:
                    execute_write("""
                        MATCH (p:Person {name: $person})
                        MERGE (o:Organization {name: $org})
                        MERGE (p)-[:MEMBER_OF]->(o)
                    """, {'person': person.name, 'org': org_name})

                    # Also link Organization to ThreatActor if matching
                    execute_write("""
                        MATCH (o:Organization {name: $org})
                        OPTIONAL MATCH (a:ThreatActor)
                        WHERE a.name CONTAINS $org OR $org CONTAINS a.name
                        FOREACH (_ IN CASE WHEN a IS NOT NULL THEN [1] ELSE [] END |
                            MERGE (o)-[:ASSOCIATED_WITH]->(a)
                        )
                    """, {'org': org_name})

        # Link person to known operations
        if person.operations:
            try:
                ops = json.loads(person.operations)
                for op in ops[:10]:
                    if isinstance(op, str) and len(op) > 3:
                        execute_write("""
                            MATCH (p:Person {name: $person})
                            MERGE (op:Operation {name: $op_name})
                            MERGE (p)-[:PARTICIPATED_IN]->(op)
                        """, {'person': person.name, 'op_name': op[:200]})
            except (json.JSONDecodeError, TypeError):
                pass

        # Link person to threat actor by alias matching
        if person.aliases:
            execute_write("""
                MATCH (p:Person {name: $name})
                OPTIONAL MATCH (a:ThreatActor)
                WHERE a.name CONTAINS $alias_part
                FOREACH (_ IN CASE WHEN a IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (p)-[:KNOWN_AS]->(a)
                )
            """, {'name': person.name, 'alias_part': person.name.split()[-1] if person.name else ''})

        logger.info(f"Synced person '{person.name}' to Neo4j")
        return True

    except Exception as e:
        logger.error(f"Error syncing person #{person_id} to Neo4j: {e}")
        return False
    finally:
        session.close()


# ==================== Organization Sync ====================

def sync_organization_to_graph(org_id):
    """Sync a ThreatOrganization to Neo4j."""
    if not is_available():
        return False

    session = get_session()
    try:
        org = session.query(ThreatOrganization).get(org_id)
        if not org:
            return False

        # Create Organization node
        execute_write("""
            MERGE (o:Organization {name: $name})
            SET o.org_type = $org_type,
                o.aliases = $aliases,
                o.country = $country,
                o.description = $description,
                o.members_count = $members_count,
                o.updated_at = datetime()
        """, {
            'name': org.name,
            'org_type': org.org_type or '',
            'aliases': org.aliases or '',
            'country': org.country or '',
            'description': (org.description or '')[:500],
            'members_count': org.members_count or 0,
        })

        # Link to parent organization
        if org.parent_org:
            execute_write("""
                MATCH (o:Organization {name: $name})
                MERGE (p:Organization {name: $parent})
                MERGE (o)-[:SUBORDINATE_TO]->(p)
            """, {'name': org.name, 'parent': org.parent_org})

        # Link to matching ThreatActor
        execute_write("""
            MATCH (o:Organization {name: $name})
            OPTIONAL MATCH (a:ThreatActor)
            WHERE a.name CONTAINS $name OR $name CONTAINS a.name
            FOREACH (_ IN CASE WHEN a IS NOT NULL THEN [1] ELSE [] END |
                MERGE (o)-[:ASSOCIATED_WITH]->(a)
            )
        """, {'name': org.name})

        # Also try aliases matching
        if org.aliases:
            for alias in org.aliases.split(','):
                alias = alias.strip()
                if alias and len(alias) > 2:
                    execute_write("""
                        MATCH (o:Organization {name: $name})
                        OPTIONAL MATCH (a:ThreatActor)
                        WHERE a.name CONTAINS $alias OR $alias CONTAINS a.name
                        FOREACH (_ IN CASE WHEN a IS NOT NULL THEN [1] ELSE [] END |
                            MERGE (o)-[:ASSOCIATED_WITH]->(a)
                        )
                    """, {'name': org.name, 'alias': alias})

        # Link known operations
        if org.known_operations:
            try:
                ops = json.loads(org.known_operations)
                for op in ops[:10]:
                    if isinstance(op, str) and len(op) > 3:
                        execute_write("""
                            MATCH (o:Organization {name: $name})
                            MERGE (op:Operation {name: $op_name})
                            MERGE (o)-[:CONDUCTED]->(op)
                        """, {'name': org.name, 'op_name': op[:200]})
            except (json.JSONDecodeError, TypeError):
                pass

        # Link to country
        if org.country:
            execute_write("""
                MATCH (o:Organization {name: $name})
                MERGE (c:Country {name: $country})
                MERGE (o)-[:BASED_IN]->(c)
            """, {'name': org.name, 'country': org.country})

        logger.info(f"Synced organization '{org.name}' to Neo4j")
        return True

    except Exception as e:
        logger.error(f"Error syncing organization #{org_id} to Neo4j: {e}")
        return False
    finally:
        session.close()


# ==================== Document Sync ====================

def sync_document_to_graph(doc_id):
    """
    Sync an uploaded document and its analysis results to Neo4j.
    Creates Document node + links to IOCs, Actors, Sectors, AttackTypes, MITRE.
    """
    if not is_available():
        return False

    session = get_session()
    try:
        doc = session.query(UploadedDocument).get(doc_id)
        if not doc:
            return False

        # --- 1. Create Document node ---
        execute_write("""
            MERGE (d:Document {doc_id: $id})
            SET d.name = $name,
                d.title = $title,
                d.doc_type = $doc_type,
                d.page_count = $pages,
                d.ioc_count = $ioc_count,
                d.language = $language,
                d.summary = $summary,
                d.updated_at = datetime()
        """, {
            'id': doc.id,
            'name': doc.original_name or '',
            'title': (doc.title or doc.original_name or '')[:200],
            'doc_type': doc.doc_type or 'pdf',
            'pages': doc.page_count or 0,
            'ioc_count': doc.ioc_count or 0,
            'language': doc.language or '',
            'summary': (doc.summary or '')[:500],
        })

        # --- 2. Link to Threat Actors ---
        if doc.threat_actors:
            for actor in doc.threat_actors.split(','):
                actor = actor.strip()
                if actor:
                    execute_write("""
                        MATCH (d:Document {doc_id: $doc_id})
                        MERGE (a:ThreatActor {name: $actor})
                        MERGE (d)-[:MENTIONS]->(a)
                    """, {'doc_id': doc.id, 'actor': actor})

        # --- 3. Link to Attack Types ---
        if doc.attack_types:
            for at in doc.attack_types.split(','):
                at = at.strip()
                if at:
                    execute_write("""
                        MATCH (d:Document {doc_id: $doc_id})
                        MERGE (t:AttackType {name: $type})
                        MERGE (d)-[:DESCRIBES]->(t)
                    """, {'doc_id': doc.id, 'type': at})

        # --- 4. Link to Sectors ---
        if doc.target_sectors:
            for sector in doc.target_sectors.split(','):
                sector = sector.strip()
                if sector:
                    execute_write("""
                        MATCH (d:Document {doc_id: $doc_id})
                        MERGE (s:Sector {name: $sector})
                        MERGE (d)-[:REFERENCES]->(s)
                    """, {'doc_id': doc.id, 'sector': sector})

        # --- 5. Link to MITRE Techniques ---
        if doc.mitre_techniques:
            for tid in doc.mitre_techniques.split(','):
                tid = tid.strip()
                if tid:
                    execute_write("""
                        MATCH (d:Document {doc_id: $doc_id})
                        MERGE (m:MITRETechnique {technique_id: $tid})
                        MERGE (d)-[:REFERENCES]->(m)
                    """, {'doc_id': doc.id, 'tid': tid})

        # --- 6. Link to IOC indicators from document ---
        if doc.ioc_data:
            try:
                iocs = json.loads(doc.ioc_data)
                ioc_type_map = {
                    'ipv4': 'IPv4', 'ipv6': 'IPv6', 'domains': 'Domain',
                    'urls': 'URL', 'md5': 'MD5', 'sha1': 'SHA1',
                    'sha256': 'SHA256', 'cve': 'CVE', 'emails': 'Email',
                }
                for key, ioc_type in ioc_type_map.items():
                    values = iocs.get(key, [])
                    for value in values[:30]:  # Limit per type
                        execute_write("""
                            MATCH (d:Document {doc_id: $doc_id})
                            MERGE (c:IOCIndicator {value: $value})
                            SET c.type = $type
                            MERGE (d)-[:CONTAINS]->(c)
                        """, {'doc_id': doc.id, 'value': value, 'type': ioc_type})

                        # Cross-link IOC with actors mentioned in the same document
                        if doc.threat_actors:
                            for actor in doc.threat_actors.split(',')[:5]:
                                actor = actor.strip()
                                if actor:
                                    execute_write("""
                                        MATCH (c:IOCIndicator {value: $value})
                                        MERGE (a:ThreatActor {name: $actor})
                                        MERGE (c)-[:LINKED_TO]->(a)
                                    """, {'value': value, 'actor': actor})
            except (json.JSONDecodeError, TypeError):
                pass

        # --- 7. Mark as synced ---
        doc.neo4j_synced = datetime.now(timezone.utc)
        session.commit()

        logger.info(f"Synced document #{doc.id} '{doc.original_name}' to Neo4j")
        return True

    except Exception as e:
        session.rollback()
        logger.error(f"Error syncing document #{doc_id} to Neo4j: {e}")
        return False
    finally:
        session.close()


# ==================== IOC Feed Sync ====================

def sync_ioc_feeds_to_graph(limit=500):
    """Sync IOC indicators from feeds to Neo4j."""
    if not is_available():
        return 0

    session = get_session()
    try:
        # Get high-confidence IOCs not yet in Neo4j (by threat_level)
        iocs = (
            session.query(IOCIndicator)
            .filter(IOCIndicator.threat_level.in_(['critical', 'high']))
            .order_by(IOCIndicator.last_seen.desc())
            .limit(limit)
            .all()
        )

        synced = 0
        for ioc in iocs:
            try:
                # Create or update IOC node
                execute_write("""
                    MERGE (c:IOCIndicator {value: $value})
                    SET c.type = $type,
                        c.source = $source,
                        c.threat_level = $threat_level,
                        c.confidence = $confidence,
                        c.tags = $tags
                """, {
                    'value': ioc.value,
                    'type': ioc.ioc_type or '',
                    'source': ioc.source or '',
                    'threat_level': ioc.threat_level or '',
                    'confidence': ioc.confidence or 0,
                    'tags': (ioc.tags or '')[:200],
                })

                # Link IOC to its feed source
                if ioc.source:
                    execute_write("""
                        MATCH (c:IOCIndicator {value: $value})
                        MERGE (s:Source {name: $source})
                        MERGE (c)-[:FROM]->(s)
                    """, {'value': ioc.value, 'source': ioc.source})

                synced += 1
            except Exception as e:
                logger.warning(f"Failed to sync IOC {ioc.value}: {e}")

        logger.info(f"Synced {synced} IOC feed indicators to Neo4j")
        return synced

    except Exception as e:
        logger.error(f"Error syncing IOC feeds to Neo4j: {e}")
        return 0
    finally:
        session.close()


# ==================== Sync All ====================

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


def sync_all_to_graph():
    """
    Sync ALL data types to Neo4j:
    - Unsynced incidents
    - All persons
    - All organizations
    - Unsynced documents
    - High-confidence IOC feed indicators
    Returns dict with stats for each type.
    """
    if not is_available():
        return {
            'status': 'unavailable',
            'message': 'Neo4j is not available',
        }

    result = {
        'status': 'success',
        'incidents_synced': 0,
        'persons_synced': 0,
        'orgs_synced': 0,
        'documents_synced': 0,
        'ioc_feeds_synced': 0,
    }

    session = get_session()

    # 1. Sync unsynced incidents
    try:
        unsynced_inc = [
            r[0] for r in
            session.query(Incident.id)
            .filter(Incident.neo4j_synced.is_(None))
            .order_by(Incident.date.desc())
            .all()
        ]
        for inc_id in unsynced_inc:
            try:
                if sync_incident_to_graph(inc_id):
                    result['incidents_synced'] += 1
            except Exception as e:
                logger.error(f"Failed to sync incident #{inc_id}: {e}")
    except Exception as e:
        logger.error(f"Incident sync query failed: {e}")

    # 2. Sync all persons
    try:
        person_ids = [r[0] for r in session.query(ThreatPerson.id).all()]
        for pid in person_ids:
            try:
                if sync_person_to_graph(pid):
                    result['persons_synced'] += 1
            except Exception as e:
                logger.error(f"Failed to sync person #{pid}: {e}")
    except Exception as e:
        logger.error(f"Person sync query failed: {e}")

    # 3. Sync all organizations
    try:
        org_ids = [r[0] for r in session.query(ThreatOrganization.id).all()]
        for oid in org_ids:
            try:
                if sync_organization_to_graph(oid):
                    result['orgs_synced'] += 1
            except Exception as e:
                logger.error(f"Failed to sync org #{oid}: {e}")
    except Exception as e:
        logger.error(f"Org sync query failed: {e}")

    # 4. Sync unsynced documents
    try:
        unsynced_docs = [
            r[0] for r in
            session.query(UploadedDocument.id)
            .filter(UploadedDocument.neo4j_synced.is_(None))
            .all()
        ]
        for doc_id in unsynced_docs:
            try:
                if sync_document_to_graph(doc_id):
                    result['documents_synced'] += 1
            except Exception as e:
                logger.error(f"Failed to sync document #{doc_id}: {e}")
    except Exception as e:
        logger.error(f"Document sync query failed: {e}")

    # 5. Sync IOC feed indicators (high-confidence)
    try:
        result['ioc_feeds_synced'] = sync_ioc_feeds_to_graph(limit=300)
    except Exception as e:
        logger.error(f"IOC feed sync failed: {e}")

    session.close()

    logger.info(
        f"Full sync complete: {result['incidents_synced']} incidents, "
        f"{result['persons_synced']} persons, {result['orgs_synced']} orgs, "
        f"{result['documents_synced']} documents, {result['ioc_feeds_synced']} IOC feeds"
    )
    return result


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
