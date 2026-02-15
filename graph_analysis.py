"""
Graph Analysis Module using NetworkX.
Builds an in-memory graph from Neo4j data and provides
centrality metrics, community detection, pathfinding, and actor profiling.
"""

import logging
from collections import defaultdict

import networkx as nx

from graph_db import execute_query, is_available

logger = logging.getLogger(__name__)


def build_networkx_graph():
    """
    Build a NetworkX graph from Neo4j data.
    Returns nx.Graph or None if Neo4j is unavailable.
    """
    if not is_available():
        return None

    G = nx.Graph()

    # Fetch all nodes
    nodes = execute_query("""
        MATCH (n)
        RETURN id(n) AS neo_id, labels(n) AS types,
               n.name AS name, n.title AS title,
               n.incident_id AS incident_id,
               n.technique_id AS technique_id,
               n.value AS value, n.type AS ioc_type,
               n.severity AS severity, n.date AS date
    """)

    for node in nodes:
        node_type = node['types'][0] if node['types'] else 'Unknown'
        label = (
            node.get('name') or
            node.get('title') or
            node.get('technique_id') or
            node.get('value') or
            str(node.get('incident_id', ''))
        )
        G.add_node(node['neo_id'], **{
            'type': node_type,
            'label': label or str(node['neo_id']),
            'incident_id': node.get('incident_id'),
            'technique_id': node.get('technique_id'),
            'value': node.get('value'),
            'ioc_type': node.get('ioc_type'),
            'severity': node.get('severity'),
            'date': node.get('date'),
        })

    # Fetch all relationships
    rels = execute_query("""
        MATCH (a)-[r]->(b)
        RETURN id(a) AS source, id(b) AS target, type(r) AS rel_type
    """)

    for rel in rels:
        G.add_edge(rel['source'], rel['target'], rel_type=rel['rel_type'])

    logger.info(f"Built NetworkX graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def compute_centrality(G=None, metric='degree'):
    """
    Compute centrality for all nodes.
    Metrics: degree, betweenness, closeness, eigenvector, pagerank
    Returns dict of {node_id: {'label': str, 'type': str, 'score': float}}
    """
    if G is None:
        G = build_networkx_graph()
    if G is None or G.number_of_nodes() == 0:
        return {}

    if metric == 'degree':
        scores = nx.degree_centrality(G)
    elif metric == 'betweenness':
        scores = nx.betweenness_centrality(G, k=min(100, G.number_of_nodes()))
    elif metric == 'closeness':
        scores = nx.closeness_centrality(G)
    elif metric == 'eigenvector':
        try:
            scores = nx.eigenvector_centrality(G, max_iter=200)
        except nx.PowerIterationFailedConvergence:
            scores = nx.eigenvector_centrality_numpy(G)
    elif metric == 'pagerank':
        scores = nx.pagerank(G)
    else:
        scores = nx.degree_centrality(G)

    # Combine with node data
    result = {}
    for node_id, score in sorted(scores.items(), key=lambda x: -x[1]):
        data = G.nodes[node_id]
        result[str(node_id)] = {
            'label': data.get('label', ''),
            'type': data.get('type', 'Unknown'),
            'score': round(score, 6),
        }

    return result


def detect_communities(G=None):
    """
    Detect communities using Louvain method.
    Returns dict of {community_id: [{'node_id': str, 'label': str, 'type': str}]}
    """
    if G is None:
        G = build_networkx_graph()
    if G is None or G.number_of_nodes() == 0:
        return {}

    try:
        from networkx.algorithms.community import louvain_communities
        communities = louvain_communities(G, seed=42)
    except ImportError:
        # Fallback to greedy modularity
        from networkx.algorithms.community import greedy_modularity_communities
        communities = greedy_modularity_communities(G)

    result = {}
    for i, community in enumerate(communities):
        members = []
        for node_id in community:
            data = G.nodes[node_id]
            members.append({
                'node_id': str(node_id),
                'label': data.get('label', ''),
                'type': data.get('type', 'Unknown'),
            })
        result[str(i)] = sorted(members, key=lambda x: x['label'])

    return result


def find_shortest_path(G=None, source_label=None, target_label=None):
    """
    Find shortest path between two nodes (by label).
    Returns list of node dicts forming the path, or None.
    """
    if G is None:
        G = build_networkx_graph()
    if G is None or not source_label or not target_label:
        return None

    # Find nodes by label
    source_id = None
    target_id = None
    for n, data in G.nodes(data=True):
        if data.get('label', '').lower() == source_label.lower():
            source_id = n
        if data.get('label', '').lower() == target_label.lower():
            target_id = n

    if source_id is None or target_id is None:
        return None

    try:
        path = nx.shortest_path(G, source=source_id, target=target_id)
        return [
            {
                'node_id': str(n),
                'label': G.nodes[n].get('label', ''),
                'type': G.nodes[n].get('type', 'Unknown'),
            }
            for n in path
        ]
    except nx.NetworkXNoPath:
        return None
    except Exception as e:
        logger.error(f"Path finding error: {e}")
        return None


def get_actor_profile(actor_name):
    """
    Get detailed profile of a threat actor from the graph.
    Returns dict with incidents, techniques, sectors, IOCs.
    """
    if not is_available():
        return None

    profile = {
        'name': actor_name,
        'incidents': [],
        'techniques': [],
        'sectors': [],
        'attack_types': [],
        'iocs': [],
    }

    # Incidents
    result = execute_query("""
        MATCH (a:ThreatActor {name: $name})-[:ATTRIBUTED_TO]->(i:Incident)
        RETURN i.incident_id AS id, i.title AS title, i.date AS date, i.severity AS severity
        ORDER BY i.date DESC
    """, {'name': actor_name})
    profile['incidents'] = [dict(r) for r in result]

    # Techniques
    result = execute_query("""
        MATCH (a:ThreatActor {name: $name})-[:USES]->(m:MITRETechnique)
        RETURN m.technique_id AS technique_id
    """, {'name': actor_name})
    profile['techniques'] = [r['technique_id'] for r in result]

    # Sectors
    result = execute_query("""
        MATCH (a:ThreatActor {name: $name})-[:TARGETS]->(s:Sector)
        RETURN s.name AS sector
    """, {'name': actor_name})
    profile['sectors'] = [r['sector'] for r in result]

    # Attack types (via incidents)
    result = execute_query("""
        MATCH (a:ThreatActor {name: $name})-[:ATTRIBUTED_TO]->(i:Incident)-[:HAS_TYPE]->(t:AttackType)
        RETURN DISTINCT t.name AS attack_type
    """, {'name': actor_name})
    profile['attack_types'] = [r['attack_type'] for r in result]

    # IOCs
    result = execute_query("""
        MATCH (c:IOCIndicator)-[:LINKED_TO]->(a:ThreatActor {name: $name})
        RETURN c.value AS value, c.type AS type
        LIMIT 50
    """, {'name': actor_name})
    profile['iocs'] = [dict(r) for r in result]

    return profile


def get_graph_stats():
    """
    Get comprehensive graph statistics.
    Returns dict with counts and top entities.
    """
    if not is_available():
        return None

    stats = {}

    # Node counts by type
    result = execute_query("""
        MATCH (n)
        WITH labels(n) AS types
        UNWIND types AS type
        RETURN type, count(*) AS count
        ORDER BY count DESC
    """)
    stats['node_counts'] = {r['type']: r['count'] for r in result}

    # Relationship counts
    result = execute_query("""
        MATCH ()-[r]->()
        RETURN type(r) AS type, count(*) AS count
        ORDER BY count DESC
    """)
    stats['relationship_counts'] = {r['type']: r['count'] for r in result}

    # Top threat actors (by incident count)
    result = execute_query("""
        MATCH (a:ThreatActor)-[:ATTRIBUTED_TO]->(i:Incident)
        RETURN a.name AS actor, count(i) AS incident_count
        ORDER BY incident_count DESC
        LIMIT 10
    """)
    stats['top_actors'] = [dict(r) for r in result]

    # Top attack types
    result = execute_query("""
        MATCH (i:Incident)-[:HAS_TYPE]->(t:AttackType)
        RETURN t.name AS attack_type, count(i) AS count
        ORDER BY count DESC
        LIMIT 10
    """)
    stats['top_attack_types'] = [dict(r) for r in result]

    # Top sectors targeted
    result = execute_query("""
        MATCH (i:Incident)-[:TARGETS]->(s:Sector)
        RETURN s.name AS sector, count(i) AS count
        ORDER BY count DESC
        LIMIT 10
    """)
    stats['top_sectors'] = [dict(r) for r in result]

    return stats
