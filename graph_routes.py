"""
Graph API Blueprint.
Provides REST API endpoints for the graph visualization and analysis.
"""

import logging
from flask import Blueprint, jsonify, request

from graph_db import is_available, execute_query
from graph_sync import sync_all_unsynced, get_graph_overview
from graph_analysis import (
    build_networkx_graph, compute_centrality,
    detect_communities, find_shortest_path,
    get_actor_profile, get_graph_stats,
)

logger = logging.getLogger(__name__)

graph_bp = Blueprint('graph', __name__)


@graph_bp.route('/api/graph/status')
def graph_status():
    """Check Neo4j availability."""
    available = is_available()
    return jsonify({
        'available': available,
        'message': 'Connected' if available else 'Neo4j is not available',
    })


@graph_bp.route('/api/graph/stats')
def graph_stats():
    """Get graph statistics."""
    if not is_available():
        return jsonify({'error': True, 'message': 'Neo4j is not available'})

    stats = get_graph_stats()
    if stats is None:
        return jsonify({'error': True, 'message': 'Failed to get stats'})

    return jsonify(stats)


@graph_bp.route('/api/graph/data')
def graph_data():
    """
    Get graph data in Cytoscape.js format.
    Query params: actor, sector, attack_type, limit (default 500)
    """
    if not is_available():
        return jsonify({
            'error': True,
            'message': 'Neo4j is not available. Set NEO4J_PASSWORD in .env',
            'elements': {'nodes': [], 'edges': []},
        })

    limit = request.args.get('limit', 500, type=int)
    limit = min(limit, 2000)

    actor = request.args.get('actor', '').strip()
    sector = request.args.get('sector', '').strip()
    attack_type = request.args.get('attack_type', '').strip()

    try:
        # Build Cypher query based on filters
        if actor:
            nodes_query = """
                MATCH (a:ThreatActor {name: $filter})-[*0..2]-(n)
                WITH DISTINCT n LIMIT $limit
                RETURN id(n) AS id, labels(n) AS types,
                       n.name AS name, n.title AS title,
                       n.incident_id AS incident_id,
                       n.technique_id AS technique_id,
                       n.value AS value, n.type AS ioc_type,
                       n.severity AS severity, n.date AS date
            """
            params = {'filter': actor, 'limit': limit}
        elif sector:
            nodes_query = """
                MATCH (s:Sector {name: $filter})-[*0..2]-(n)
                WITH DISTINCT n LIMIT $limit
                RETURN id(n) AS id, labels(n) AS types,
                       n.name AS name, n.title AS title,
                       n.incident_id AS incident_id,
                       n.technique_id AS technique_id,
                       n.value AS value, n.type AS ioc_type,
                       n.severity AS severity, n.date AS date
            """
            params = {'filter': sector, 'limit': limit}
        elif attack_type:
            nodes_query = """
                MATCH (t:AttackType {name: $filter})-[*0..2]-(n)
                WITH DISTINCT n LIMIT $limit
                RETURN id(n) AS id, labels(n) AS types,
                       n.name AS name, n.title AS title,
                       n.incident_id AS incident_id,
                       n.technique_id AS technique_id,
                       n.value AS value, n.type AS ioc_type,
                       n.severity AS severity, n.date AS date
            """
            params = {'filter': attack_type, 'limit': limit}
        else:
            nodes_query = """
                MATCH (n)
                RETURN id(n) AS id, labels(n) AS types,
                       n.name AS name, n.title AS title,
                       n.incident_id AS incident_id,
                       n.technique_id AS technique_id,
                       n.value AS value, n.type AS ioc_type,
                       n.severity AS severity, n.date AS date
                LIMIT $limit
            """
            params = {'limit': limit}

        nodes = execute_query(nodes_query, params)

        # Get edges between retrieved nodes
        node_ids = [n['id'] for n in nodes]
        edges = []
        if node_ids:
            edges = execute_query("""
                MATCH (a)-[r]->(b)
                WHERE id(a) IN $ids AND id(b) IN $ids
                RETURN id(a) AS source, id(b) AS target, type(r) AS rel_type, id(r) AS id
            """, {'ids': node_ids})

        # Convert to Cytoscape.js format
        cy_nodes = []
        for n in nodes:
            node_type = n['types'][0] if n.get('types') else 'Unknown'
            label = (
                n.get('name') or
                n.get('title') or
                n.get('technique_id') or
                n.get('value') or
                str(n.get('incident_id', ''))
            )
            # Truncate long labels
            if label and len(label) > 40:
                label = label[:37] + '...'

            cy_nodes.append({
                'data': {
                    'id': str(n['id']),
                    'label': label or str(n['id']),
                    'type': node_type,
                    'incident_id': n.get('incident_id'),
                    'technique_id': n.get('technique_id'),
                    'value': n.get('value'),
                    'ioc_type': n.get('ioc_type'),
                    'severity': n.get('severity'),
                    'date': str(n.get('date', '')),
                }
            })

        cy_edges = []
        for e in edges:
            cy_edges.append({
                'data': {
                    'id': f"e{e['id']}",
                    'source': str(e['source']),
                    'target': str(e['target']),
                    'rel_type': e['rel_type'],
                }
            })

        return jsonify({
            'elements': {
                'nodes': cy_nodes,
                'edges': cy_edges,
            }
        })

    except Exception as e:
        logger.error(f"Error building graph data: {e}")
        return jsonify({
            'error': True,
            'message': str(e),
            'elements': {'nodes': [], 'edges': []},
        })


@graph_bp.route('/api/graph/centrality')
def graph_centrality():
    """
    Compute centrality metrics.
    Query param: metric (degree, betweenness, closeness, pagerank)
    """
    if not is_available():
        return jsonify({'error': True, 'message': 'Neo4j is not available'})

    metric = request.args.get('metric', 'degree')
    limit = request.args.get('limit', 50, type=int)

    try:
        G = build_networkx_graph()
        result = compute_centrality(G, metric)

        # Return top N
        top = dict(list(result.items())[:limit])
        return jsonify(top)
    except Exception as e:
        logger.error(f"Centrality error: {e}")
        return jsonify({'error': True, 'message': str(e)})


@graph_bp.route('/api/graph/communities')
def graph_communities():
    """Detect communities in the graph."""
    if not is_available():
        return jsonify({'error': True, 'message': 'Neo4j is not available'})

    try:
        G = build_networkx_graph()
        communities = detect_communities(G)
        return jsonify(communities)
    except Exception as e:
        logger.error(f"Community detection error: {e}")
        return jsonify({'error': True, 'message': str(e)})


@graph_bp.route('/api/graph/actor/<name>')
def graph_actor(name):
    """Get threat actor profile."""
    if not is_available():
        return jsonify({'error': True, 'message': 'Neo4j is not available'})

    profile = get_actor_profile(name)
    if profile is None:
        return jsonify({'error': True, 'message': 'Actor not found'})

    return jsonify(profile)


@graph_bp.route('/api/graph/path')
def graph_path():
    """
    Find shortest path between two nodes.
    Query params: source, target (node labels)
    """
    if not is_available():
        return jsonify({'error': True, 'message': 'Neo4j is not available'})

    source = request.args.get('source', '').strip()
    target = request.args.get('target', '').strip()

    if not source or not target:
        return jsonify({'error': True, 'message': 'source and target required'})

    try:
        G = build_networkx_graph()
        path = find_shortest_path(G, source, target)
        if path is None:
            return jsonify({'error': True, 'message': 'No path found'})
        return jsonify({'path': path})
    except Exception as e:
        logger.error(f"Path error: {e}")
        return jsonify({'error': True, 'message': str(e)})


@graph_bp.route('/api/graph/sync', methods=['POST'])
def graph_sync():
    """Trigger Neo4j sync."""
    result = sync_all_unsynced()
    return jsonify(result)
