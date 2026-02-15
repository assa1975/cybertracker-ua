/**
 * Cyber Tracker UA — Graph Visualization (Cytoscape.js)
 * Interactive graph of cyber incidents, threat actors, sectors,
 * attack types, MITRE techniques, and IOC indicators.
 */

// Node colors by type
const NODE_COLORS = {
    Incident: '#005BBB',
    ThreatActor: '#dc3545',
    Sector: '#28a745',
    AttackType: '#fd7e14',
    MITRETechnique: '#6f42c1',
    IOCIndicator: '#6c757d',
    Source: '#0dcaf0',
};

// Node shapes by type
const NODE_SHAPES = {
    Incident: 'ellipse',
    ThreatActor: 'diamond',
    Sector: 'round-rectangle',
    AttackType: 'hexagon',
    MITRETechnique: 'triangle',
    IOCIndicator: 'round-octagon',
    Source: 'star',
};

let cy = null;

// Initialize Cytoscape
function initCytoscape(elements) {
    if (cy) {
        cy.destroy();
    }

    cy = cytoscape({
        container: document.getElementById('cy'),
        elements: elements,
        style: [
            {
                selector: 'node',
                style: {
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'font-size': '9px',
                    'color': '#e0e0e0',
                    'text-outline-width': 1,
                    'text-outline-color': '#111',
                    'background-color': function(ele) {
                        return NODE_COLORS[ele.data('type')] || '#888';
                    },
                    'shape': function(ele) {
                        return NODE_SHAPES[ele.data('type')] || 'ellipse';
                    },
                    'width': function(ele) {
                        const base = 20;
                        const degree = ele.degree() || 0;
                        return Math.min(base + degree * 3, 60);
                    },
                    'height': function(ele) {
                        const base = 20;
                        const degree = ele.degree() || 0;
                        return Math.min(base + degree * 3, 60);
                    },
                    'text-max-width': '80px',
                    'text-wrap': 'ellipsis',
                    'border-width': 1,
                    'border-color': '#333',
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3,
                    'border-color': '#FFD500',
                    'text-outline-color': '#FFD500',
                }
            },
            {
                selector: 'node.highlighted',
                style: {
                    'border-width': 3,
                    'border-color': '#FFD500',
                    'opacity': 1,
                }
            },
            {
                selector: 'node.faded',
                style: {
                    'opacity': 0.15,
                }
            },
            {
                selector: 'node.community',
                style: {
                    'border-width': 3,
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 1,
                    'line-color': '#444',
                    'target-arrow-color': '#555',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                    'opacity': 0.6,
                    'arrow-scale': 0.6,
                }
            },
            {
                selector: 'edge.highlighted',
                style: {
                    'line-color': '#FFD500',
                    'target-arrow-color': '#FFD500',
                    'width': 2,
                    'opacity': 1,
                }
            },
            {
                selector: 'edge.faded',
                style: {
                    'opacity': 0.08,
                }
            },
        ],
        layout: { name: 'cose', animate: false },
        minZoom: 0.1,
        maxZoom: 5,
        wheelSensitivity: 0.3,
    });

    // Node click handler
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        highlightNeighbors(node);
        showNodeDetails(node);
    });

    // Background click — reset highlighting
    cy.on('tap', function(evt) {
        if (evt.target === cy) {
            resetHighlight();
            document.getElementById('node-details-card').style.display = 'none';
        }
    });

    // Update info badge
    const info = document.getElementById('graph-info');
    info.textContent = `${cy.nodes().length} вузлів, ${cy.edges().length} зв'язків`;

    return cy;
}


function highlightNeighbors(node) {
    resetHighlight();

    const neighborhood = node.neighborhood().add(node);

    cy.elements().addClass('faded');
    neighborhood.removeClass('faded');
    neighborhood.addClass('highlighted');
    node.connectedEdges().addClass('highlighted');
}


function resetHighlight() {
    cy.elements().removeClass('faded highlighted');
}


function showNodeDetails(node) {
    const data = node.data();
    const card = document.getElementById('node-details-card');
    const details = document.getElementById('node-details');

    let html = `
        <p class="mb-1"><strong>${data.label || 'N/A'}</strong></p>
        <p class="mb-1"><span class="badge" style="background:${NODE_COLORS[data.type] || '#888'}">${data.type || 'Unknown'}</span></p>
    `;

    if (data.severity) {
        html += `<p class="mb-1"><small>Severity: <strong>${data.severity}</strong></small></p>`;
    }
    if (data.date) {
        html += `<p class="mb-1"><small>Date: ${data.date}</small></p>`;
    }
    if (data.incident_id) {
        html += `<p class="mb-1"><a href="/incidents/${data.incident_id}" class="small" target="_blank">View Incident</a></p>`;
    }
    if (data.technique_id) {
        html += `<p class="mb-1"><a href="https://attack.mitre.org/techniques/${data.technique_id}/" class="small" target="_blank">MITRE ATT&CK</a></p>`;
    }

    // Connected nodes
    const neighbors = node.neighborhood('node');
    if (neighbors.length > 0) {
        html += `<hr class="my-1"><p class="mb-1 small fw-bold">Connected (${neighbors.length}):</p><div style="max-height:150px;overflow-y:auto;">`;
        neighbors.forEach(n => {
            const nData = n.data();
            html += `<span class="badge me-1 mb-1" style="background:${NODE_COLORS[nData.type] || '#888'};font-size:0.65rem">${nData.label}</span>`;
        });
        html += '</div>';
    }

    details.innerHTML = html;
    card.style.display = 'block';
}


function applyLayout(name) {
    if (!cy) return;

    const layouts = {
        cose: { name: 'cose', animate: true, animationDuration: 500, nodeRepulsion: 8000, idealEdgeLength: 80 },
        circle: { name: 'circle', animate: true, animationDuration: 500 },
        grid: { name: 'grid', animate: true, animationDuration: 500 },
        breadthfirst: { name: 'breadthfirst', animate: true, animationDuration: 500, directed: true },
        concentric: {
            name: 'concentric', animate: true, animationDuration: 500,
            concentric: function(node) { return node.degree(); },
            levelWidth: function() { return 3; },
        },
    };

    const layout = cy.layout(layouts[name] || layouts.cose);
    layout.run();
}


function filterByTypes() {
    if (!cy) return;

    const checked = [];
    document.querySelectorAll('.type-filter:checked').forEach(cb => {
        checked.push(cb.value);
    });

    cy.nodes().forEach(node => {
        if (checked.includes(node.data('type'))) {
            node.show();
        } else {
            node.hide();
        }
    });
}


function searchNodes(query) {
    if (!cy || !query) {
        resetHighlight();
        return;
    }

    const lowerQuery = query.toLowerCase();
    const matching = cy.nodes().filter(n =>
        (n.data('label') || '').toLowerCase().includes(lowerQuery)
    );

    if (matching.length > 0) {
        cy.elements().addClass('faded');
        matching.forEach(node => {
            const neighborhood = node.neighborhood().add(node);
            neighborhood.removeClass('faded');
        });
        matching.addClass('highlighted');

        // Fit view to matching nodes
        if (matching.length <= 10) {
            cy.fit(matching, 50);
        }
    }
}


// Community coloring
const COMMUNITY_COLORS = [
    '#e6194b', '#3cb44b', '#ffe119', '#4363d8', '#f58231',
    '#911eb4', '#42d4f4', '#f032e6', '#bfef45', '#fabed4',
    '#469990', '#dcbeff', '#9A6324', '#fffac8', '#800000',
    '#aaffc3', '#808000', '#ffd8b1', '#000075', '#a9a9a9',
];


async function loadCommunities() {
    try {
        const resp = await fetch('/api/graph/communities');
        const data = await resp.json();

        if (!data || data.error) {
            alert(data.message || 'Communities not available');
            return;
        }

        // Apply community colors
        cy.nodes().removeClass('community');
        for (const [commId, members] of Object.entries(data)) {
            const color = COMMUNITY_COLORS[parseInt(commId) % COMMUNITY_COLORS.length];
            members.forEach(m => {
                const node = cy.getElementById(m.node_id);
                if (node && node.length > 0) {
                    node.style('border-color', color);
                    node.addClass('community');
                }
            });
        }
    } catch (e) {
        console.error('Error loading communities:', e);
    }
}


async function loadGraph() {
    const limit = document.getElementById('node-limit').value || 300;
    const info = document.getElementById('graph-info');
    info.textContent = 'Завантаження...';

    try {
        const resp = await fetch(`/api/graph/data?limit=${limit}`);
        const data = await resp.json();

        if (data.error) {
            info.textContent = data.message || 'Error';
            return;
        }

        const elements = data.elements || { nodes: [], edges: [] };
        initCytoscape(elements);

        // Load stats
        loadStats();

    } catch (e) {
        console.error('Error loading graph:', e);
        info.textContent = 'Помилка завантаження';
    }
}


async function syncGraph() {
    const btn = document.getElementById('btn-sync');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Sync...';

    try {
        const resp = await fetch('/api/graph/sync', { method: 'POST' });
        const data = await resp.json();
        alert(`Synced: ${data.synced || 0} of ${data.total || 0} incidents`);
        loadGraph(); // Reload
    } catch (e) {
        console.error('Sync error:', e);
        alert('Sync failed');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Синхронізація';
    }
}


async function checkStatus() {
    const statusEl = document.getElementById('neo4j-status');
    try {
        const resp = await fetch('/api/graph/status');
        const data = await resp.json();
        if (data.available) {
            statusEl.innerHTML = '<span class="text-success"><i class="bi bi-check-circle-fill"></i> Connected</span>';
        } else {
            statusEl.innerHTML = '<span class="text-warning"><i class="bi bi-exclamation-triangle"></i> Not available</span><br><small class="text-muted">Set NEO4J_PASSWORD in .env</small>';
        }
    } catch (e) {
        statusEl.innerHTML = '<span class="text-danger"><i class="bi bi-x-circle"></i> Error</span>';
    }
}


async function loadStats() {
    try {
        const resp = await fetch('/api/graph/stats');
        const data = await resp.json();

        if (!data || data.error) return;

        const card = document.getElementById('graph-stats-card');
        const el = document.getElementById('graph-stats');

        let html = '';
        if (data.node_counts) {
            html += '<p class="mb-1 small fw-bold">Nodes:</p>';
            for (const [type, count] of Object.entries(data.node_counts)) {
                html += `<span class="badge me-1 mb-1" style="background:${NODE_COLORS[type] || '#888'}">${type}: ${count}</span>`;
            }
        }
        if (data.relationship_counts) {
            html += '<p class="mb-1 mt-2 small fw-bold">Relationships:</p>';
            for (const [type, count] of Object.entries(data.relationship_counts)) {
                html += `<span class="badge bg-secondary me-1 mb-1">${type}: ${count}</span>`;
            }
        }

        el.innerHTML = html;
        card.style.display = 'block';
    } catch (e) {
        console.error('Stats error:', e);
    }
}


// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    checkStatus();

    document.getElementById('btn-load').addEventListener('click', loadGraph);
    document.getElementById('btn-sync').addEventListener('click', syncGraph);
    document.getElementById('btn-communities').addEventListener('click', loadCommunities);
    document.getElementById('btn-fit').addEventListener('click', () => {
        if (cy) cy.fit(undefined, 30);
    });

    document.getElementById('layout-select').addEventListener('change', function() {
        applyLayout(this.value);
    });

    document.querySelectorAll('.type-filter').forEach(cb => {
        cb.addEventListener('change', filterByTypes);
    });

    let searchTimeout;
    document.getElementById('node-search').addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const q = this.value.trim();
        searchTimeout = setTimeout(() => {
            if (q.length >= 2) {
                searchNodes(q);
            } else {
                resetHighlight();
            }
        }, 300);
    });
});
