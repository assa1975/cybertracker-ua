document.addEventListener('DOMContentLoaded', function() {
    var chartColors = [
        '#005BBB', '#FFD500', '#dc3545', '#28a745', '#fd7e14',
        '#6f42c1', '#20c997', '#0dcaf0', '#d63384', '#6c757d'
    ];

    var severityColorMap = {
        critical: '#dc3545',
        high: '#fd7e14',
        medium: '#ffc107',
        low: '#28a745',
    };

    // Severity label to key mapping (Ukrainian -> English)
    var severityKeyMap = {};
    severityKeyMap[decodeURIComponent('%D0%9A%D1%80%D0%B8%D1%82%D0%B8%D1%87%D0%BD%D0%B8%D0%B9')] = 'critical';
    severityKeyMap[decodeURIComponent('%D0%92%D0%B8%D1%81%D0%BE%D0%BA%D0%B8%D0%B9')] = 'high';
    severityKeyMap[decodeURIComponent('%D0%A1%D0%B5%D1%80%D0%B5%D0%B4%D0%BD%D1%96%D0%B9')] = 'medium';
    severityKeyMap[decodeURIComponent('%D0%9D%D0%B8%D0%B7%D1%8C%D0%BA%D0%B8%D0%B9')] = 'low';

    // Timeline chart
    if (typeof monthlyLabels !== 'undefined' && monthlyLabels.length > 0) {
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: monthlyLabels,
                datasets: [{
                    label: 'Incidents',
                    data: monthlyCounts,
                    borderColor: '#005BBB',
                    backgroundColor: 'rgba(0, 91, 187, 0.1)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 4,
                    pointBackgroundColor: '#FFD500',
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1 } }
                }
            }
        });
    }

    // Attack type chart
    if (typeof typeLabels !== 'undefined' && typeLabels.length > 0) {
        new Chart(document.getElementById('typeChart'), {
            type: 'doughnut',
            data: {
                labels: typeLabels,
                datasets: [{
                    data: typeCounts,
                    backgroundColor: chartColors.slice(0, typeLabels.length),
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { position: 'right' } }
            }
        });
    }

    // Sector chart
    if (typeof sectorLabels !== 'undefined' && sectorLabels.length > 0) {
        new Chart(document.getElementById('sectorChart'), {
            type: 'bar',
            data: {
                labels: sectorLabels,
                datasets: [{
                    label: 'Incidents',
                    data: sectorCounts,
                    backgroundColor: '#005BBB',
                    borderColor: '#003f7f',
                    borderWidth: 1,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { stepSize: 1 } }
                }
            }
        });
    }

    // Severity chart
    if (typeof severityLabels !== 'undefined' && severityLabels.length > 0) {
        var sevColors = severityLabels.map(function(label) {
            var key = severityKeyMap[label] || 'low';
            return severityColorMap[key] || '#6c757d';
        });

        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: severityLabels,
                datasets: [{
                    data: severityCounts,
                    backgroundColor: sevColors,
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { position: 'right' } }
            }
        });
    }
});
