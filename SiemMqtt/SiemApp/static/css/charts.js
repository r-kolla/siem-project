function initializeCharts() {
    // Log Activity Chart
    var logActivityCtx = document.getElementById('logActivityChart');
    if (logActivityCtx && window.logActivityLabels && window.logActivityData) {
        new Chart(logActivityCtx, {
            type: 'line',
            data: {
                labels: window.logActivityLabels,
                datasets: [{
                    label: 'Log Count',
                    data: window.logActivityData,
                    borderColor: '#0072C6',
                    backgroundColor: 'rgba(0, 114, 198, 0.1)',
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // Top Publishers Chart
    var topPublishersCtx = document.getElementById('topPublishersChart');
    if (topPublishersCtx && window.publisherLabels && window.publisherData) {
        new Chart(topPublishersCtx, {
            type: 'bar',
            data: {
                labels: window.publisherLabels,
                datasets: [{
                    label: 'Message Count',
                    data: window.publisherData,
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // Top Topics Chart
    var topTopicsCtx = document.getElementById('topTopicsChart');
    if (topTopicsCtx && window.topicLabels && window.topicData) {
        new Chart(topTopicsCtx, {
            type: 'bar',
            data: {
                labels: window.topicLabels,
                datasets: [{
                    label: 'Message Count',
                    data: window.topicData,
                    backgroundColor: [
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // QoS Distribution Chart
    var qosDistributionCtx = document.getElementById('qosDistributionChart');
    if (qosDistributionCtx && window.qosData) {
        new Chart(qosDistributionCtx, {
            type: 'doughnut',
            data: {
                labels: ['QoS 0', 'QoS 1', 'QoS 2'],
                datasets: [{
                    label: 'QoS Distribution',
                    data: window.qosData,
                    backgroundColor: [
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
}