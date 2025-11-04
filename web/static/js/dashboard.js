// Dashboard functionality
let dashboardCharts = {};
let realtimeData = {
    packetsProcessed: 0,
    threatsDetected: 0,
    activeAlerts: 0,
    threatTypes: {}
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeDashboard();
    startRealtimeUpdates();
    setupEventListeners();
});

function initializeDashboard() {
    console.log('Initializing dashboard...');
    
    // Initialize charts
    initializeCharts();
    
    // Load initial data
    loadDashboardData();
    
    // Update status indicators
    updateStatusIndicators();
}

function initializeCharts() {
    // Threat Detection Over Time Chart
    const ctx1 = document.getElementById('threatDetectionChart');
    if (ctx1) {
        dashboardCharts.threatDetection = new Chart(ctx1, {
            type: 'line',
            data: {
                labels: generateTimeLabels(24),
                datasets: [{
                    label: 'Threats Detected',
                    data: generateRandomData(24, 0, 10),
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: true
                    }
                }
            }
        });
    }
    
    // Threat Types Distribution Chart
    const ctx2 = document.getElementById('threatTypesChart');
    if (ctx2) {
        dashboardCharts.threatTypes = new Chart(ctx2, {
            type: 'doughnut',
            data: {
                labels: ['DDoS', 'PortScan', 'Bot', 'Web Attack', 'Other'],
                datasets: [{
                    data: [25, 20, 15, 10, 5],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#20c997',
                        '#6c757d'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                    }
                }
            }
        });
    }
    
    // System Performance Chart
    const ctx3 = document.getElementById('performanceChart');
    if (ctx3) {
        dashboardCharts.performance = new Chart(ctx3, {
            type: 'bar',
            data: {
                labels: ['CPU Usage', 'Memory Usage', 'Network I/O', 'Disk I/O'],
                datasets: [{
                    label: 'Usage %',
                    data: [45, 62, 38, 25],
                    backgroundColor: [
                        '#007bff',
                        '#28a745',
                        '#ffc107',
                        '#dc3545'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    }
}

function loadDashboardData() {
    // Load recent threats
    fetch('/api/threats/recent?limit=10')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateThreatsTable(data.threats);
                updateThreatCounters(data.threats);
            }
        })
        .catch(error => {
            console.error('Error loading threats:', error);
            // Use simulated data
            updateThreatsTable(generateSimulatedThreats());
        });
    
    // Load system status
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                updateSystemStatus(data.status);
            }
        })
        .catch(error => {
            console.error('Error loading system status:', error);
        });
}

function updateThreatsTable(threats) {
    const tbody = document.querySelector('#threatsTable tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    threats.forEach(threat => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${threat.threat_type || 'Unknown'}</td>
            <td>${threat.source_ip || 'N/A'}</td>
            <td>${threat.destination_ip || 'N/A'}</td>
            <td><span class="badge bg-${getSeverityColor(threat.severity)}">${threat.severity || 'LOW'}</span></td>
            <td>${formatTimestamp(threat.timestamp)}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="viewThreatDetails('${threat.id}')">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function updateThreatCounters(threats) {
    // Update counters
    const totalThreats = threats.length;
    const highSeverity = threats.filter(t => t.severity === 'HIGH').length;
    const mediumSeverity = threats.filter(t => t.severity === 'MEDIUM').length;
    const lowSeverity = threats.filter(t => t.severity === 'LOW').length;
    
    // Update threat type distribution
    const threatTypes = {};
    threats.forEach(threat => {
        const type = threat.threat_type || 'Other';
        threatTypes[type] = (threatTypes[type] || 0) + 1;
    });
    
    // Update charts
    if (dashboardCharts.threatTypes) {
        const labels = Object.keys(threatTypes);
        const data = Object.values(threatTypes);
        
        dashboardCharts.threatTypes.data.labels = labels;
        dashboardCharts.threatTypes.data.datasets[0].data = data;
        dashboardCharts.threatTypes.update();
    }
    
    // Update real-time counters
    realtimeData.threatsDetected = totalThreats;
    realtimeData.threatTypes = threatTypes;
    
    updateRealtimeCounters();
}

function updateRealtimeCounters() {
    // Update packets processed (simulate)
    realtimeData.packetsProcessed += Math.floor(Math.random() * 100) + 50;
    
    // Update active alerts
    realtimeData.activeAlerts = Math.floor(Math.random() * 5) + 1;
    
    // Update display
    document.getElementById('packetsProcessed').textContent = realtimeData.packetsProcessed.toLocaleString();
    document.getElementById('threatsDetected').textContent = realtimeData.threatsDetected.toLocaleString();
    document.getElementById('activeAlerts').textContent = realtimeData.activeAlerts.toLocaleString();
    
    // Update threat detection chart
    if (dashboardCharts.threatDetection) {
        const chart = dashboardCharts.threatDetection;
        const newValue = Math.floor(Math.random() * 10);
        
        // Shift data
        chart.data.datasets[0].data.shift();
        chart.data.datasets[0].data.push(newValue);
        
        chart.update('none');
    }
}

function startRealtimeUpdates() {
    // Update counters every 5 seconds
    setInterval(updateRealtimeCounters, 5000);
    
    // Refresh threat data every 30 seconds
    setInterval(loadDashboardData, 30000);
}

function setupEventListeners() {
    // Threat simulation button
    const simulateBtn = document.getElementById('simulateThreats');
    if (simulateBtn) {
        simulateBtn.addEventListener('click', function() {
            simulateThreats();
        });
    }
    
    // Export report button
    const exportBtn = document.getElementById('exportReport');
    if (exportBtn) {
        exportBtn.addEventListener('click', function() {
            exportReport();
        });
    }
    
    // View logs button
    const logsBtn = document.getElementById('viewLogs');
    if (logsBtn) {
        logsBtn.addEventListener('click', function() {
            viewLogs();
        });
    }
}

function simulateThreats() {
    const button = document.getElementById('simulateThreats');
    const originalText = button.innerHTML;
    
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Simulating...';
    button.disabled = true;
    
    fetch('/api/threats/simulate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            num_packets: 50
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Threat simulation started! New threats will appear shortly.', 'success');
            
            // Refresh data after a short delay
            setTimeout(() => {
                loadDashboardData();
            }, 3000);
        } else {
            showNotification('Failed to start threat simulation: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Failed to start threat simulation', 'error');
    })
    .finally(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    });
}

function exportReport() {
    const button = document.getElementById('exportReport');
    const originalText = button.innerHTML;
    
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
    button.disabled = true;
    
    fetch('/api/export/report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            type: 'threats',
            date_range: '7d'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Create and download report
            const reportData = JSON.stringify(data.data, null, 2);
            const blob = new Blob([reportData], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report-${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            showNotification('Report exported successfully!', 'success');
        } else {
            showNotification('Failed to export report: ' + data.error, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Failed to export report', 'error');
    })
    .finally(() => {
        button.innerHTML = originalText;
        button.disabled = false;
    });
}

function viewLogs() {
    // Open logs in a modal or new page
    fetch('/api/logs?hours=24')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showLogsModal(data.logs);
            } else {
                showNotification('Failed to load logs: ' + data.error, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Failed to load logs', 'error');
        });
}

function showLogsModal(logs) {
    // Create modal HTML
    const modalHTML = `
        <div class="modal fade" id="logsModal" tabindex="-1">
            <div class="modal-dialog modal-xl">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">System Logs</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Timestamp</th>
                                        <th>Level</th>
                                        <th>Component</th>
                                        <th>Message</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${logs.map(log => `
                                        <tr>
                                            <td>${formatTimestamp(log.timestamp)}</td>
                                            <td><span class="badge bg-${getLogLevelColor(log.level)}">${log.level}</span></td>
                                            <td>${log.component}</td>
                                            <td>${log.message}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal
    const existingModal = document.getElementById('logsModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('logsModal'));
    modal.show();
}

function viewThreatDetails(threatId) {
    // Navigate to threat details page or show modal
    showNotification(`Viewing details for threat ${threatId}`, 'info');
}

// Utility functions
function generateTimeLabels(hours) {
    const labels = [];
    const now = new Date();
    for (let i = hours; i >= 0; i--) {
        const time = new Date(now.getTime() - i * 60 * 60 * 1000);
        labels.push(time.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
    }
    return labels;
}

function generateRandomData(count, min, max) {
    return Array.from({ length: count }, () => Math.floor(Math.random() * (max - min + 1)) + min);
}

function generateSimulatedThreats() {
    const threatTypes = ['DDoS', 'PortScan', 'Bot', 'Web Attack'];
    const severities = ['HIGH', 'MEDIUM', 'LOW'];
    const threats = [];
    
    for (let i = 0; i < 10; i++) {
        threats.push({
            id: `THREAT_${i}`,
            threat_type: threatTypes[Math.floor(Math.random() * threatTypes.length)],
            source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
            destination_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
            severity: severities[Math.floor(Math.random() * severities.length)],
            timestamp: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString()
        });
    }
    
    return threats;
}

function getSeverityColor(severity) {
    const colors = {
        'HIGH': 'danger',
        'MEDIUM': 'warning',
        'LOW': 'success'
    };
    return colors[severity] || 'secondary';
}

function getLogLevelColor(level) {
    const colors = {
        'ERROR': 'danger',
        'WARNING': 'warning',
        'INFO': 'info',
        'DEBUG': 'secondary'
    };
    return colors[level] || 'secondary';
}

function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

function updateSystemStatus(status) {
    // Update system status indicators
    if (status.detection_active) {
        document.getElementById('detectionStatus').innerHTML = '<i class="fas fa-check-circle text-success"></i> Active';
    } else {
        document.getElementById('detectionStatus').innerHTML = '<i class="fas fa-times-circle text-danger"></i> Inactive';
    }
    
    if (status.models_loaded) {
        document.getElementById('modelsStatus').innerHTML = '<i class="fas fa-check-circle text-success"></i> Loaded';
    } else {
        document.getElementById('modelsStatus').innerHTML = '<i class="fas fa-times-circle text-danger"></i> Not Loaded';
    }
}

function updateStatusIndicators() {
    // Update status indicators with current data
    const indicators = document.querySelectorAll('.status-indicator');
    indicators.forEach(indicator => {
        const status = Math.random() > 0.5 ? 'success' : 'warning';
        indicator.className = `status-indicator status-${status}`;
    });
}

function showNotification(type, message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}
