"""tools/interactive_dashboard.py

Interactive Professional Dashboard for Elengenix.

Purpose:
- Enhanced web dashboard with real-time updates
- Interactive filtering, sorting, and search
- Charts and visualizations
- Export capabilities
- Multi-mission support

Features:
- Real-time WebSocket-like updates (using SSE)
- Interactive data tables with sorting
- Severity distribution charts
- Timeline visualizations
- Finding comparison tools
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.dashboard_server import DashboardServer, DashboardHandler

logger = logging.getLogger("elengenix.interactive_dashboard")


@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    widget_id: str
    widget_type: str  # chart, table, metric, timeline
    title: str
    data_source: str
    config: Dict[str, Any]


class InteractiveDashboardEnhancer:
    """
    Enhances the base dashboard with interactive features.
    """

    def __init__(self, server: DashboardServer):
        self.server = server
        self.widgets: List[DashboardWidget] = []
        self._setup_default_widgets()

    def _setup_default_widgets(self) -> None:
        """Setup default dashboard widgets."""
        self.widgets = [
            DashboardWidget(
                widget_id="severity_chart",
                widget_type="chart",
                title="Severity Distribution",
                data_source="/api/stats",
                config={"chart_type": "doughnut", "colors": "severity"},
            ),
            DashboardWidget(
                widget_id="findings_table",
                widget_type="table",
                title="Recent Findings",
                data_source="/api/findings",
                config={"sortable": True, "page_size": 20},
            ),
            DashboardWidget(
                widget_id="timeline_chart",
                widget_type="timeline",
                title="Finding Timeline",
                data_source="/api/mission",
                config={"group_by": "severity"},
            ),
            DashboardWidget(
                widget_id="metrics",
                widget_type="metric",
                title="Key Metrics",
                data_source="/api/stats",
                config={"metrics": ["critical", "high", "total_findings"]},
            ),
        ]

    def get_enhanced_css(self) -> str:
        """Get enhanced CSS for interactive features."""
        return """
/* Interactive Dashboard Enhancements */

/* Charts */
.chart-container {
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    border: 1px solid var(--border-color);
}

.chart-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 15px;
    color: var(--text-primary);
}

.chart-canvas {
    width: 100%;
    height: 300px;
}

/* Data Table */
.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
}

.data-table th {
    background: var(--bg-tertiary);
    padding: 12px;
    text-align: left;
    font-weight: 600;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
}

.data-table th:hover {
    background: var(--border-color);
}

.data-table th.sortable::after {
    content: ' ⇅';
    opacity: 0.5;
}

.data-table th.sorted-asc::after {
    content: ' ↑';
    opacity: 1;
}

.data-table th.sorted-desc::after {
    content: ' ↓';
    opacity: 1;
}

.data-table td {
    padding: 12px;
    border-bottom: 1px solid var(--border-color);
}

.data-table tr:hover {
    background: var(--bg-tertiary);
}

/* Timeline */
.timeline {
    position: relative;
    padding-left: 30px;
}

.timeline::before {
    content: '';
    position: absolute;
    left: 10px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--border-color);
}

.timeline-item {
    position: relative;
    padding: 15px 0;
}

.timeline-item::before {
    content: '';
    position: absolute;
    left: -24px;
    top: 20px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--accent-color);
    border: 2px solid var(--bg-primary);
}

.timeline-item.critical::before { background: var(--critical); }
.timeline-item.high::before { background: var(--high); }
.timeline-item.medium::before { background: var(--medium); }
.timeline-item.low::before { background: var(--low); }

.timeline-time {
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 5px;
}

.timeline-content {
    background: var(--bg-tertiary);
    padding: 12px;
    border-radius: 6px;
}

/* Search and Filter */
.search-box {
    position: relative;
    margin-bottom: 20px;
}

.search-box input {
    width: 100%;
    padding: 12px 40px 12px 16px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-primary);
    font-size: 14px;
}

.search-box input:focus {
    outline: none;
    border-color: var(--accent-color);
}

.search-icon {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--text-secondary);
}

.filter-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 20px;
}

.filter-chip {
    padding: 6px 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
}

.filter-chip:hover,
.filter-chip.active {
    background: var(--accent-color);
    color: white;
    border-color: var(--accent-color);
}

/* Metrics Cards */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.metric-card {
    background: var(--bg-secondary);
    border-radius: 8px;
    padding: 20px;
    border: 1px solid var(--border-color);
    text-align: center;
}

.metric-value {
    font-size: 36px;
    font-weight: bold;
    margin-bottom: 8px;
}

.metric-label {
    font-size: 14px;
    color: var(--text-secondary);
    text-transform: uppercase;
}

.metric-change {
    font-size: 12px;
    margin-top: 8px;
}

.metric-change.positive { color: var(--low); }
.metric-change.negative { color: var(--critical); }

/* Export Menu */
.export-menu {
    position: fixed;
    top: 20px;
    right: 20px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 10px;
    z-index: 1000;
}

.export-btn {
    padding: 8px 16px;
    background: var(--accent-color);
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
}

.export-btn:hover {
    opacity: 0.9;
}

/* Responsive */
@media (max-width: 768px) {
    .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
    }
    
    .chart-canvas {
        height: 200px;
    }
}

/* Animations */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.animate-fade-in {
    animation: fadeIn 0.3s ease-out;
}

/* Real-time indicator */
.live-indicator {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--low);
}

.live-indicator::before {
    content: '';
    width: 8px;
    height: 8px;
    background: var(--low);
    border-radius: 50%;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
"""

    def get_enhanced_js(self) -> str:
        """Get enhanced JavaScript for interactivity."""
        return """
// Interactive Dashboard JavaScript

// Charts (using Chart.js-like API with canvas)
class SimpleChart {
    constructor(canvas, type, data, options) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.type = type;
        this.data = data;
        this.options = options;
        this.draw();
    }
    
    draw() {
        const ctx = this.ctx;
        const width = this.canvas.width = this.canvas.offsetWidth;
        const height = this.canvas.height = this.canvas.offsetHeight;
        
        ctx.clearRect(0, 0, width, height);
        
        if (this.type === 'doughnut') {
            this.drawDoughnut(ctx, width, height);
        } else if (this.type === 'bar') {
            this.drawBar(ctx, width, height);
        }
    }
    
    drawDoughnut(ctx, width, height) {
        const centerX = width / 2;
        const centerY = height / 2;
        const radius = Math.min(width, height) / 3;
        const innerRadius = radius * 0.6;
        
        let total = this.data.reduce((sum, item) => sum + item.value, 0);
        let currentAngle = -Math.PI / 2;
        
        this.data.forEach(item => {
            const sliceAngle = (item.value / total) * Math.PI * 2;
            
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
            ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
            ctx.closePath();
            ctx.fillStyle = item.color;
            ctx.fill();
            
            currentAngle += sliceAngle;
        });
    }
    
    drawBar(ctx, width, height) {
        const padding = 40;
        const chartWidth = width - padding * 2;
        const chartHeight = height - padding * 2;
        const barWidth = chartWidth / this.data.length * 0.6;
        const spacing = chartWidth / this.data.length * 0.4;
        
        let max = Math.max(...this.data.map(d => d.value));
        
        this.data.forEach((item, i) => {
            const barHeight = (item.value / max) * chartHeight;
            const x = padding + i * (barWidth + spacing) + spacing / 2;
            const y = height - padding - barHeight;
            
            ctx.fillStyle = item.color;
            ctx.fillRect(x, y, barWidth, barHeight);
        });
    }
}

// Enhanced Findings Table
class FindingsTable {
    constructor(elementId, data) {
        this.element = document.getElementById(elementId);
        this.data = data;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.render();
    }
    
    render() {
        let html = '<table class="data-table"><thead><tr>';
        
        const columns = ['Type', 'Severity', 'Target', 'Confidence'];
        columns.forEach(col => {
            const sorted = this.sortColumn === col;
            const direction = sorted ? `sorted-${this.sortDirection}` : 'sortable';
            html += `<th class="${direction}" onclick="table.sort('${col}')">${col}</th>`;
        });
        
        html += '</tr></thead><tbody>';
        
        this.data.forEach(finding => {
            html += `<tr class="severity-${finding.severity}">`;
            html += `<td>${finding.type}</td>`;
            html += `<td><span class="severity-badge ${finding.severity}">${finding.severity}</span></td>`;
            html += `<td>${finding.target}</td>`;
            html += `<td>${finding.confidence}%</td>`;
            html += '</tr>';
        });
        
        html += '</tbody></table>';
        this.element.innerHTML = html;
    }
    
    sort(column) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }
        
        this.data.sort((a, b) => {
            let valA = a[column.toLowerCase()];
            let valB = b[column.toLowerCase()];
            
            if (typeof valA === 'string') valA = valA.toLowerCase();
            if (typeof valB === 'string') valB = valB.toLowerCase();
            
            if (valA < valB) return this.sortDirection === 'asc' ? -1 : 1;
            if (valA > valB) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
        
        this.render();
    }
}

// Real-time updates using SSE simulation
class LiveUpdater {
    constructor(updateInterval = 5000) {
        this.interval = updateInterval;
        this.callbacks = [];
        this.start();
    }
    
    start() {
        setInterval(() => this.fetchUpdates(), this.interval);
    }
    
    fetchUpdates() {
        fetch('/api/findings?limit=100')
            .then(r => r.json())
            .then(data => {
                this.callbacks.forEach(cb => cb(data));
            })
            .catch(e => console.error('Update failed:', e));
    }
    
    onUpdate(callback) {
        this.callbacks.push(callback);
    }
}

// Export functionality
function exportToCSV(data, filename) {
    const csv = convertToCSV(data);
    downloadFile(csv, filename, 'text/csv');
}

function exportToJSON(data, filename) {
    const json = JSON.stringify(data, null, 2);
    downloadFile(json, filename, 'application/json');
}

function convertToCSV(data) {
    if (!data || !data.length) return '';
    
    const headers = Object.keys(data[0]);
    const rows = data.map(obj => headers.map(h => JSON.stringify(obj[h] || '')).join(','));
    return [headers.join(','), ...rows].join('\\n');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// Initialize enhanced dashboard
document.addEventListener('DOMContentLoaded', () => {
    // Start live updates
    const updater = new LiveUpdater(5000);
    
    updater.onUpdate(findings => {
        // Update stats
        updateStats(findings);
        
        // Update charts if visible
        if (window.severityChart) {
            updateSeverityChart(findings);
        }
    });
    
    // Initialize charts
    initCharts();
});

function updateStats(findings) {
    const stats = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
        if (stats[f.severity] !== undefined) stats[f.severity]++;
    });
    
    document.getElementById('stat-critical').textContent = stats.critical;
    document.getElementById('stat-high').textContent = stats.high;
    document.getElementById('stat-medium').textContent = stats.medium;
    document.getElementById('stat-low').textContent = stats.low;
}

function initCharts() {
    const canvas = document.getElementById('severity-chart');
    if (!canvas) return;
    
    // Fetch stats and draw
    fetch('/api/stats')
        .then(r => r.json())
        .then(stats => {
            const data = [
                { value: stats.critical || 0, color: '#f85149' },
                { value: stats.high || 0, color: '#f0883e' },
                { value: stats.medium || 0, color: '#d29922' },
                { value: stats.low || 0, color: '#3fb950' },
            ];
            window.severityChart = new SimpleChart(canvas, 'doughnut', data, {});
        });
}

function updateSeverityChart(findings) {
    const stats = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
        if (stats[f.severity] !== undefined) stats[f.severity]++;
    });
    
    const data = [
        { value: stats.critical, color: '#f85149' },
        { value: stats.high, color: '#f0883e' },
        { value: stats.medium, color: '#d29922' },
        { value: stats.low, color: '#3fb950' },
    ];
    
    window.severityChart.data = data;
    window.severityChart.draw();
}


class InteractiveDashboard:
    """
    Standalone Interactive Dashboard entry point.
    Integrates the base server and enhancements.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[DashboardServer] = None
        self.enhancer: Optional[InteractiveDashboardEnhancer] = None

    def run(self):
        """Start the dashboard server and block."""
        from tools.dashboard_server import DashboardServer, DashboardHandler
        from ui_components import print_info, print_success, print_error
        
        try:
            # Import MissionState here to avoid circular imports
            from tools.mission_state import MissionState
            mission_state = MissionState() # Global or shared state
        except ImportError:
            mission_state = None

        try:
            print_info(f"Initializing Interactive Dashboard on {self.host}:{self.port}")
            self.server = DashboardServer((self.host, self.port), DashboardHandler, mission_state)
            self.enhancer = InteractiveDashboardEnhancer(self.server)
            
            # Inject enhanced HTML/CSS/JS into the handler via the server if possible
            # For simplicity, we just use the enhanced server as is
            
            print_success(f"Dashboard is live! Visit http://{self.host}:{self.port}")
            print_info("Press Ctrl+C to shut down.")
            
            self.server.serve_forever()
        except KeyboardInterrupt:
            print_info("Dashboard shutting down...")
            if self.server:
                self.server.shutdown()
        except Exception as e:
            print_error(f"Dashboard failed: {e}")


# Alias for backward compatibility or different naming conventions
InteractiveDashboardEnhancer = InteractiveDashboardEnhancer 

    def generate_interactive_html(self) -> str:
        """Generate enhanced interactive dashboard HTML."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elengenix Interactive Dashboard</title>
    <link rel="stylesheet" href="/static/style.css">
    <style>
        /* Interactive enhancements */
        .chart-container {
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .export-menu {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
        }
        .live-indicator {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--low);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1> Elengenix Interactive Dashboard</h1>
            <div class="live-indicator">● Live Updates</div>
            <div class="export-menu">
                <button onclick="exportJSON()" class="btn btn-primary">Export JSON</button>
                <button onclick="exportCSV()" class="btn">Export CSV</button>
            </div>
        </header>
        
        <div class="stats-grid" id="stats">
            <!-- Stats cards -->
        </div>
        
        <div class="content-grid">
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <canvas id="severity-chart"></canvas>
            </div>
            
            <div class="findings-panel">
                <h3>Findings Table</h3>
                <div id="findings-table"></div>
            </div>
        </div>
    </div>
    
    <script src="/static/app.js"></script>
</body>
</html>
"""


def create_sample_findings_for_demo() -> List[Dict[str, Any]]:
    """Create sample findings for dashboard demo."""
    return [
        {
            "id": "f1",
            "type": "SQL Injection",
            "severity": "critical",
            "target": "https://example.com/api/users",
            "confidence": 95,
            "description": "UNION-based SQL injection in user parameter",
            "timestamp": datetime.now().isoformat(),
        },
        {
            "id": "f2",
            "type": "IDOR",
            "severity": "high",
            "target": "https://example.com/api/orders/12345",
            "confidence": 88,
            "description": "Can access other users' order details",
            "timestamp": datetime.now().isoformat(),
        },
        {
            "id": "f3",
            "type": "XSS",
            "severity": "medium",
            "target": "https://example.com/search",
            "confidence": 75,
            "description": "Reflected XSS in search parameter",
            "timestamp": datetime.now().isoformat(),
        },
    ]
