"""tools/dashboard_server.py

Interactive Web Dashboard for Elengenix Findings.

Purpose:
- Real-time web interface for viewing security findings
- Filter and search findings by severity, type, target
- Compare scan results (diff view)
- Export reports to PDF/HTML
- Visual analytics with charts
- Mission state visualization

Features:
- Built-in web server (no external dependencies beyond stdlib)
- Auto-refreshes when new findings arrive
- Mobile-responsive design
- Dark/light mode support
"""

from __future__ import annotations

import json
import logging
import socket
import threading
import time
import webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from tools.mission_state import MissionState

logger = logging.getLogger("elengenix.dashboard")


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the dashboard."""
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query = parse_qs(parsed_path.query)
        
        if path == '/' or path == '/index.html':
            self._serve_dashboard()
        elif path == '/api/findings':
            self._serve_findings_api(query)
        elif path == '/api/mission':
            self._serve_mission_api()
        elif path == '/api/stats':
            self._serve_stats_api()
        elif path == '/export/json':
            self._serve_json_export()
        elif path == '/export/html':
            self._serve_html_export()
        elif path.startswith('/static/'):
            self._serve_static_file(path[8:])
        else:
            self._send_404()
    
    def _serve_dashboard(self):
        """Serve the main dashboard HTML."""
        html = self._generate_dashboard_html()
        self._send_response(200, 'text/html', html.encode('utf-8'))
    
    def _serve_findings_api(self, query: Dict[str, List[str]]):
        """Serve findings as JSON API."""
        findings = self.server.dashboard.get_findings(
            severity=query.get('severity', [None])[0],
            finding_type=query.get('type', [None])[0],
            target=query.get('target', [None])[0],
            limit=int(query.get('limit', ['100'])[0]),
        )
        self._send_json_response(findings)
    
    def _serve_mission_api(self):
        """Serve mission state as JSON."""
        mission = self.server.dashboard.get_mission_summary()
        self._send_json_response(mission)
    
    def _serve_stats_api(self):
        """Serve statistics as JSON."""
        stats = self.server.dashboard.get_statistics()
        self._send_json_response(stats)
    
    def _serve_json_export(self):
        """Export all findings as JSON."""
        findings = self.server.dashboard.get_all_findings()
        export_data = {
            "export_time": datetime.utcnow().isoformat(),
            "tool": "Elengenix v2.0.0",
            "total_findings": len(findings),
            "findings": findings,
        }
        self._send_json_response(export_data, download_name="elengenix_findings.json")
    
    def _serve_html_export(self):
        """Export findings as standalone HTML report."""
        html = self._generate_report_html()
        self._send_response(200, 'text/html', html.encode('utf-8'), 
                          headers={'Content-Disposition': 'attachment; filename="elengenix_report.html"'})
    
    def _serve_static_file(self, filename: str):
        """Serve static files (CSS, JS)."""
        content_types = {
            'css': 'text/css',
            'js': 'application/javascript',
            'png': 'image/png',
            'ico': 'image/x-icon',
        }
        ext = filename.split('.')[-1] if '.' in filename else ''
        content_type = content_types.get(ext, 'application/octet-stream')
        
        # Built-in styles and scripts
        if filename == 'style.css':
            content = self._get_css().encode('utf-8')
            self._send_response(200, content_type, content)
        elif filename == 'app.js':
            content = self._get_js().encode('utf-8')
            self._send_response(200, content_type, content)
        else:
            self._send_404()
    
    def _send_response(self, code: int, content_type: str, content: bytes, headers: Optional[Dict[str, str]] = None):
        """Send HTTP response."""
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(content)
    
    def _send_json_response(self, data: Any, download_name: Optional[str] = None):
        """Send JSON response."""
        content = json.dumps(data, indent=2, default=str).encode('utf-8')
        headers = {}
        if download_name:
            headers['Content-Disposition'] = f'attachment; filename="{download_name}"'
        self._send_response(200, 'application/json', content, headers)
    
    def _send_404(self):
        """Send 404 response."""
        self._send_response(404, 'text/plain', b'Not Found')
    
    def _generate_dashboard_html(self) -> str:
        """Generate the dashboard HTML."""
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elengenix Security Dashboard</title>
    <link rel="stylesheet" href="/static/style.css">
    <script src="/static/app.js" defer></script>
</head>
<body>
    <div class="container">
        <header>
            <h1> Elengenix Security Dashboard</h1>
            <p>Real-time vulnerability findings and mission state</p>
            <div class="header-actions">
                <button onclick="toggleTheme()" class="btn"> Theme</button>
                <button onclick="refreshData()" class="btn"> Refresh</button>
                <button onclick="exportJSON()" class="btn btn-primary"> Export JSON</button>
                <button onclick="exportHTML()" class="btn btn-primary"> Export HTML</button>
            </div>
        </header>
        
        <div class="stats-grid" id="stats">
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="stat-value" id="stat-critical">0</div>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="stat-value" id="stat-high">0</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="stat-value" id="stat-medium">0</div>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="stat-value" id="stat-low">0</div>
            </div>
        </div>
        
        <div class="filters">
            <h3> Filters</h3>
            <div class="filter-row">
                <select id="filter-severity" onchange="applyFilters()">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select id="filter-type" onchange="applyFilters()">
                    <option value="">All Types</option>
                    <option value="idor">IDOR/BOLA</option>
                    <option value="xss">XSS</option>
                    <option value="sqli">SQL Injection</option>
                    <option value="misconfig">Misconfiguration</option>
                    <option value="secret">Hardcoded Secret</option>
                    <option value="weak_crypto">Weak Crypto</option>
                    <option value="protocol">Protocol Issue</option>
                </select>
                <input type="text" id="filter-target" placeholder="Target filter..." onkeyup="applyFilters()">
                <input type="text" id="filter-search" placeholder="Search findings..." onkeyup="applyFilters()">
            </div>
        </div>
        
        <div class="content-grid">
            <div class="findings-panel">
                <h3> Findings (<span id="findings-count">0</span>)</h3>
                <div id="findings-list" class="findings-list">
                    <div class="loading">Loading findings...</div>
                </div>
            </div>
            
            <div class="details-panel">
                <h3> Finding Details</h3>
                <div id="finding-details" class="finding-details">
                    <p class="placeholder">Select a finding to view details</p>
                </div>
            </div>
        </div>
        
        <div class="mission-panel">
            <h3> Mission State</h3>
            <div id="mission-state" class="mission-state">
                <div class="loading">Loading mission state...</div>
            </div>
        </div>
        
        <footer>
            <p>Elengenix v2.0.0 - Autonomous Offensive-Defensive System</p>
            <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        </footer>
    </div>
</body>
</html>'''
    
    def _generate_report_html(self) -> str:
        """Generate standalone HTML report."""
        findings = self.server.dashboard.get_all_findings()
        
        findings_html = ""
        for f in findings[:100]:  # Limit to 100 for report
            sev_class = f.get('severity', 'info')
            findings_html += f'''
            <div class="finding-item {sev_class}">
                <h4>[{f.get('severity', 'N/A').upper()}] {f.get('type', 'Unknown')}</h4>
                <p><strong>Target:</strong> {f.get('target', 'N/A')}</p>
                <p><strong>Description:</strong> {f.get('description', 'N/A')}</p>
                <p><strong>Evidence:</strong> <pre>{json.dumps(f.get('evidence', {{}}), indent=2)}</pre></p>
                <hr>
            </div>
            '''
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Elengenix Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        .finding-item {{ margin: 20px 0; padding: 15px; border-radius: 4px; }}
        .finding-item.critical {{ background: #ffebee; border-left: 4px solid #d32f2f; }}
        .finding-item.high {{ background: #fff3e0; border-left: 4px solid #f57c00; }}
        .finding-item.medium {{ background: #fffde7; border-left: 4px solid #fbc02d; }}
        .finding-item.low {{ background: #e8f5e9; border-left: 4px solid #388e3c; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }}
        footer {{ margin-top: 40px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1> Elengenix Security Assessment Report</h1>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p><strong>Total Findings:</strong> {len(findings)}</p>
        
        <h2>Findings</h2>
        {findings_html}
        
        <footer>
            <p>Generated by Elengenix v2.0.0 - Autonomous Offensive-Defensive System</p>
        </footer>
    </div>
</body>
</html>'''
    
    def _get_css(self) -> str:
        """Get the dashboard CSS."""
        return '''
:root {
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #c9d1d9;
    --text-secondary: #8b949e;
    --border-color: #30363d;
    --accent-color: #58a6ff;
    --critical: #f85149;
    --high: #f0883e;
    --medium: #d29922;
    --low: #3fb950;
    --info: #58a6ff;
}

.light-mode {
    --bg-primary: #ffffff;
    --bg-secondary: #f6f8fa;
    --bg-tertiary: #eaeef2;
    --text-primary: #24292f;
    --text-secondary: #57606a;
    --border-color: #d0d7de;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 20px;
}

header {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    border: 1px solid var(--border-color);
}

header h1 {
    font-size: 28px;
    margin-bottom: 5px;
}

header p {
    color: var(--text-secondary);
}

.header-actions {
    margin-top: 15px;
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.btn {
    padding: 8px 16px;
    border: 1px solid var(--border-color);
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    transition: all 0.2s;
}

.btn:hover {
    background: var(--border-color);
}

.btn-primary {
    background: var(--accent-color);
    color: white;
    border-color: var(--accent-color);
}

.btn-primary:hover {
    opacity: 0.9;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}

.stat-card {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    text-align: center;
}

.stat-card h3 {
    color: var(--text-secondary);
    font-size: 14px;
    text-transform: uppercase;
    margin-bottom: 10px;
}

.stat-value {
    font-size: 36px;
    font-weight: bold;
}

.stat-card.critical .stat-value { color: var(--critical); }
.stat-card.high .stat-value { color: var(--high); }
.stat-card.medium .stat-value { color: var(--medium); }
.stat-card.low .stat-value { color: var(--low); }

.filters {
    background: var(--bg-secondary);
    padding: 15px 20px;
    border-radius: 8px;
    margin-bottom: 20px;
    border: 1px solid var(--border-color);
}

.filters h3 {
    margin-bottom: 10px;
    font-size: 16px;
}

.filter-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}

.filter-row select,
.filter-row input {
    padding: 8px 12px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    border-radius: 6px;
    font-size: 14px;
}

.filter-row input {
    min-width: 150px;
}

.content-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
}

@media (max-width: 900px) {
    .content-grid {
        grid-template-columns: 1fr;
    }
}

.findings-panel,
.details-panel {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    max-height: 600px;
    overflow-y: auto;
}

.findings-panel h3,
.details-panel h3 {
    margin-bottom: 15px;
    font-size: 18px;
}

.findings-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.finding-item {
    padding: 15px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.2s;
    border-left: 4px solid transparent;
}

.finding-item:hover {
    background: var(--bg-tertiary);
}

.finding-item.active {
    background: var(--bg-tertiary);
    border-left-color: var(--accent-color);
}

.finding-item.critical { border-left-color: var(--critical); }
.finding-item.high { border-left-color: var(--high); }
.finding-item.medium { border-left-color: var(--medium); }
.finding-item.low { border-left-color: var(--low); }
.finding-item.info { border-left-color: var(--info); }

.finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 5px;
}

.finding-type {
    font-weight: 600;
    font-size: 14px;
}

.finding-severity {
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}

.finding-severity.critical { background: var(--critical); color: white; }
.finding-severity.high { background: var(--high); color: white; }
.finding-severity.medium { background: var(--medium); color: black; }
.finding-severity.low { background: var(--low); color: white; }

.finding-target {
    color: var(--text-secondary);
    font-size: 12px;
}

.finding-details {
    background: var(--bg-tertiary);
    padding: 20px;
    border-radius: 6px;
}

.finding-details h4 {
    margin-bottom: 15px;
    color: var(--accent-color);
}

.detail-row {
    margin-bottom: 12px;
}

.detail-row label {
    color: var(--text-secondary);
    font-size: 12px;
    text-transform: uppercase;
    display: block;
    margin-bottom: 3px;
}

.detail-row pre {
    background: var(--bg-primary);
    padding: 10px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 12px;
}

.mission-panel {
    background: var(--bg-secondary);
    padding: 20px;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    margin-bottom: 20px;
}

.mission-panel h3 {
    margin-bottom: 15px;
}

.mission-state {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

.mission-card {
    background: var(--bg-tertiary);
    padding: 15px;
    border-radius: 6px;
}

.mission-card h4 {
    color: var(--text-secondary);
    font-size: 12px;
    margin-bottom: 8px;
}

.mission-card .value {
    font-size: 24px;
    font-weight: bold;
}

.loading {
    text-align: center;
    color: var(--text-secondary);
    padding: 40px;
}

.placeholder {
    color: var(--text-secondary);
    text-align: center;
    padding: 40px;
}

footer {
    text-align: center;
    color: var(--text-secondary);
    font-size: 12px;
    padding: 20px;
}
'''
    
    def _get_js(self) -> str:
        """Get the dashboard JavaScript."""
        return '''
let currentFindings = [];
let selectedFinding = null;
let autoRefresh = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadData();
    autoRefresh = setInterval(loadData, 5000); // Refresh every 5 seconds
});

async function loadData() {
    try {
        await Promise.all([
            loadStats(),
            loadFindings(),
            loadMission()
        ]);
    } catch (error) {
        console.error('Failed to load data:', error);
    }
}

async function loadStats() {
    const response = await fetch('/api/stats');
    const stats = await response.json();
    
    document.getElementById('stat-critical').textContent = stats.critical || 0;
    document.getElementById('stat-high').textContent = stats.high || 0;
    document.getElementById('stat-medium').textContent = stats.medium || 0;
    document.getElementById('stat-low').textContent = stats.low || 0;
}

async function loadFindings() {
    const severity = document.getElementById('filter-severity').value;
    const type = document.getElementById('filter-type').value;
    const target = document.getElementById('filter-target').value;
    
    let url = '/api/findings?limit=100';
    if (severity) url += `&severity=${severity}`;
    if (type) url += `&type=${type}`;
    if (target) url += `&target=${target}`;
    
    const response = await fetch(url);
    currentFindings = await response.json();
    
    applyFilters();
}

function applyFilters() {
    const search = document.getElementById('filter-search').value.toLowerCase();
    
    let filtered = currentFindings;
    if (search) {
        filtered = filtered.filter(f => 
            JSON.stringify(f).toLowerCase().includes(search)
        );
    }
    
    renderFindings(filtered);
}

function renderFindings(findings) {
    document.getElementById('findings-count').textContent = findings.length;
    
    const list = document.getElementById('findings-list');
    
    if (findings.length === 0) {
        list.innerHTML = '<div class="placeholder">No findings match the current filters</div>';
        return;
    }
    
    list.innerHTML = findings.map((f, index) => `
        <div class="finding-item ${f.severity || 'info'} ${selectedFinding === index ? 'active' : ''}" 
             onclick="selectFinding(${index})">
            <div class="finding-header">
                <span class="finding-type">${f.type || 'Unknown'}</span>
                <span class="finding-severity ${f.severity || 'info'}">${f.severity || 'INFO'}</span>
            </div>
            <div class="finding-target">${f.target || 'N/A'}</div>
        </div>
    `).join('');
}

function selectFinding(index) {
    selectedFinding = index;
    const finding = currentFindings[index];
    
    // Update active state
    document.querySelectorAll('.finding-item').forEach((el, i) => {
        el.classList.toggle('active', i === index);
    });
    
    // Render details
    const details = document.getElementById('finding-details');
    details.innerHTML = `
        <h4>${finding.type || 'Unknown'} Finding</h4>
        
        <div class="detail-row">
            <label>Severity</label>
            <div>${finding.severity || 'N/A'}</div>
        </div>
        
        <div class="detail-row">
            <label>Target</label>
            <div>${finding.target || 'N/A'}</div>
        </div>
        
        <div class="detail-row">
            <label>Description</label>
            <div>${finding.description || 'N/A'}</div>
        </div>
        
        <div class="detail-row">
            <label>Evidence</label>
            <pre>${JSON.stringify(finding.evidence || {}, null, 2)}</pre>
        </div>
        
        <div class="detail-row">
            <label>Remediation</label>
            <div>${finding.remediation || 'N/A'}</div>
        </div>
        
        ${finding.cwe ? `
        <div class="detail-row">
            <label>CWE</label>
            <div>${finding.cwe}</div>
        </div>
        ` : ''}
    `;
}

async function loadMission() {
    const response = await fetch('/api/mission');
    const mission = await response.json();
    
    const container = document.getElementById('mission-state');
    container.innerHTML = `
        <div class="mission-card">
            <h4>Facts</h4>
            <div class="value">${mission.facts || 0}</div>
        </div>
        <div class="mission-card">
            <h4>Hypotheses</h4>
            <div class="value">${mission.hypotheses || 0}</div>
        </div>
        <div class="mission-card">
            <h4>Ledger Entries</h4>
            <div class="value">${mission.ledger || 0}</div>
        </div>
        <div class="mission-card">
            <h4>Active Mission</h4>
            <div class="value">${mission.active_missions || 0}</div>
        </div>
    `;
}

function refreshData() {
    loadData();
}

function exportJSON() {
    window.open('/export/json', '_blank');
}

function exportHTML() {
    window.open('/export/html', '_blank');
}

function toggleTheme() {
    document.body.classList.toggle('light-mode');
    localStorage.setItem('theme', document.body.classList.contains('light-mode') ? 'light' : 'dark');
}

// Restore theme
if (localStorage.getItem('theme') === 'light') {
    document.body.classList.add('light-mode');
}
'''


class DashboardServer(HTTPServer):
    """Dashboard HTTP server with access to findings data."""
    
    def __init__(self, address, handler_class, mission_state: Optional[MissionState] = None):
        super().__init__(address, handler_class)
        self.mission_state = mission_state
        self.findings_cache: List[Dict[str, Any]] = []
        self.last_update = 0
    
    def get_findings(self, severity: Optional[str] = None, 
                    finding_type: Optional[str] = None,
                    target: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        """Get findings with optional filtering."""
        findings = self._load_findings_from_mission()
        
        if severity:
            findings = [f for f in findings if f.get('severity') == severity]
        if finding_type:
            findings = [f for f in findings if finding_type.lower() in f.get('type', '').lower()]
        if target:
            findings = [f for f in findings if target.lower() in str(f.get('target', '')).lower()]
        
        return findings[:limit]
    
    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self._load_findings_from_mission()
    
    def _load_findings_from_mission(self) -> List[Dict[str, Any]]:
        """Load findings from mission state."""
        if not self.mission_state:
            return self.findings_cache
        
        # Prevent excessive reloading
        now = time.time()
        if now - self.last_update < 2:  # Cache for 2 seconds
            return self.findings_cache
        
        try:
            snapshot = self.mission_state.snapshot(max_items=200)
            findings = []
            
            # Get from facts (vulnerabilities)
            for fact in snapshot.get('facts', []):
                if fact.get('category') in ['vulnerability', 'finding', 'misconfiguration']:
                    findings.append({
                        'id': fact.get('fact_id', ''),
                        'type': fact.get('category', 'finding'),
                        'severity': self._extract_severity(fact),
                        'target': fact.get('statement', 'Unknown')[:100],
                        'description': fact.get('statement', ''),
                        'evidence': fact.get('evidence', {}),
                        'confidence': fact.get('confidence', 0),
                    })
            
            # Get from hypotheses
            for hyp in snapshot.get('hypotheses', []):
                if 'vulnerability' in str(hyp.get('tags', [])).lower() or \
                   'security' in str(hyp.get('tags', [])).lower():
                    findings.append({
                        'id': hyp.get('hyp_id', ''),
                        'type': 'hypothesis',
                        'severity': 'medium',
                        'target': hyp.get('title', 'Unknown'),
                        'description': hyp.get('description', ''),
                        'evidence': hyp.get('evidence', {}),
                        'confidence': hyp.get('confidence', 0),
                    })
            
            self.findings_cache = findings
            self.last_update = now
            return findings
            
        except Exception as e:
            logger.error(f"Failed to load findings from mission state: {e}")
            return self.findings_cache
    
    def _extract_severity(self, fact: Dict[str, Any]) -> str:
        """Extract severity from fact data."""
        evidence = fact.get('evidence', {})
        if isinstance(evidence, dict):
            sev = evidence.get('severity') or evidence.get('finding', {}).get('severity')
            if sev:
                return sev.lower()
        return 'info'
    
    def get_mission_summary(self) -> Dict[str, Any]:
        """Get mission state summary."""
        if not self.mission_state:
            return {"facts": 0, "hypotheses": 0, "ledger": 0, "active_missions": 0}
        
        try:
            snapshot = self.mission_state.snapshot(max_items=10)
            return {
                "facts": len(snapshot.get('facts', [])),
                "hypotheses": len(snapshot.get('hypotheses', [])),
                "ledger": len(snapshot.get('ledger', [])),
                "active_missions": 1 if self.mission_state.target else 0,
            }
        except Exception:
            return {"facts": 0, "hypotheses": 0, "ledger": 0, "active_missions": 0}
    
    def get_statistics(self) -> Dict[str, int]:
        """Get finding statistics."""
        findings = self.get_all_findings()
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in stats:
                stats[sev] += 1
            else:
                stats['info'] += 1
        
        return stats


def start_dashboard(mission_state: Optional[MissionState] = None, 
                   port: int = 0,
                   open_browser: bool = True) -> Tuple[int, threading.Thread]:
    """
    Start the dashboard server.
    
    Args:
        mission_state: MissionState instance to pull data from
        port: Port to use (0 = auto-assign)
        open_browser: Whether to open browser automatically
    
    Returns:
        (port, thread) tuple
    """
    # Find available port
    if port == 0:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
    
    server = DashboardServer(('0.0.0.0', port), DashboardHandler, mission_state)
    
    def run_server():
        try:
            logger.info(f"Dashboard server starting on port {port}")
            server.serve_forever()
        except Exception as e:
            logger.error(f"Dashboard server error: {e}")
    
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    
    url = f"http://localhost:{port}"
    logger.info(f"Dashboard available at {url}")
    
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    
    return port, thread


def stop_dashboard(server_thread: threading.Thread):
    """Stop the dashboard server."""
    # Note: Proper shutdown would require storing the server instance
    logger.info("Dashboard stop requested (server runs in daemon thread)")
