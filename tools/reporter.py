import os
from datetime import datetime

def generate_bug_report(target, findings, report_path):
    """
    Generates a professional Markdown report for bug hunting submissions.
    """
    report_content = f"""# 🛡️ Bug Bounty Report: {target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Framework:** Elengenix AI Framework

## 🚀 1. Executive Summary
The automated assessment of `{target}` revealed several findings across reconnaissance, vulnerability scanning, and deep code analysis.

## 🔍 2. Reconnaissance (Target Mapping)
Found live targets and subdomains. Details are stored in the reports directory.

## 🔥 3. Vulnerability Findings (Nuclei & Custom Scans)
"""
    if findings:
        for finding in findings:
            report_content += f"### {finding.get('name', 'Finding')}\n"
            report_content += f"- **URL:** `{finding.get('url')}`\n"
            report_content += f"- **Severity:** {finding.get('severity', 'N/A')}\n"
            report_content += f"- **Details:** {finding.get('details', 'N/A')}\n\n"
    else:
        report_content += "No high-severity vulnerabilities were automatically detected.\n"

    report_content += """
## 🧠 4. AI Insights & Manual Verification Steps
AI Agent suggested the following verification steps based on findings.

## ⚖️ 5. Disclaimer
This report was generated for ethical security research purposes only.
"""
    with open(report_path, "w") as f:
        f.write(report_content)
    
    return report_path
