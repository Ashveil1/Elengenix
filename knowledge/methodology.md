# Bug Bounty Hunting Methodology for Elengenix

## 1. Reconnaissance (Mapping the Surface)
- **Vertical Discovery**: Find subdomains using subfinder.
- **Horizontal Discovery**: Find IPs and other root domains.
- **Live Check**: Use httpx to filter out dead hosts and get titles/status codes.
- **Visual Recon**: (Optional) Use tools to screenshot targets.

## 2. Information Gathering
- **JavaScript Analysis**: Use js_analyzer to find API keys, secrets, and internal endpoints.
- **Endpoint Mining**: Use katana and waybackurls to find hidden paths.
- **Parameter Mining**: Look for ?debug, ?admin, ?config, etc.

## 3. Vulnerability Testing (Priority Order)
1. **Critical**: RCE, SQL Injection, Auth Bypass, Massive SSRF.
2. **High**: IDOR, File Upload, Stored XSS, Privilege Escalation.
3. **Medium**: CORS Misconfig, Reflected XSS, Broken Link Hijacking.
4. **Low**: Information Disclosure, Header Misconfigurations.

## 4. Exploitation & Verification
- When you find a potential vulnerability, try to create a non-destructive Proof of Concept (PoC).
- Report findings with clear steps to reproduce.
