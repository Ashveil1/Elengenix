# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Elengenix itself (not findings from using Elengenix against a target), please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

Email: **ashveil1@proton.me**

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

### Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Patch release | 14 business days |

### Scope

The following are in scope:
- Command injection via agent inputs
- Governance bypass (executing DESTRUCTIVE commands)
- API key leakage through logs or outputs
- Arbitrary file read/write outside of designated directories
- Privilege escalation within the agent execution context

The following are out of scope:
- Vulnerabilities in third-party Go tools (subfinder, nuclei, etc.)
- Issues requiring physical access to the machine
- Social engineering attacks

## Security Architecture

Elengenix enforces defense-in-depth:

1. **Governance Gate** — Classifies every command as SAFE / PRIVILEGED / DESTRUCTIVE before execution
2. **No `shell=True`** — All subprocess calls use list-form arguments
3. **Metacharacter blocking** — Pipe, semicolon, backtick, and substitution characters are rejected
4. **Target validation** — All scan targets are validated before tool dispatch
5. **Scope enforcement** — Operations are confined to declared scope boundaries

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (main branch) | Yes |
| Older releases | No |
