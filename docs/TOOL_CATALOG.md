# Elengenix Tool Catalog (98 modules, auto-generated)

> Last updated: 2026-06-07
> Source: `tools/*.py` module docstrings
> Total tools: **98**
> Categorized into **9 groups**

## Quick Reference

| Group | Count | Purpose |
|-------|------:|---------|
| [RECON](#recon-11) | 11 | Subdomain, endpoint, parameter discovery |
| [FUZZ](#fuzz-12) | 12 | Active vulnerability testing |
| [EXPLOIT](#exploit-2) | 2 | PoC generation, chain building |
| [REPORTING](#reporting-10) | 10 | CVE lookup, CVSS scoring, report generation |
| [AI](#ai-14) | 14 | LLM clients, memory, token counting |
| [WAF](#waf-5) | 5 | WAF detection + evasion |
| [TELEGRAM](#telegram-1) | 1 | Remote control gateway |
| [INFRA](#infra-31) | 31 | Orchestration, governance, config, health |
| [UTILS](#utils-12) | 12 | Helpers, integration wrappers |

---

## RECON (11)

| Tool | Description |
|------|-------------|
| `api_finder` | API Documentation & Endpoint Discovery |
| `api_schema_diff` | Compare API schemas across versions |
| `base_recon` | Subdomain & URL Enumeration |
| `dork_miner` | Google Dorking Engine |
| `github_intel` | GitHub Intelligence & Leak Hunter |
| `mobile_api_tester` | Mobile API endpoint testing |
| `param_miner` | Hidden Parameter Discovery |
| `python_recon` | Pure-Python recon (subdomain/dir/port/param) — used by Phase 0 preflight |
| `smart_recon` | Asset correlation engine |
| `subdomain_takeover` | Detect dangling subdomain DNS records |
| `wayback_tool` | Historical URL & Archive Intelligence |

**CLI access**: `elengenix recon <target>`, `elengenium arsenal recon`

## FUZZ (12)

| Tool | Description |
|------|-------------|
| `active_fuzzer` | Intelligent active fuzzer with baseline + differential |
| `agent_bola_bridge` | Bridge AI agent to BOLA differential testing |
| `auth_tester` | Authentication weakness discovery |
| `bola_harness` | BOLA test harness (orchestrates bola_tester) |
| `bola_tester` | Broken Object Level Authorization detector |
| `cors_checker` | CORS Misconfiguration Detector |
| `graphql_scanner` | GraphQL introspection + query testing |
| `injection_tester` | Automated Injection Vulnerability Tester (SQLi/XPath/NoSQL) |
| `payload_mutation` | Generate XSS/SQLi payload variants |
| `race_condition_tester` | TOCTOU / race condition exploit |
| `ssrf_scanner` | Server-Side Request Forgery detector |
| `workflow_fuzzer` | Multi-step workflow fuzzer |

**CLI access**: `elengenix scan <target>` (runs fuzz automatically), `elengenix bola`, `elengenix waf`

## EXPLOIT (2)

| Tool | Description |
|------|-------------|
| `exploit_chain_builder` | Combine findings into multi-stage exploit chains |
| `exploit_template` | Proof-of-Concept Exploit Tester |

**CLI access**: `elengenix poc --framework <name> --version <v>`

## REPORTING (10)

| Tool | Description |
|------|-------------|
| `bounty_intelligence` | HackerOne/Bugcrowd program intelligence |
| `bounty_predictor` | Estimate payout for a finding |
| `bounty_reporter` | Auto-submit to bug bounty platform |
| `coverage_analyzer` | Track which endpoints were tested |
| `cve_database` | CVE Database & Vulnerability Intelligence |
| `cvss_calculator` | CVSS 3.1/4.0 Scoring Engine |
| `finding_dedup` | Deduplicate findings across scans |
| `html_reporter` | Interactive HTML Dashboard Generator |
| `pdf_report_generator` | PDF report with charts |
| `reporter` | Professional Markdown Bug Report Generator |

**CLI access**: `elengenix report <target>`, `elengenix cve-update`

## AI (14)

| Tool | Description |
|------|-------------|
| `agent_reflection` | AI self-reflection after each step |
| `ai_config` | **Single source of truth** for AI provider config (P0-G6) |
| `ai_sandbox` | Safe AI code execution (governance-gated) |
| `ai_tool_creator` | AI proposes new tool, user approves install |
| `context_compressor` | Compress long context for token savings |
| `memory_manager` | Persistent SQLite Memory Store |
| `memory_persistence` | Persistent conversation memory with SQLite |
| `memory_profile` | Personal AI Memory Profile (MEMORY.md) |
| `token_counter` | Accurate token counting with optional tiktoken |
| `token_manager` | AI token budget tracking |
| `universal_ai_client` | OpenAI-compatible HTTP client (NVIDIA, OpenAI, Gemini, etc.) |
| `user_memory` | Persistent User Preference & Context Memory |
| `user_preferences` | User preference store |
| `vector_memory` | Semantic Vector Memory System (ChromaDB) |

**Single source of truth**: All 14 read from `tools/ai_config.py` → `config.yaml`.

## WAF (5)

| Tool | Description |
|------|-------------|
| `dynamic_waf_mutator` | Adaptive WAF bypass via response analysis |
| `edr_evasion` | EDR/IDS evasion utilities (governance-gated) |
| `waf_detector` | Identify WAF vendor from response signatures |
| `waf_evasion` | Generate WAF bypass payloads |
| `waf_signatures` | WAF fingerprint database |

**CLI access**: `elengenix waf <target>`, `elengenix evasion <action>`

## TELEGRAM (1)

| Tool | Description |
|------|-------------|
| `telegram_bridge` | Telegram bot gateway for remote scan control |

**CLI access**: `elengenix gateway` (requires `TELEGRAM_BOT_TOKEN` in `.env`)

## INFRA (31)

| Tool | Description |
|------|-------------|
| `analysis_pipeline` | Post-finding analysis pipeline |
| `autonomous_agent` | Autonomous multi-step agent |
| `base_scanner` | Nuclei Vulnerability Scanner Wrapper |
| `cloud_scanner` | Cloud misconfiguration scanner (AWS/GCP/Azure) |
| `command_suggest` | AI-powered command suggestion |
| `config_wizard` | Interactive API key configuration |
| `dashboard_server` | Web dashboard (Flask-based) |
| `doctor` | Elengenix Framework Health Check |
| `event_loop` | Module-level persistent asyncio event loop singleton |
| `governance` | **Security policy** — gates destructive commands |
| `history_manager` | Scan history lookup |
| `install_request` | AI Tool Installation Request System |
| `interactive_dashboard` | Terminal-based live dashboard |
| `mission_state` | Mission state persistence (JSON + SQLite) |
| `multi_agent` | **Team Aegis**: Multi-Agent Collaboration Engine |
| `overlay_menu` | Settings Overlay (Ctrl+E) |
| `profile_manager` | Scan profile management (quick/deep/stealth) |
| `progress_display` | Progress bar manager |
| `protocol_analyzer` | Network protocol analyzer (TCP/TLS) |
| `research_tool` | OSINT Web Research Tool |
| `safe_exec` | **Native Shell Executor** (security-critical) |
| `sast_engine` | Static Application Security Testing |
| `session_manager` | Mission session state |
| `skill_registry` | Skill & Tool Awareness System |
| `soc_analyzer` | SOC detection rule generation |
| `swarm_controller` | Multi-agent swarm orchestrator |
| `tool_registry` | Elengenix Plugin System |
| `universal_executor` | Universal AI Agent Executor |
| `vuln_researcher` | AI-powered vulnerability research |
| `welcome_wizard` | First-run setup wizard |
| `wordlist_manager` | AI-Driven Smart Wordlist Management |

**Security-critical**: `governance`, `safe_exec` — **must not break** (no shell escape).

**CLI access**: `elengenix doctor`, `elengenix configure`, `elengenix welcome`

## UTILS (12)

| Tool | Description |
|------|-------------|
| `access_control_matrix` | RBAC/ABAC analysis |
| `arjun_integration` | HTTP Parameter Discovery (arjun wrapper) |
| `auto_detector` | Auto-detect target type (web/api/host) |
| `js_analyzer` | JavaScript Secret & Endpoint Extractor |
| `learning_engine` | Cross-scan learning (which tools work best) |
| `logic_analyzer` | Business logic flaw detection |
| `object_id_permuter` | IDOR via object ID manipulation |
| `omni_scan` | Elengenix Full-Scale Scan Entry Point |
| `smart_scanner` | Smart scan with correlation |
| `threat_intel` | Threat intelligence feeds |
| `truffle_integration` | Secret Detection (truffleHog wrapper) |
| `vulncheck_tool` | VulnCheck API integration |

---

## How to Use This Catalog

### Find a tool by category
```bash
ls tools/ | grep -E "recon|fuzz" | sort
```

### Run a specific tool directly
Most tools are exposed via main.py CLI:
```bash
elengenix scan <target>      # auto-runs recon + fuzz + reporting
elengenix recon <target>     # recon-only
elengenix bola <target>      # BOLA-only
elengenix waf <target>       # WAF detection
```

### Import directly in Python
```python
from tools.cvss_calculator import CVSSCalculator
score = CVSSCalculator().calculate(
    av="N", ac="L", pr="N", ui="N",
    s="U", c="H", i="H", a="H"
)
```

### Check tool status
```bash
elengenix doctor  # checks Python deps + Go tools (if any)
```

---

## Test Coverage

| Status | Count | Tools |
|--------|------:|-------|
| Has dedicated test | 6 | bola_tester, waf_detector, waf_mutator, active_fuzzer, coverage_analyzer, learning_engine, ai_tool_sandbox, semantic_fuzzer, semantic_planner |
| No dedicated test | 92 | (most) |
| Integration tested | 11 | test_integration_wired, test_integration_phase4, etc. |

**Goal**: 92 → 0 (target 300+ tests in next sprint)
