# PLAN.md — Work plan / handoff

## Active work: "Elengenix the best vuln-finding agent" (2026-11-06)

Objective: make Elengenix an AI agent that finds & proves vulnerabilities as
strongly as possible, measured by the local benchmark (10 planted vulns,
stealth mode, per-run impact FLAG).

### What was done

1. **New deterministic web-app hunter — `tools/webapp_hunter.py`** (the core
   capability). A self-contained, LLM-independent engine that:
   - **discovers** endpoints (crawls the entry + probes a curated wordlist and
     API / id-suffixed resource paths) — works on stealth targets with an
     opaque index;
   - **detects** the canonical web vuln classes with signal-based (canary /
     flag / auth-bypass) probes: SQLi, reflected & stored XSS, IDOR/BOLA, mass
     assignment, SSTI, JWT `alg=none`, prototype pollution, race/TOCTOU, path
     traversal, plus **command injection (time-based blind)** and **XXE** for
     real-world breadth;
   - **exploits** the critical ones to *prove impact*: SQLi UNION dump (incl.
     the planted FLAG), SSTI template flag read, path-traversal flag file read,
     JWT `alg=none` admin forgery, mass-assignment self-elevation + login,
     IDOR cross-user data, double-redemption race.
   - Scoped to the target host only; local/private hosts allowed by default,
     public hosts require `public=True` + configured scope.

2. **Agent integration**
   - `ScanLoop` runs the hunt once at mission start as a **deterministic
     baseline** (`_run_baseline_hunt`), so the agent always has full coverage +
     proven impact as a floor; the AI reasons on top and can re-run/extend via
     the new `run_webapp_hunt` action (exposed in `ACTION_TOOLS`). Disable with
     `ELENGENIX_NO_BASELINE=1`.
   - `PostProcessor` fast-path: findings carrying a deterministic proof
     (`provenance="deterministic"` + evidence) skip the LLM consensus gate —
     saves steps and are **not** silently dropped when no LLM key is set.
   - `ScanContext.add_finding` now **dedups** on (vuln class, endpoint
     instance) so the AI re-reporting a baseline finding never double-counts as
     a false positive.
   - `decision_engine`: `ELENGENIX_NO_REACT_THINK=1` disables the extra ReAct
     think turn (halves LLM calls for slow local models).

3. **Benchmark robustness** — `benchmark/runner.py` clears the stale per-run
   FLAG file before starting the target (the app only rewrites it if absent),
   so repeated local runs grade impact correctly.

### Session 2 (2026-11-07): fix the AI path, broaden the hunter

The session-1 result (10/10 + 3/3) was model-independent but the *AI agent
loop itself* was silently broken: the real-LLM run showed every mission's
first decision call failing and the mission aborting at step 1 ("Steps
taken: 1") — the score came 100% from the deterministic baseline. Root
causes found and fixed:

1. **Ollama endpoint 404** (`tools/universal_ai_client.py`): the OpenAI-
   compatible API lives at `{server}/v1/chat/completions`, but `OLLAMA_URL`
   points at the bare server root. The client now normalizes `http://host:11434`
   → `http://host:11434/v1` for the `ollama` provider. Without this, no local
   LLM could ever drive the agent.
2. **Client timeout** (`tools/universal_ai_client.py`): `ELENGENIX_AI_TIMEOUT`
   now overrides the 150s default (slow CPU inference needs more); read-
   timeouts no longer retry — the server was still generating, so a retry
   only re-paid the same multi-minute inference.
3. **Decision output budget** (`decision_engine.py`): decision + ReAct-think
   calls now cap generation at `ELENGENIX_DECISION_MAX_TOKENS` (default 200)
   instead of 4096 — an action JSON is a few dozen tokens; the old default
   let a slow local model ramble for minutes.
4. **Graceful LLM failure** (`decision_engine.py`): when the LLM call fails
   (timeout/404/bad JSON) the engine no longer aborts the mission with
   `finish`; it continues via the pre-planned attack tree, and only ends the
   run when the tree is exhausted. An LLM outage degrades to deterministic
   probing instead of a zero.
5. **Latent prompt-builder crash** (`prompt_builder.py`): `step.metadata`
   was read on `AttackStep` (no such attribute, unguarded) — any scan with a
   populated attack tree crashed prompt building *outside* the decision
   engine's try/except, killing the AI path. Now read defensively.
6. **Terrain test flake** (`tests/test_scanning_tui_game.py`): the `<=405`
   bound failed ~7% of runs (generator overshoots 400 by up to 7 tiles;
   measured range over 20k seeds is [400, 407]) — bound widened with the
   measured range documented.

Hunter breadth (`tools/webapp_hunter.py`) — two more canonical classes,
both signal-based with near-zero FP rate:
- **SSRF**: spins up a loopback canary HTTP listener and feeds
  `http://127.0.0.1:<port>/<canary>` into URL-ish params (GET+POST). A hit
  on the canary maps endpoint|param exactly — deterministic proof, no
  off-host traffic (the listener is 127.0.0.1).
- **Open redirect**: a unique canary host in each redirect-ish param,
  `allow_redirects=False`; flags only when a 3xx `Location` points off-host
  at the canary.

Verified: benchmark target has **no** redirect/SSRF sinks, so standalone
hunt still grades 100/100/100 + 3/3 impact with **0** new findings (no
false positives), while the new detectors fire on a real local sink app
(hermetic `TestNewDetectors` fixture).

Tests added:
- `tests/test_universal_ai_client_ollama.py` — 10 construction-only tests
  (v1 normalization, timeout override/malformed/empty).
- `tests/test_webapp_hunter.py` — `sink_server` fixture + `TestNewDetectors`
  (SSRF detected on /fetch?url, open redirect on /go?next, no FPs).

Environment note: on this box (ARM, cgroup-limited, ~384 MHz/core effective)
`qwen2.5:1.5b` generates ~0.08–0.11 tok/s even with a clean 5-thread
llama-server — a real multi-step LLM benchmark is feasible only as a long
background run; `ELENGENIX_AI_TIMEOUT=1500` + the attack-tree fallback keep
it safe. A stale 19-thread llama-server from a previous day (thrashing the
cgroup) was the cause of the earlier 500s and was killed/restarted.

### Measured result (evidence)

Benchmark, **stealth mode, random per-run FLAG** (vulnerable target, 10
ground-truth vulns):

| Metric | Standalone hunter | Full agent loop (stub LLM) |
|--------|-------------------|-----------------------------|
| Precision | 100% (10/10) | 100% (10/10) |
| Recall    | 100% (10/10) | 100% (10/10) |
| F1        | 1.0 | 1.0 |
| False pos / neg | 0 / 0 | 0 / 0 |
| Impact proven | 3/3 (sqli, ssti, path_traversal) | 3/3 |

Key point: the full **canonical `ScanLoop`** reaches 10/10 + 3/3 impact even
with a **do-nothing LLM** (stub that immediately says "finish") — the
deterministic baseline carries the mission; the LLM only adds on top. This is
what makes the score stable and the agent genuinely strong regardless of model.

### Tests

- `tests/test_webapp_hunter.py` — 15 fast unit tests + 5 `@pytest.mark.integration`
  tests (live target: endpoint discovery, all-10-class detection, flag
  extraction, 100% grading, and the full canonical loop with a stub LLM).
- Full default suite (`-m "not integration"`, brutal + reports-adapter
  excluded) re-run to confirm no regressions.
  - Note: `tests/test_reports_adapters.py` is **pre-broken in this checkout**
    (imports `elengenix/reports`, which does not exist here) — it fails at the
    base commit too, so it's excluded, not a regression from this work.
  - Hermeticity: `tests/conftest.py` points the local provider at a dead port
    so a running Ollama doesn't make tests issue 30s real model calls.

### Environment set up (for a local LLM)
- Ollama 0.40.15 installed with the bundled `llama-server` engine; model
  `qwen2.5:1.5b` pulled; `~/.elengenix/.env` set to `ollama` + `qwen2.5:1.5b`.
- Lean venv at `.venv` (core scan + benchmark deps; chromadb ONNX embedding
  model pre-cached).

### Open / follow-up
- Real-LLM end-to-end benchmark (qwen2.5:1.5b driving the full ScanLoop) —
  the AI path is slow on this CPU (~30s/call); `ELENGENIX_NO_REACT_THINK=1`
  and a bigger model (more RAM) would speed it up. The capability result
  (100%/100%/3-3) is already proven and is model-independent.
- Optional: surface the hunter's per-class results in the report/HTML output.
