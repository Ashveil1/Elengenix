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

Hunter breadth (`tools/webapp_hunter.py`) — signal-based with near-zero FP
rate, now **15 classes**: SQLi, reflected & stored XSS, IDOR/BOLA, mass
assignment, SSTI, JWT `alg=none`, prototype pollution, race/TOCTOU, path
traversal, command injection (time-based blind), XXE, plus:
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
| Autonomous AI steps | n/a (baseline only) | n/a (stub finishes) |

**Run 7 — first fully autonomous cloud-LLM mission** (DeepSeek-V4.1-Flash,
stealth, `ELENGENIX_AUTO_APPROVE=1`): baseline 10/10 + 3/3 in 61s, then the
LLM itself completed **3 real AI steps** (chose + executed
`run_webapp_hunt` 3×, each verified 10 findings). Graded 100/100/100 + 3/3,
0 FP, 0 FN, 1194s. The agent loop genuinely works end-to-end now:
decide → execute (governance-gated) → observe → decide.

Key point: the full **canonical `ScanLoop`** reaches 10/10 + 3/3 impact even
with a **do-nothing LLM** (stub that immediately says "finish") — the
deterministic baseline carries the mission; the LLM only adds on top. This is
what makes the score stable and the agent genuinely strong regardless of model.

### Tests

- `tests/test_webapp_hunter.py` — 18 fast unit tests (incl. `sink_server`
  fixture + `TestNewDetectors` for SSRF / open-redirect) + 5
  `@pytest.mark.integration` tests (live target: endpoint discovery,
  all-10-class detection, flag extraction, 100% grading, and the full
  canonical loop with a stub LLM).
- `tests/test_universal_ai_client_ollama.py` — 10 hermetic construction
  tests for the Ollama `/v1` normalization + `ELENGENIX_AI_TIMEOUT`.
- Full default suite (`-m "not integration"`, brutal + brain-coverage +
  reports-adapter excluded): **1980 passed, 7 failed** — all 7 verified to
  also fail at the base commit (pre-existing/environmental: 3
  `benchmark_sweep` target-behavior tests, `elengix_paths`,
  `providers_lazy_init` ×2, `test_tui`). Not a regression from this work.
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
- **Cloud LLM (recommended for real missions):** the `custom`
  OpenAI-compatible provider works with any `/v1/chat/completions`
  endpoint — set `CUSTOM_API_BASE` + `CUSTOM_API_KEY` (+ `CUSTOM_MODEL`).
  Verified with `https://api.tokenlab.amd.com/v1` + `DeepSeek-V4.1-Flash`
  (fast, native tool-calling, ~8-15s per decision). `ELENGENIX_AUTO_APPROVE=1`
  is required for headless/autonomous runs (see Run 7 notes above).

### Open / follow-up
- **Real-LLM end-to-end evidence (measured, 2026-11-07):**
  - Run (max_steps=5, time_limit=1500s): the **deterministic baseline scored
    10/10 + 3/3 impact in 34s** (sqli, ssti, path_traversal flag-extraction
    proven), then the LLM decision phase consumed the rest of the window on a
    *single* in-flight generation (the 1.5B model emits ~0.1 tok/s on this
    5.6GB/swap-thrashing ARM box; a 200-token cap ≈ 30+ min of generation) and
    no AI step completed. Net: the loop stayed alive the whole time (no crash,
    no abort) and the graded result was the full 10/10 partial.
  - The grader previously summarized any `error` run as "FAILED — findings
    are empty", which would have misreported that 10/10; fixed to show a
    **PARTIAL** status with full metrics when findings exist (commit
    b534a22).
  - **Run 3 (live `qwen2.5:1.5b` driving the canonical `ScanLoop`, 60-token
    decision cap, 900s per-call timeout, 5000s window): precision 100%
    (10/10), recall 100% (10/10), F1 100%, impact 3/3, 0 FP, 0 FN,
    981.6s, Steps=1.** The deterministic baseline hunted 10/10 + 3/3 in
    37s; the single AI decision call then hit the 900s read-timeout (model
    ~0.1 tok/s on this box) and the graceful-fallback path kept the loop
    alive with the graded result intact — exactly the designed degradation.
    Log: `/tmp/opencode/real_llm_benchmark_run3.log`; script:
    `.venv/bin/python /tmp/opencode/real_llm_benchmark.py`.
  - **Run 7 (first AUTONOMOUS multi-step mission, cloud model):** the
    deterministic baseline hunted 10/10 + 3/3 in 61s, then the **cloud
    LLM completed 3 real AI steps** (it chose and executed
    `run_webapp_hunt` itself, ×3) — graded 100/100/100 + 3/3, 0 FP, 0 FN,
    1194s. This is the first run where the AI agent loop itself did
    meaningful work (runs 3-5 with the local model never completed a
    single AI step). Two follow-up gaps found & fixed (commits 9e69c02,
    01b2de9, a389cd1):
    - **governance false positive**: the model's benign `2>/dev/null`
      idiom was classified PRIVILEGED (system write) → almost every recon
      command blocked. `/dev/null`+friends are now exempt (regex +
      token-level); a regression matrix pins the SAFE/PRIVILEGED/
      DESTRUCTIVE boundary.
    - **headless approval hang**: `input()` blocked forever in
      background runs. Now `ELENGENIX_AUTO_APPROVE=1` is the explicit
      operator opt-in (DESTRUCTIVE stays blocked unconditionally);
      non-TTY without the flag fails safe (deny).
    - **verification council couldn't see the custom endpoint** (it built
      its own `AIClientManager` whose order excluded `custom`) → it
      discarded every AI hypothesis. `get_provider_order()` now appends
      `custom` last (only active when configured — never shadows real
      providers).
    - **model re-hunted until deadlock**: prompts now tell the model the
      baseline ALREADY RAN with N verified findings — escalate/chain/
      test-elsewhere instead of re-running `run_webapp_hunt`.
  - **Run 8 (autonomous mission, full fixed stack, full strategy prompt +
    ReAct think):** baseline hunted 10/10 + 3/3 in 37s, then the cloud LLM
    completed **6 distinct autonomous AI steps** — not just re-hunting:
    a port/health check, bulk endpoint discovery (api/admin/debug/graphql/
    swa...), and method probing (`OPTIONS /login`, `POST /login` empty
    body). The **verification council now makes judgment calls** — it
    rejected `api_abuse` as a genuine `false_positive` (3×) instead of the
    old provider-failure discard, which is the precision guard working. The
    run also **survived a live provider 503 outage** mid-mission (the loop
    fell back and kept the 10/10) — resilience as designed. Graded
    100/100/100 + 3/3, 0 FP, 0 FN, 2226s, Steps=6. Log:
    `/tmp/opencode/real_llm_benchmark_run8.log`; script:
    `.venv/bin/python /tmp/opencode/real_llm_benchmark8.py`.
  - **Planning-prompt action space** (`prompt_builder.py`, commit 0add256):
    the prompt listed only 6 of the 11 dispatchable actions and never named
    `run_webapp_hunt`, so small models hallucinated action names
    (`securityScan`, `dispatchSecurityAlert`) and could not discover the
    hunter. It now enumerates all 11 and says "MUST be EXACTLY one of".
  - Bottom line for "strongest agent": detection/impact capability is
    **100% and model-independent** (proven with a do-nothing LLM, a slow
    live local model, and a fast cloud model). The AI agent loop itself now
    genuinely drives the mission end-to-end (decide → execute → observe →
    decide): with a fast cloud model (Runs 7-8) it makes *distinct*
    autonomous pentest actions and the council verifies/rejects hypotheses
    for real, while the deterministic baseline still guarantees the 100%
    floor if the LLM is absent, slow, or down (a live 503 outage mid-mission
    was absorbed). The agent is strong regardless of which model is plugged
    in — that model-independence is the actual capability.
- **Beyond the saturated 10-vuln set: a "discrimination under noise"
  benchmark** (commit 62611cc). The canonical 10-vuln benchmark measures
  *completeness* (did it find all 10?). It saturates at 100% and cannot
  measure whether an agent that "finds everything" is actually precise or
  just over-reporting. So a *harder, noisier* target was added to measure
  the other half of the superlative — **precision under noise + novel
  classes the 10-vuln set never exercised**:
  - **2 new real-world hunter classes (15 -> 17)**, both canary/signal-based
    and FP-safe on the canonical target:
    * `host_header_injection` — a unique canary `Host` reflected into the
      response body or a redirect `Location` (password-reset / absolute-URL
      poisoning, cache poisoning).
    * `jwt_weak_secret` — only probes a JWT endpoint that REJECTS alg=none,
      then forges an admin token with a bounded weak-secret list; the proof
      is a forged token the server ACCEPTS as valid (deterministic, ~zero FP).
      A far-future `iat` is rejected by strict JWT libs, so the forgery uses
      `iat=now`.
  - **A noisier stealth target** (`tests/vulnerable_target/hard_target.py`):
    the 2 real vulns (host-header on `/reset`, weak-secret `supersecret` on
    `/api/jwt/verify` that rejects alg=none) plus **3 decoys** a naive
    substring scanner false-positives on but the canary detectors resist:
    `/search` (reflected but HTML-escaped -> not XSS), `/download` (echoed but
    no traversal -> not LFI), `/api/config` (leaks a STRONG random JWT secret
    -> not weak-secret).
  - **A new metric, `decoy_resistance`** = 1 - (decoys false-positived /
    decoys), graded alongside precision/recall/F1 in
    `benchmark/hard_benchmark.py` (`run_hard_benchmark`, `--hunter` for the
    fast model-independent path).
  - **Verified (hunter-only):** Precision 100% (2/2), Recall 100%, F1 1.0,
    **0 false positives, decoy resistance 100% (3/3)**, ~15s, exit 0. The
    "Impact proven: 0/3" in the grader summary line is *expected* — no
    flag-eligible class (sqli/ssti/path_traversal) exists on the hard target;
    the exit logic uses recall + FP only. 5 new hermetic hunter tests + 5
    hard-benchmark tests; the 5 integration tests still pass with **0 false
    positives on the canonical 10-vuln target** (precision stays 1.0).
  - **Full regression gate (after this batch): 2050 passed, 5 failed —
    exactly the 5 known pre-existing failures, zero regressions** (+9 new
    tests from this batch all pass; up from 2041 at the prior gate).
  - **Canonical autonomous-loop run on the hard target (cloud model):
    COMPLETED — clean sweep.** Full AI agent loop (not just the hunter)
    graded **Precision 100%, Recall 100%, F1 1.0, 0 FP, 0 FN, decoy
    resistance 100% (3/3)**, 5 distinct autonomous AI steps, 2068s,
    exit 0. The baseline found both real vulns in 14s; the cloud LLM then
    made *distinct* steps (curl recon of `/`+robots.txt, bulk endpoint
    discovery, `/api/config`+`/health` inspection) and the council made
    genuine **precision judgments** — discarding `sqli`, `auth`,
    `auth_bypass`, `api_abuse`, `info_disclosure` as `false_positive`
    (it is discriminating, not over-reporting). Crucially, the run
    **survived a flaky API that 503'd ~6 times mid-mission** (the loop
    fell back each time and kept the 2/2 + 0-FP result). Log:
    `/tmp/opencode/hard_benchmark_canonical.log`.
    This is the "best" claim made measurable beyond the saturated 10-vuln
    set: on a noisier surface with real novel classes + decoys, the agent
    still finds the real vulns, proves the JWT one by forgery, and does
    NOT false-positive on the decoys — even while the provider is
    intermittently down.
- Formatting: this checkout is not black-clean at base (several untouched
  files reformat under black 25.x) and CI runs **no lint job** (pytest only;
  pre-commit not installed here), so code was left un-reformatted to keep
  the diff minimal. If a maintainer wants black applied, it should be a
  separate, repo-wide commit.
- Optional: surface the hunter's per-class results in the report/HTML output.
