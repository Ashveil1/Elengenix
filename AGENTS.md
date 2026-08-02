# AGENTS.md — How to Work with Elengenix

## Working Protocol

### ขั้นตอนทำงาน

| ขั้นตอน | ทำอะไร |
|---------|--------|
| **คิด** | วิเคราะห์ปัญหาและผลกระทบก่อนลงมือ |
| **สำรวจ** | อ่านโค้ดที่เกี่ยวข้อง |
| **วางแผน** | กำหนดว่าจะแก้ตรงไหน |
| **ทำ** | เขียนโค้ด |
| **ทดสอบ** | รัน test ตรวจสอบ |
| **ตรวจสอบ** | ว่าไม่กระทบส่วนอื่น |

### กฎเหล็ก

- **อย่าแก้โค้ดโดยไม่อ่านก่อน** — ต้อง `read` ไฟล์ก่อน `edit`
- **อย่าข้าม test** — ต้องรัน test หลังแก้โค้ดทุกครั้ง
- **อย่าแก้หลายไฟล์พร้อมกัน** — แก้ทีละไฟล์ ทดสอบทีละจุด
- **อย่าเดา** — ถ้าไม่แน่ใจ ให้ `grep` หาคำตอบ

---

## Code Review Checklist

เมื่อรีวิวโค้ด ต้องตรวจสอบ:

- [ ] **Imports** — ถูกต้องไหม? ไม่ circular?
- [ ] **Error handling** — จับ exception ได้ไหม?
- [ ] **Security** — มี injection? XSS? ข้อมูลรั่ว?
- [ ] **Performance** — มี bottleneck? N+1 query?
- [ ] **Backward compatibility** — โค้ดเดิมพังไหม?
- [ ] **Test coverage** — มี test ครอบคลุมไหม?

---

## Architecture Notes (canonical namespace)

- **Live code lives under `elengenix/`** — especially `elengenix/scanning/*` (scan loop, council, planner, decision engine, prompt builder, verification, vuln reasoning).
- **Top-level `agents/*.py` are thin deprecation shims** that re-export from `elengenix.scanning.*` with a `DeprecationWarning`. Do not add new top-level agent modules; extend `elengenix/scanning/` instead. If you need a public symbol, import it from the live module.
- **Top-level `core/`** (`brain.py`, `agent.py`, `orchestrator.py`) are deprecated compatibility shims delegating into `elengenix/` — same rule: keep them working, don't extend them.
- **Two LLM stacks exist**:
  - *Stack A* — `elengenix/providers/`: clean 10-provider `Provider` Protocol (`call`/`call_ex`/`call_with_tools`) with reflection and `ToolCallFixer`. This is the preferred, model-agnostic path.
  - *Stack B* — `tools/universal_ai_client.py`: legacy live client (textual-JSON + native tool-call hybrid). The scan loop prefers Stack A when configured (see `elengenix/scanning/provider_bridge.py`) and falls back to Stack B otherwise.
- **MCP**: `mcp/protocol.py` + `mcp/client.py` provide a compact JSON-RPC 2.0 MCP implementation (stdio + http). Use it for tool standardization when integrating new external tools.

---

## Benchmark

- `benchmark/README.md` — what the benchmark measures + how to run sweeps & read history
- `benchmark/run_benchmark.py` — CLI: single run, `--models a,b --repeat N` sweep, `--history`
- `benchmark/grading.py` — ground truth (10 planted vulns) + precision/recall/F1 grader
- `benchmark/runner.py` — spins up `tests/vulnerable_target/app.py`, runs the canonical ScanLoop
- `benchmark/sweep.py` — per-model sweep aggregation (mean/min/max F1 across repeats)
- `benchmark/results_store.py` — persists each run JSON to `data/benchmark_results/` (via `get_data_dir`), history loader/formatter

Useful commands:

```bash
python3 benchmark/run_benchmark.py --json                                  # single run
python3 benchmark/run_benchmark.py --models gpt-4o-mini,qwen2.5-coder     # sweep across models
python3 benchmark/run_benchmark.py --models llama3.2 --repeat 3           # repeat stats (mean/min/max F1)
python3 benchmark/run_benchmark.py --history                              # last 20 stored runs
```

Exit codes: `0` = ran, recall>0 · `1` = ran, recall=0 · `2` = infrastructure error (missing API key, target failed to start, legacy mode, …). See `benchmark/README.md` for detail.

---

## Common Patterns

### Lazy Import
```python
# ใช้เมื่อ import อาจล้มเหลว
try:
    from tools.optional_module import Something
except ImportError:
    Something = None
```

### Safe Operation
```python
# ใช้เมื่อ operation อาจล้มเหลว
def _safe_operation(name, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.debug(f"{name} failed: {e}")
```

### Governance Check
```python
# ทุก shell command ต้องผ่าน governance
gate = governance.gate(mission_id, target, action)
if gate.decision == "needs_approval":
    # popup ถาม user
elif gate.decision == "deny":
    # บล็อค
```

---

## Testing Commands

```bash
# Full test suite (everything, excluding brutal/ subset)
python3 -m pytest tests/ --ignore=tests/brutal -q

# Scanning subsystem
python3 -m pytest tests/test_scanning_*.py -q

# Benchmark (grading, results store, sweep — offline/hermetic)
python3 -m pytest tests/test_benchmark_grading.py tests/test_benchmark_sweep.py -q

# MCP subsystem
python3 -m pytest tests/test_mcp_*.py -q
```
