# PLAN.md — แผนปรับปรุง Elengenix รอบใหญ่ (ทุกด้าน, ทิศทางเดียว)

> ไฟล์นี้คือ handoff ฉบับสมบูรณ์สำหรับ AI agent ที่มารับงานต่อแบบไม่มี context เดิม
> อ่านไฟล์นี้ไฟล์เดียวแล้วเริ่มงานต่อได้ทันที
> เขียนเมื่อ: 2026-09-19 | สถานะ: **PR#1 ทำค้างไว้ ~70% (ยังไม่ commit)**

---

## 1. เป้าหมายและทิศทางหลัก

ปรับปรุงโปรเจกต์ Elengenix (Autonomous AI Security Research Framework, Python) ทุกด้านให้ไปในทางเดียวกัน:

> **โค้ดมีชีวิตอยู่ที่ `elengenix/` + `commands/` + `tools/` เท่านั้น** — ที่เหลือคือเก็บกวาด รวมศูนย์ หรือลบทิ้ง

ทิศนี้มาจากผลสำรวจ: `agents/` (26 ไฟล์) ส่วนใหญ่เป็น deprecation shim, `core/brain.py` (1115 บรรทัด) แปะป้าย shim แต่ไม่มี counterpart, `pipeline/scope.py` เป็นสำเนาตายของ `elengenix/scope.py`, Memory implementation มี 8+ ตัว, report generator มี 5 ตัว, LLM stack มี 2 ชุด

## 2. คำตัดสินใจของเจ้าของโปรเจกต์ (ห้ามเปลี่ยนเอง ถ้าจะเปลี่ยนต้องถามก่อน)

| ข้อ | คำตอบ |
|---|---|
| โค้ดตาย (shims, pipeline, tarball, `*,cover`) | **ลบเด็ดขาด** (ไม่เก็บ compat ยกเว้น `core/orchestrator.is_in_scope` ที่ `main.py` ยังใช้ — เก็บ re-export ไว้ 1 รุ่น) |
| ลำดับความสำคัญ | **Test/CI ก่อน** → Security → ลบโค้ดตาย → Lint/Docs → Benchmark/DX |
| รูปแบบส่งงาน | **PR ย่อยหลายตัว** แยกตามด้าน (รีวิวง่าย, revert ทีละส่วนได้) |

## 3. สถานะปัจจุบัน (สิ่งที่ทำไปแล้ว — ยังไม่ commit ทั้งหมด)

### 3.1 งานที่เสร็จแล้ว (uncommitted — ตรวจด้วย `git status --short`)

```
M .github/workflows/ci.yml      → เขียนใหม่ (ดู 3.2)
D .github/workflows/test.yml    → ลบทิ้ง (stale, อ้างไฟล์ test ที่ไม่มีอยู่จริง 7 ไฟล์)
M .gitignore                    → เพิ่ม `*,cover` และ `*.tar.gz`
M AGENTS.md                     → อัปเดตส่วน Verify ให้ตรง CI ใหม่แล้ว
M pyproject.toml                → dev deps + pytest config (ดู 3.3)
D pytest.ini                    → ลบ (ซ้ำกับ pyproject — ดูเหตุผลใน 3.3)
M tests/brutal/test_agents_brutal.py   → แก้ `get_event_loop` เป็น `asyncio.run` 1 บรรทัด
M tests/brutal/test_api_auth_brutal.py → ลบโค้ดตาย `if False else` 1 จุด
D ไฟล์ `*,cover` 65 ไฟล์ + `elengenix-pentagi-integration.tar.gz` (760KB) → `git rm` ออก (ลบเด็ดขาด)
```

### 3.2 CI ใหม่ (`.github/workflows/ci.yml` — เขียนแล้ว)

- เหลือ workflow เดียว: job `test` (matrix Python 3.11–3.13, `pip install -e ".[dev]"`, รัน main suite **ไม่รวม brutal**) + job `brutal` แยก (Python 3.12 อย่างเดียว, รัน `pytest tests/brutal`)
- เหตุผลที่แยก brutal: `tests/brutal/` มี 1179 tests เป็น fuzz-style subset; AGENTS.md บอกให้แยกจาก default run แต่ CI เก่ารวมไว้โดยไม่ตั้งใจ
- Boot smoke test ยังอยู่: `python -m elengenix --help || elengenix --help || true`

### 3.3 `pyproject.toml` ที่แก้แล้ว

- `[dev]` เพิ่ม `pytest-timeout`, `rich` (ของเดิม CI ติดตั้งแยกด้วยคำสั่งพิเศษ — ตอนนี้ `pip install -e ".[dev]"` ครอบหมด)
- `[tool.pytest.ini_options]` เพิ่ม `timeout = 300` + `filterwarnings = ignore::DeprecationWarning`
- **ลบ `pytest.ini` เหตุผลสำคัญ:** pytest ให้ `pytest.ini` มี priority สูงกว่า `pyproject.toml` — ตราบใดที่ `pytest.ini` ยังอยู่ ค่า `markers`/`timeout` ใน pyproject จะถูก ignore เงียบ ๆ (เจอตอนรันจริง: `inifile: pytest.ini`) ปัจจุบัน config เหลือที่เดียวคือ pyproject

### 3.4 งานที่ทำค้าง (ต้องทำต่อ — ละเอียดในข้อ 5)

1. **PR#1 ค้าง:** ชุด test ใน `tests/brutal/test_integration_security_brutal.py` (~88 tests) import `elengenix.reports.*` ซึ่ง**ไม่มีอยู่จริงใน repo** → ต้องตัดสินใจ implement vs quarantine (วิเคราะห์ไว้แล้วในข้อ 4)
2. Deps ที่โค้ดใช้แต่ไม่ได้ประกาศ: `strawberry` (`elengenix/graphql/schema.py:32`), `fastapi` (`elengenix/api/routes/__init__.py:44`), `itsdangerous` (lazy import ใน `elengenix/auth/sessions.py:108-116`), ไม่มี PDF lib ใด ๆ (แต่ test คาดหวัง PDF bytes)
3. Full suite baseline รันค้างอยู่ (background job, ดูข้อ 6.4)

---

## 4. ข้อค้นพบสำคัญ (หลักฐานพร้อม file:line — ไม่ต้องสำรวจซ้ำ)

### 4.1 Test suite ตัวเลขจริง (วัดเอง ไม่ใช่ตาม docs)

- `pytest --collect-only` (หลัง ignore brain 2 ไฟล์): **3049 tests**; ในนั้น `tests/brutal/` = **1179 tests**
- README เคลม "334 tests", CLAUDE.md เคลม "379+ tests" — **ผิดทั้งคู่ (stale ~10 เท่า)** ต้องแก้ใน PR#4
- `grep mark.integration tests/` = **0 uses** — marker `integration` ตายสนิท (suite ทั้งหมด hermetic: mocked/localhost) แต่ให้เก็บ marker + `-m "not integration"` ไว้เป็น convention อนาคต
- `CLAUDE.md:33-42` อ้างชื่อไฟล์ test ที่ไม่มีอยู่จริง ~10 ไฟล์ (`test_security.py`, `test_core_modules.py`, `test_scan_context.py`, ... ชื่อจริงคือ `test_scanning_*`, `test_elengix_*`) — ต้องเขียน CLAUDE.md ใหม่ใน PR#4
- Test หลัก (`test_elengix_scope/governance/paths` 54 ตัว) **ผ่าน**; `tests/brutal/test_agents_brutal.py` 200 ตัว **ผ่านหลังแก้ข้อ 3.1**

### 4.2 `elengenix.reports` ไม่มีอยู่จริง (งานค้างชิ้นใหญ่ของ PR#1)

- `tests/brutal/test_integration_security_brutal.py` เรียก `from elengenix.reports.<mod> import ...` แต่ `elengenix/` ไม่มีโฟลเดอร์ `reports/` → **~88+ tests ล้มด้วย `ModuleNotFoundError`** (นับจาก error `No module named 'elengenix.reports'` × 88)
- Contract ที่ test คาดหวัง (อ่านจาก test แล้ว):
  - `reports.markdown`: `generate_report_markdown(flow, tasks, subtasks)` (คืน str ขึ้นต้น `# `, มี title/result ครบ), `generate_anchors`, `shift_markdown_headers`, `slugify_github`, `status_emoji`, `DEFAULT_STATUS_EMOJI` — **stdlib ล้วน ทำได้**
  - `reports.cvss`: `parse_cvss_vector`, `format_cvss_vector`, `calculate_cvss_score`, `CVSSVector`, `CVSSResult`, `cvss_result`, `cvss_severity`, enums (`AttackVector`, `AttackComplexity`, `PrivilegesRequired`, `UserInteraction`, `Scope`, `CIAImpact`) — **stdlib ล้วน (CVSS 3.1 math มาตรฐาน) ทำได้** มี test vectors ชัดเจน (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8; `...S:C/C:H/I:H/A:H` → 10.0)
  - `reports.templates`: `COMPLIANCE/EXECUTIVE_SUMMARY/TECHNICAL/VULNERABILITY_REPORT_TEMPLATE`, `render_template` — **stdlib ทำได้** (ต้องอ่าน assertions ใน test บรรทัด ~1601-1648, 1790)
  - `reports.export`: `export_report`, `render_html`, `generate_filename`, `_slugify_title`, `SUPPORT
...[truncated 8188 chars]