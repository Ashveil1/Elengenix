# AGENTS.md — How to Work with Elengenix

## Core Principle

**คิดก่อนทำ ทุกครั้ง** — ใช้ MCP thinking tools ก่อนลงมือเขียนโค้ดทุกครั้ง

---

## MCP Thinking Tools (บังคับใช้)

**ต้องเรียก MCP thinking tools ก่อนลงมือเขียนโค้ดทุกครั้ง** — ห้ามข้าม

### 1. sequential-thinking (คิด step-by-step)

ใช้เมื่อ:
- เริ่มงานใหม่
- เจอปัญหาที่ไม่แน่ใจ
- ต้องเลือกระหว่างหลายทาง

```json
{
  "thought": "วิเคราะห์ปัญหา...",
  "thoughtNumber": 1,
  "totalThoughts": 5,
  "nextThoughtNeeded": true
}
```

### 2. chain-of-recursive-thoughts (คิดลึกซึ้ง ซ้ำๆ)

ใช้เมื่อ:
- ปัญหาซับซ้อน ต้องคิดลึก
- ต้องหา root cause
- ต้อง refactor โค้ด

```json
{
  "thought": "วิเคราะห์ root cause...",
  "depth": 1,
  "branching": false
}
```

### 3. mcp-structured-thinking (คิดเป็นขั้นตอน)

ใช้เมื่อ:
- ต้องวางแผนขั้นตอน
- ต้องแบ่งงานเป็นส่วนๆ
- ต้องประมาณเวลา

---

## Working Protocol

### 1. ก่อนเริ่มงานทุกครั้ง

```
sequential-thinking:
  thought: "วิเคราะห์ปัญหา..."
  - ปัญหาคืออะไร?
  - ผลกระทบต่อส่วนไหน?
  - มีทางเลือกอะไรบ้าง?
  - ทางไหนดีที่สุด?
```

### 2. ขั้นตอนทำงาน

| ขั้นตอน | ทำอะไร |
|---------|--------|
| **คิด** | MCP thinking tools วิเคราะห์ก่อน |
| **สำรวจ** | อ่านโค้ดที่เกี่ยวข้อง |
| **วางแผน** | กำหนดว่าจะแก้ตรงไหน |
| **ทำ** | เขียนโค้ด |
| **ทดสอบ** | รัน test ตรวจสอบ |
| **ตรวจสอบ** | ว่าไม่กระทบส่วนอื่น |

### 3. กฎเหล็ก

- **อย่าแก้โค้ดโดยไม่อ่านก่อน** — ต้อง `read` ไฟล์ก่อน `edit`
- **อย่าข้าม test** — ต้องรัน test หลังแก้โค้ดทุกครั้ง
- **อย่าแก้หลายไฟล์พร้อมกัน** — แก้ทีละไฟล์ ทดสอบทีละจุด
- **อย่าเดา** — ถ้าไม่แน่ใจ ให้ `grep` หาคำตอบ
- **อย่าข้าม MCP thinking** — ต้องคิดก่อนทำเสมอ

### 4. การใช้ MCP thinking tools

**ใช้ sequential-thinking เมื่อ:**
- เริ่มงานใหม่
- เจอปัญหาที่ไม่แน่ใจ
- ต้องเลือกระหว่างหลายทาง
- แก้ bug ที่ซับซ้อน

**ใช้ chain-of-recursive-thoughts เมื่อ:**
- ปัญหาซับซ้อน ต้องคิดลึก
- ต้องหา root cause
- ต้อง refactor โค้ดขนาดใหญ่

**ใช้ mcp-structured-thinking เมื่อ:**
- ต้องวางแผนขั้นตอน
- ต้องแบ่งงานเป็นส่วนๆ
- ต้องประมาณเวลาและทรัพยากร

### 5. ตัวอย่าง sequential-thinking

```
sequential-thinking:
  thought: |
    ปัญหา: ฟังก์ชัน is_in_scope() ไม่รองรับ IPv6

    วิเคราะห์:
    - normalize_target() ตัด port ด้วย split(":")
    - แต่ IPv6 มี ":" หลายตัว → ตัดผิด

    ทางเลือก:
    1. เช็คว่าเป็น IPv6 ก่อน → ซับซ้อน
    2. นับ ":" ถ้า > 1 แสดงว่า IPv6 → ง่ายกว่า

    ตัดสินใจ: ใช้ทางเลือก 2

    ผลกระทบ:
    - pipeline/scope.py — แก้ normalize_target
    - ต้องเพิ่ม test สำหรับ IPv6
  nextThoughtNeeded: false
```

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

## File Structure

ดูรายละเอียดใน elengenix-dev skill

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
# Stable suite
python3 -m pytest tests/test_tui.py tests/test_security.py tests/test_core_modules.py tests/test_new_scanners.py tests/test_critical_modules.py -v

# New modules
python3 -m pytest tests/test_scan_context.py tests/test_prompt_builder.py tests/test_post_processor.py tests/test_decision_engine.py tests/test_scan_loop.py -v

# Pipeline
python3 -m pytest tests/test_scope.py tests/test_phase_registry.py tests/test_unified_pipeline.py -v
```
