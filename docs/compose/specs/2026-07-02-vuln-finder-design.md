# Adaptive Vulnerability Finder — Design Spec

## [S1] Problem

Elengenix ต้องการระบบ AI สำหรับหาช่องโหว่ที่:
- ทำงาน autonomous ได้ 100% (ไม่ต้อง human intervention ยกเว้น sudo password)
- หาช่องโหว่ได้ทุกประเภท: OWASP Top 10, API security, Auth/Logic, Advanced exploitation, Infrastructure, Supply chain
- คิดและตัดสินใจเองได้ (adaptive strategy ไม่ใช่ static checklist)
- Chain ช่องโหว่เล็กๆ ให้กลายเป็น critical impact (เช่น IDOR + Info Disclosure → Full Account Takeover)
- Escalate low-severity bugs ให้กลายเป็น high/critical โดยลอง exploit ต่อ
- ใช้ 3 reasoning layers: CoT prompting + Sequential-thinking + Reflection
- Verify findings ด้วย dual-model verification
- รายงานผลใน format: Markdown, HTML, PDF พร้อม attack chain diagrams

## [S2] Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                    VulnFinder Engine                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐  │
│  │   Recon      │───▶│  Planning    │───▶│ Execution  │  │
│  │   Module     │    │  Module      │    │ Module     │  │
│  └─────────────┘    └──────────────┘    └────────────┘  │
│         │                  │                   │         │
│         ▼                  ▼                   ▼         │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Shared Memory (Vector + SQLite)      │   │
│  │  - Assets discovered                             │   │
│  │  - Findings with severity + evidence             │   │
│  │  - Attack paths tried (success/fail)             │   │
│  │  - Gaps identified                               │   │
│  └──────────────────────────────────────────────────┘   │
│         │                  │                   │         │
│         ▼                  ▼                   ▼         │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐  │
│  │  Verification│───▶│  Chaining    │───▶│  Report    │  │
│  │  Module      │    │  Module      │    │  Module    │  │
│  └─────────────┘    └──────────────┘    └────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## [S3] Attack Methodology

### Target/Path Ranking (จาก Mythos Scaffold)

ก่อน execute ทุกครั้ง AI ต้อง rank targets/paths ก่อน:

```
1. AI ได้ asset inventory จาก recon
2. AI rank แต่ละ target/path 1-5:
   - 5 = สูงมาก (raw data from internet, parses user input)
   - 4 = สูง (handles auth, file upload, API endpoints)
   - 3 = ปานกลาง (standard web pages)
   - 2 = ต่ำ (static content, read-only)
   - 1 = ไม่มี (constants, config, no attack surface)
3. เริ่มจาก rank 5 ลงไป
4. ถ้า rank สูงสุดไม่เจอ → ลอง rank ถัดไป
5. วนจนครบ หรือจน AI ตัดสินใจว่าพอแล้ว
```

**Retry Logic:**
```
ranked_paths = AI.rank(all_paths)  # [5,5,4,4,3,3,2,1]
tried = set()

for rank in [5, 4, 3, 2, 1]:
    paths_at_rank = [p for p in ranked_paths if p.rank == rank and p not in tried]
    for path in paths_at_rank:
        result = execute(path)
        tried.add(path)
        if result.finding:
            # escalate, chain, verify
            ...

    # หลังทำ rank นี้เสร็จ — AI ตัดสินใจว่า:
    # - ข้อมูลพอหรือยัง? → หยุด
    # - ยังไม่พอ? → ทำ rank ถัดไป
    # - ต้อง recon เพิ่มไหม? → กลับ recon
```

### Phase 1: Reconnaissance (ไม่จำกัด scope)

AI เริ่มจากข้อมูลน้อยที่สุด แล้วค่อยๆ ขยาย attack surface:

1. **Passive Recon** — DNS enum, WHOIS, cert transparency, search dorking, GitHub leaks, Wayback URLs
2. **Active Recon** — Port scan, service detection, HTTP probing, tech fingerprinting, WAF detection
3. **Endpoint Discovery** — Directory brute-force, parameter discovery, API enumeration, JS analysis
4. **Scope Expansion** — ถ้าเจอ subdomain/domain ที่เชื่อมต่อกัน ให้เพิ่มเข้ามาด้วย (ไม่ limit scope)

**Output:** Asset inventory (subdomains, IPs, endpoints, tech stack, WAF status)

### Phase 2: Planning (CoT + Sequential-thinking)

AI วิเคราะห์ asset inventory แล้วสร้าง attack plan:

1. **Tech-to-Vuln Mapping** — map tech stack กับ known vulnerabilities (จาก VULN_BY_STACK database)
2. **Attack Path Generation** — สร้าง attack paths ตาม priority
3. **Gap Analysis** — ยังมีอะไรที่ไม่ได้ test บ้าง?
4. **Sequential-thinking** — คิด step-by-step ว่า attack path ไหนคุ้มค่าที่สุด

**Output:** Ordered attack plan with expected impact per path

### Phase 3: Execution Loop (Adaptive — ไม่บังคับลำดับ)

**สำคัญ:** Phases ไม่ได้ fix ลำดับ AI สามารถข้าม/กลับ/เพิ่ม phase ได้ตามสถานการณ์

```
while not done:
    # AI ตัดสินใจเองว่า下一步 ทำอะไร
    next_action = ai_decide(
        memory=memory,
        current_phase=current_phase,
        findings=findings,
        gaps=gaps
    )

    # ตัวอย่างการ flow ที่ AI เลือกเอง:
    # Recon → Planning → Execution → เจอ nothing → กลับ Recon → Execution → เจอ low bug → Escalate → Chain → Report

    result = execute(next_action)

    if result.finding:
        # Escalation mindset
        if severity == LOW or severity == MEDIUM:
            escalated = try_escalate(result)
            if escalated:
                finding = escalated

        # Chaining mindset
        related = find_related_findings(result)
        if related and len(related) >= 2:
            chain = create_attack_chain(related + [result])
            if chain.impact >= HIGH:
                finding = chain

    # AI ตัดสินใจว่า:
    # - ข้อมูลพอหรือยัง?
    # - ต้อง recon เพิ่มไหม?
    # - ต้อง replan ไหม?
    # - ควร escalate finding นี้ไหม?
    # - ควร chain findings ไหม?
    # - ควรทำต่อหรือพอแล้ว?

    update_memory(result)
    current_phase = ai_decide_next_phase()
```

**Escalation Strategy:**
- XSS → try stored XSS → try cookie theft → account takeover
- SQLi → try UNION-based → try file read → try RCE
- IDOR → try sequential IDs → try bulk extraction → try privilege escalation
- Info disclosure → combine with other findings → increase impact
- SSRF → try internal network scan → try cloud metadata → try RCE

**Chaining Strategy:**
- หา findings ที่เกี่ยวข้องกัน (เช่น อยู่ใน endpoint เดียวกัน หรือใช้ auth เดียวกัน)
- ลอง combine findings เพื่อเพิ่ม impact
- ถ้า chain ให้ impact ได้ ≥ HIGH → บันทึกเป็น chained finding

### Phase 4: Verification (Dual-Model)

ทุก finding ต้องผ่าน dual-model verification:

1. **Model A (Primary)** — ยืนยันว่า finding นี้ real (ไม่ false positive)
2. **Model B (Validator)** — ตรวจสอบ impact assessment
3. **Cross-check** — ถ้า 2 models ไม่เห็นด้วย → flag ให้ human review

### Phase 5: Reflection & Completion

ก่อนจบ mission:
1. ทบทวน findings ทั้งหมด
2. ตรวจ gaps ที่ยังไม่ได้ test
3. ตัดสินใจว่าต้อง test เพิ่มหรือพอแล้ว
4. Generate final report

## [S4] Reasoning Architecture (3 Layers)

### Layer 1: CoT Prompting (System Prompt)

**Key Insight จาก Mythos Research:** "We did not explicitly train Mythos Preview to have these capabilities. Rather, they emerged as a downstream consequence of general improvements in code, reasoning, and autonomy."

**System Prompt = Progressive Disclosure (ไม่ใช่ "สั้นลง")**

Prompt ไม่ได้สั้นลงเสมอไป แต่แบ่งเป็น layers:

**Layer A — Tool Catalog (บอกเสมอ):**
- มี tools อะไรบ้าง (Python modules + Shell commands)
- แต่ละ tool ทำอะไร
- ไม่บอกว่าต้องใช้อันไหน — ปล่อยให้ AI เลือก

**Layer B — Methodology Hints (บอกแต่ไม่บังคับ):**
- "ลอง escalate low bug ดู"
- "ลอง chain findings ดู"
- " rank targets ก่อน execute"
- AI ทำตามบ้าง ไม่ทำบ้าง — แล้วแต่ situation

**Layer C — Freedom (ไม่บอก):**
- ลำดับ phases — AI ตัดสินใจเอง
- วิธี escalation/chaining — AI คิดเอง
- Attack strategy — AI สร้างเอง

**ทำไมไม่ใช่ "prompt สั้น" เสมอ:**
- Mythos prompt สั้นเพราะมี security knowledge อยู่แล้ว
- Model เล็กต้องบอกมากกว่านั้นถึงจะรู้ว่าทำอะไร
- Progressive Disclosure ตอบโจทย์ทุก model

### Layer 2: Sequential-thinking (Built-in)

ใช้ sequential-thinking tool สำหรับ:
- วิเคราะห์ attack path ที่ดีที่สุด
- ตัดสินใจว่า下一步 ทำอะไร
- Evaluate risk/reward ของแต่ละ action
- Chain analysis — หา relationships ระหว่าง findings

### Layer 3: Reflection Loop (Post-Action)

หลังทำทุก action:
- "ผลลัพธ์นี้บอกอะไรฉัน?"
- "ฉันควรทำอะไรต่อ?"
- "มี gap ไหมที่ฉันพลาดไป?"
- "finding นี้ escalate ได้ไหม?"
- "finding นี้ chain กับตัวอื่นได้ไหม?"

## [S5] Hybrid Memory Architecture

### Layer 1: ChromaDB (Semantic Recall)
- "find similar past findings"
- "what tools worked for this tech?"
- Cross-session learning
- Vector embeddings for semantic search

### Layer 2: SQLite (Structured State)
- Mission graph, findings, ledger
- Fast queries for current state
- Token usage tracking
- Program cache

### Layer 3: Knowledge Graph (Relationships) — สำคัญที่สุด

```
┌─────────────────────────────────────────────────────────┐
│                   KNOWLEDGE GRAPH                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  [Asset] ──has──▶ [Finding] ──found_by──▶ [Tool]        │
│     │                  │                    │            │
│     │                  │                    │            │
│     ▼                  ▼                    ▼            │
│  [Endpoint]      [Vuln Class]         [Technique]       │
│     │                  │                    │            │
│     │                  │                    │            │
│     └──────── chains_to ────────────────────┘            │
│                                                          │
│  Nodes:                                                 │
│  - Asset (subdomain, IP, endpoint)                      │
│  - Finding (vulnerability with severity)                 │
│  - Tool (scanner, technique used)                        │
│  - Vuln Class (XSS, SQLi, IDOR, etc.)                   │
│  - Attack Path (sequence of findings)                    │
│                                                          │
│  Edges:                                                 │
│  - Asset → has → Finding                                 │
│  - Finding → found_by → Tool                             │
│  - Finding → belongs_to → Vuln Class                     │
│  - Finding → chains_to → Finding                         │
│  - Attack Path → consists_of → [Finding]                 │
│  - Tool → works_on → Vuln Class                          │
│  - Asset → related_to → Asset                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Knowledge Graph ช่วย AI:**
- เห็น relationships ระหว่าง findings
- รู้ว่า tools ไหน work กับ vuln class ไหน
- Chain findings ได้แม่นยำขึ้น
- Predict attack paths ที่น่าจะ work

**ตัวอย่าง Usage:**

```python
# AI query knowledge graph
kg.find_related_findings(finding_xss)
# → [finding_idor, finding_info_disclosure]

kg.get_tools_for_vuln_class("XSS")
# → [active_fuzzer, custom_xss_scanner, dalfox]

kg.get_attack_paths(asset="/api/user")
# → [path1: XSS→CookieTheft→Takeover, path2: IDOR→BulkExtract]

kg.can_chain(finding_xss, finding_idor)
# → True: XSS gives access token, IDOR extracts data
```

### Layer 4: Context Window (Active Reasoning)
- Current findings summary
- Next actions
- Gaps identified
- Compressed for efficiency

### Layer 5: Checkpoint (Resume Capability)
- Full mission state snapshot
- Resume from any point
- Cross-session persistence

## [S6] How AI Executes Actions

### AI ตัดสินใจเอง — ไม่บังคับ execution method

**Key Principle:** ปล่อยให้ AI เลือกวิธี execute เองตาม situation

**Python modules** เหมาะเมื่อ:
- ต้องการ structured output (dataclass, dict)
- ต้องการ speed (ไม่ต้อง spawn subprocess)
- ต้อง offline execution

**Shell commands** เหมาะเมื่อ:
- ต้องใช้ external tools (nuclei, ffuf, subfinder, nmap)
- ต้อง chain commands (pipes, redirects)
- ต้อง flexibility (AI คิด command เอง)
- Smart models (Mythos) ใช้ shell ได้คุ้มกว่า

**Hybrid** เหมาะเมื่อ:
- Python recon → shell scan → Python analysis
- AI เลือก combination ที่เหมาะสมที่สุด

**ไม่บอก AI ว่าต้องใช้วิธีไหน** — ปล่อยให้มันตัดสินใจเอง

### Governance Change: Confirmation Dialog (ไม่ Block)

**เดิม:** Governance block คำสั่ง DESTRUCTIVE ทันที
**ใหม่:** แสดง confirmation dialog ถามผู้ใช้ (เหมือน question tool)

```
┌─────────────────────────────────────────┐
│  [GOVERNANCE] Command Requires Approval │
├─────────────────────────────────────────┤
│                                         │
│  Command: sudo apt install nuclei       │
│  Risk Level: PRIVILEGED                 │
│  Purpose: Install vulnerability scanner │
│                                         │
│  [Allow]  [Allow Auto]  [Deny]         │
│                                         │
│  ─────────────────────────────────────  │
│  If approved, show sudo password input: │
│  ┌─────────────────────────────────┐    │
│  │ Password: ••••••••              │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

**Flow ใหม่:**
1. AI ตัดสินใจจะ run command
2. แสดง confirmation dialog ถามผู้ใช้
3. ถ้า Allow → execute (ถ้าต้อง sudo → แสดง password input)
4. ถ้า Allow Auto → execute + จำ choice สำหรับ session นี้
5. ถ้า Deny → AI เลือก alternative action

**Tool Installation Flow:**
1. AI ต้องการ install tool (เช่น nuclei)
2. แสดง confirmation: "ต้องการ install nuclei ผ่าน apt?"
3. ถ้า Allow → แสดง sudo password input → install
4. ถ้า Deny → AI ใช้ Python alternative (เช่น python_recon.py)

### Adaptive Phase Transitions

AI ไม่ได้ถูกบังคับให้ทำตามลำดับ phases ตายตัว:

```
Scenario 1: Recon → Execution → เจอ nothing
    → AI เลือก: กลับ Recon (หาข้อมูลเพิ่ม)

Scenario 2: Recon → Planning → Execution → เจอ low bug
    → AI เลือก: Escalate (ลอง exploit ต่อ)

Scenario 3: Execution → เจอหลาย bugs
    → AI เลือก: Chain (รวม bugs)

Scenario 4: Execution → data พอแล้ว
    → AI เลือก: Report

Scenario 5: Planning → ไม่รู้จะทำอะไร
    → AI เลือก: Recon (หาข้อมูลเพิ่ม)
```

**Key principle:** AI เป็นผู้ตัดสินใจทุกอย่าง ไม่ใช่ code บังคับ

### Scanner Modules (from existing codebase)
- `ssrf_scanner.py` — SSRF testing
- `ssti_scanner.py` — Template injection
- `xxe_scanner.py` — XML external entity
- `deserialization_scanner.py` — Insecure deserialization
- `graphql_scanner.py` — GraphQL vulnerabilities
- `race_condition_tester.py` — Race conditions
- `cors_checker.py` — CORS misconfiguration
- `jwt_tester.py` — JWT security
- `logic_flaw_engine.py` — Business logic flaws
- `supply_chain_analyzer.py` — Dependency vulnerabilities
- `active_fuzzer.py` — XSS/SQLi fuzzing
- `waf_detector.py` — WAF detection + evasion
- `python_recon.py` — Pure Python recon (no external tools)

### External Tools (via Tool Registry)
- subfinder, httpx, nuclei, ffuf, dalfox, etc.
- Governance-gated execution

### New Modules Needed
- `escalation_engine.py` — Logic for escalating low→high findings
- `chaining_engine.py` — Logic for combining findings into chains
- `verification_engine.py` — Dual-model verification
- `adaptive_planner.py` — Dynamic attack plan updates

## [S7] Report Structure

### Professional Report (Markdown/HTML/PDF)
1. Executive Summary (severity breakdown, key findings)
2. Attack Chain Diagrams (visual chains)
3. Findings by Severity (Critical → High → Medium → Low → Info)
4. Detailed Evidence (for each finding: description, PoC, impact, remediation)
5. Methodology (what was tested, what wasn't)
6. Appendices (raw data, tool output)

### Attack Chain Visualization
- Visual diagram แสดงว่า bugs เชื่อมกันอย่างไร
- Example: IDOR (Low) + Info Disclosure (Low) → Full Account Takeover (Critical)

### Raw Findings Data (JSON)
- Machine-readable format สำหรับ integration กับ tool อื่น

## [S8] Cost Awareness

### Token Usage Tracking
```
Mission Cost Dashboard:
├── Tokens used: 125,000 / 500,000 (25%)
├── Estimated cost: $3.75 / $15.00
├── Findings so far: 12 (3 critical, 4 high, 5 medium)
└── Cost per finding: $0.31
```

### Budget Limits
```yaml
cost_limits:
  max_tokens_per_mission: 500000
  max_cost_per_mission: 50.00
  max_steps: 200
  alert_at_percent: 80  # warn when 80% budget used
```

### Cost Optimization
- AI รู้ budget → เลือก actions ที่คุ้มค่า
- ถ้า budget เกือบหมด → focus กับ findings ที่มีอยู่แล้ว instead of scanning เพิ่ม
- Track cost per tool → รู้ว่า tool ไหนคุ้มค่า

## [S9] Adaptive to Model Intelligence

### The Problem

ถ้าเราเขียน rules แข็งเกินไป:
- **Smart models (Mythos)** — โดน constrain, ใช้ความฉลาดได้ไม่เต็มที่
- **Smaller models** — ไม่รู้ว่ามี tools อะไร, ทำอะไรไม่ถูก

### The Solution: Progressive Disclosure

```
┌─────────────────────────────────────────────────────┐
│              System Prompt Structure                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  [Layer 1: Tool Descriptions]  ← บอกเสมอ           │
│  - มี tools อะไรบ้าง                                 │
│  - แต่ละ tool ทำอะไร                                 │
│  - ใช้ Python modules เป็นหลัก                       │
│                                                     │
│  [Layer 2: Methodology Hints]  ← บอกแต่ไม่บังคับ    │
│  - "ลอง escalate ดู" (แต่ไม่บังคับ)                  │
│  - "ลอง chain ดู" (แต่ไม่บังคับ)                     │
│  - "ถ้า data ไม่พอ recon เพิ่ม"                       │
│                                                     │
│  [Layer 3: Freedom]  ← ไม่บอก                        │
│  - ลำดับ phases — AI ตัดสินใจเอง                     │
│  - วิธี escalation — AI หา way เอง                   │
│  - วิธี chaining — AI คิด strategy เอง               │
│  - Attack methodology — AI สร้างเอง                   │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Model-Specific Behavior

**Small Models (GPT-3.5, Haiku, etc.):**
- ใช้ tool descriptions เป็นหลัก
- ทำตาม methodology hints ค่อนข้างตรง
- Escalation/chaining ทำได้บ้างถ้ามี hints

**Medium Models (GPT-4, Sonnet, etc.):**
- ใช้ tool descriptions + methodology hints
- เริ่ม innovate บางส่วน
- Escalation/chaining ทำได้ดี

**Smart Models (Mythos, Opus, etc.):**
- ใช้ tool descriptions เท่านั้น
- คิด methodology เอง
- Escalation/chaining ทำได้ดีเยี่ยม
- หา zero-days ได้

### What We DON'T Do

1. **ไม่บังคับลำดับ phases** — AI ข้าม/กลับ/เพิ่ม phase ได้
2. **ไม่บังคับวิธี escalation** — AI หา way เอง
3. **ไม่บังคับวิธี chaining** — AI คิด strategy เเอง
4. **ไม่บังคับ tool selection** — AI เลือก tool เอง
5. **ไม่บังคับ attack methodology** — AI สร้างเองตาม context

### What We DO

1. **บอกว่ามี tools อะไร** — ให้ model เลือกใช้
2. **บอก methodology hints** — ให้ model ลองทำ (ไม่บังคับ)
3. **ให้ governance framework** — ให้ model รู้ bound แต่ไม่ constrain
4. **ให้ memory system** — ให้ model จำและเรียนรู้

### Model Configuration
```yaml
vuln_finder:
  primary_model: "claude-3-opus"      # สำหรับ planning + execution
  validator_model: "gpt-4"            # สำหรับ verification
  reasoning_model: "claude-3-opus"    # สำหรับ sequential-thinking

  strategy: "adaptive"                # adaptive | systematic | hybrid
  max_steps: 100                      # จำนวน steps สูงสุดต่อ mission
  verification: "dual-model"          # dual-model | single | none

  escalation:
    enabled: true
    max_escalation_depth: 3           # ลอง escalate กี่ครั้ง

  chaining:
    enabled: true
    min_findings_to_chain: 2          # ต้องมี findings กี่ตัวถึงจะ chain
```

## [S10] Implementation Phases

### Phase 1: Core Engine (Week 1-2)
- Rewrite `agent_brain.py` process_query loop
- Implement adaptive planning with memory
- Add escalation mindset logic
- Add chaining mindset logic

### Phase 2: Reasoning Layers (Week 2-3)
- Integrate CoT prompting in system prompt
- Add sequential-thinking integration
- Implement reflection loop

### Phase 3: Verification (Week 3-4)
- Implement dual-model verification
- Add false positive detection
- Cross-model validation

### Phase 4: Reporting (Week 4-5)
- Professional report generation (MD/HTML/PDF)
- Attack chain visualization
- Raw data export

### Phase 5: Testing & Polish (Week 5-6)
- Unit tests for each module
- Integration tests
- Performance optimization
- Bug fixes from codebase analysis

## [S11] Success Criteria

1. AI สามารถ finding vulnerabilities ได้ autonomous โดยไม่ต้อง human intervention
2. Low-severity findings ถูก escalate ให้กลายเป็น high/critical ได้อย่างน้อย 30% ของ cases
3. Multiple low findings ถูก chain ให้กลายเป็น critical impact ได้
4. False positive rate < 10% หลัง dual-model verification
5. Report มี professional quality พร้อม attack chain diagrams
6. สามารถ resume mission ที่ค้างไว้ได้
