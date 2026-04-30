# Autonomous Bug Bounty Hunter - System Overview

## Vision
"AI หาเงินให้คุณอัตโนมัติ - เข้า AI บอกว่าอยากได้เงิน เดี๋ยว AI จัดการให้ทั้งหมด"

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    User Interface Layer                          │
├─────────────────────────────────────────────────────────────────┤
│  CLI (elengenix ai)  │  Telegram Gateway  │  Web Dashboard (future) │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Autonomous Controller                          │
│              (Mission Planner + State Manager)                    │
├─────────────────────────────────────────────────────────────────┤
│  • HackerOne Discovery  • Target Prioritizer  • Token Manager     │
│  • Pause/Resume System  • Progress Tracker    • Alert System      │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Intelligence Layer                             │
├─────────────────────────────────────────────────────────────────┤
│  HackerOne API    │  Public Scraper    │  News Monitor           │
│  (with token)     │  (token-free)      │  (Twitter/Reddit/HN)    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Execution Layer                                │
├─────────────────────────────────────────────────────────────────┤
│  Reconnaissance → Vulnerability Scan → Exploit Test → Report    │
│  (With pause/resume between phases, smart token usage)          │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                    Notification Layer                             │
├─────────────────────────────────────────────────────────────────┤
│  CLI Real-time  │  Telegram Alerts  │  Email Reports (future)    │
└─────────────────────────────────────────────────────────────────┘
```

## Phase Breakdown

### Phase 1: Intelligence Discovery (2-3 days)
**Goal:** Find profitable programs automatically

**Components:**
1. **HackerOne API Client**
   - Endpoint: `https://api.hackerone.com/v1/hackers/programs`
   - Filter: `offers_bounties: true`, `state: open`
   - Sort: By bounty range (high to low)
   - Cache: 6 hours

2. **Public Scraper (token-free)**
   - URL: `https://hackerone.com/bug-bounty-programs`
   - Extract: Program name, scope, rewards, response time
   - Rate limit: 1 request/min (respectful)

3. **News Monitor**
   - Reddit: r/bugbounty hot posts
   - Twitter: #bugbounty #hackerone trending
   - Hacker News: "Show HN" security tools
   - Filter: Programs mentioned with positive sentiment

**Output:** Ranked list of programs with:
- Potential reward range
- Response time score
- Scope clarity score
- Public interest score

---

### Phase 2: Smart Scanner with Token Management (3-4 days)
**Goal:** Scan efficiently without burning tokens

**Components:**
1. **Token Manager**
   - Track usage per minute/hour/day
   - Pause when approaching limit
   - Alert at 50%, 75%, 90%
   - Auto-switch AI models if primary exhausted

2. **Pause/Resume System**
   - Save state: `~/.config/elengenix/missions/{mission_id}.json`
   - State includes: Target, phase, findings, tokens used
   - Resume from exact point
   - Auto-pause after N hours without findings

3. **Smart Scanning Strategy**
   - Phase 1: Quick recon (cheap, fast)
   - Phase 2: Targeted scanning (medium cost)
   - Phase 3: Deep testing (expensive, only if promising)
   - Checkpoint after each phase

**User Controls:**
- Pause: `p` key or Telegram `/pause`
- Resume: Telegram `/resume {mission_id}`
- Status: Telegram `/status`

---

### Phase 3: Telegram Bridge (2-3 days)
**Goal:** Seamless Telegram integration

**Components:**
1. **Telegram Bot Extensions**
   - `/bounty` - Start autonomous bounty hunt
   - `/status {id}` - Check mission progress
   - `/pause {id}` - Pause mission
   - `/resume {id}` - Resume mission
   - `/findings {id}` - View findings
   - `/programs` - List top programs

2. **Notification Templates**
   - Mission started
   - Phase completed
   - Finding discovered (URGENT)
   - Token warning
   - Mission paused (timeout)
   - Mission completed

3. **Real-time Sync**
   - CLI activity → Telegram
   - Telegram commands → CLI
   - Works in both directions

---

### Phase 4: Integration & Polish (2-3 days)
**Goal:** Everything works together smoothly

**Components:**
1. **Mission Dashboard**
   - Active missions
   - Historical missions
   - Token usage charts
   - Bounty predictions

2. **Safety Features**
   - Scope validation before scan
   - Rate limiting per program
   - Respect out-of-scope lists
   - Legal compliance check

3. **Report Generation**
   - Auto-generate on finding
   - Professional format for HackerOne
   - Screenshots + evidence
   - CVSS scoring

## Database Schema (SQLite)

```sql
-- Missions table
CREATE TABLE missions (
    id TEXT PRIMARY KEY,
    program_name TEXT,
    program_url TEXT,
    target_scope TEXT,
    status TEXT, -- pending, running, paused, completed, failed
    current_phase TEXT, -- discovery, recon, scanning, reporting
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    tokens_used INTEGER,
    findings_count INTEGER,
    estimated_bounty INTEGER,
    state_json TEXT -- Full state for resume
);

-- Findings table
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    vulnerability_type TEXT,
    severity TEXT, -- critical, high, medium, low
    target_endpoint TEXT,
    description TEXT,
    evidence TEXT, -- JSON: screenshots, payloads, responses
    cvss_score REAL,
    bounty_estimate INTEGER,
    created_at TIMESTAMP,
    reported BOOLEAN
);

-- Token usage table
CREATE TABLE token_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT,
    provider TEXT, -- openai, anthropic, etc.
    tokens_input INTEGER,
    tokens_output INTEGER,
    cost_usd REAL,
    timestamp TIMESTAMP
);

-- Programs cache
CREATE TABLE programs (
    id TEXT PRIMARY KEY,
    name TEXT,
    platform TEXT, -- hackerone, bugcrowd, etc.
    offers_bounties BOOLEAN,
    min_bounty INTEGER,
    max_bounty INTEGER,
    scope_json TEXT,
    response_time_hours INTEGER,
    is_public BOOLEAN,
    cached_at TIMESTAMP
);
```

## User Flow Examples

### Flow 1: CLI Autonomous Hunt
```bash
$ elengenix ai

> หาโปรแกรม HackerOne จ่ายตังดีๆ แล้วช่วยสแกนหาช่องโหว่ให้หน่อย
[AI] กำลังดึงโปรแกรมจาก HackerOne...
[AI] พบ 3 โปรแกรมที่น่าสนใจ:
   1. Stripe ($500-$50,000) - Response 24h
   2. Shopify ($500-$30,000) - Response 48h
   3. Twitter/X ($100-$20,000) - Response 72h

[AI] เลือกโปรแกรมไหน? (หรือให้ฉันเลือกอัตโนมัติ)

> เลือกอัตโนมัติเลย
[AI] เลือก Shopify - scope ชัด + reward ดี
[AI] เริ่มสแกน: api.shopify.com

[MISSION-2024-abc123] Phase 1/4: Reconnaissance
├─ Finding subdomains... 12 found
├─ Finding endpoints... 45 found  
├─ Tech stack: GraphQL, Ruby on Rails
└─ Checkpoint saved. Tokens used: 2,400

[MISSION-2024-abc123] Phase 2/4: Vulnerability Scan
├─ Testing BOLA... 
├─ Testing SQLi...
├─ Testing XSS... 2 potential found
└─ Checkpoint saved. Tokens used: 8,200

[MISSION-2024-abc123] Phase 3/4: Exploit Verification
├─ Verifying XSS #1... Confirmed (Stored XSS)
├─ Verifying XSS #2... False positive
└─ Finding: Stored XSS in admin panel
    Severity: High
    Endpoint: /admin/users/bulk-edit
    Bounty Estimate: $1,500 - $3,000

[AI] สรุปผลส่ง Telegram แล้ว
[AI] ต้องการเขียนรายงานส่ง HackerOne เลยไหม?

> เขียนเลย
[AI] กำลัง generate report...
[AI] Report saved: reports/shopify-xss-2024-001.md
[AI] ส่งไป HackerOne อัตโนมัติ? (ต้องการ API key)
```

### Flow 2: Telegram Control
```
User: /bounty
Bot:  เริ่มล่า bounty อัตโนมัติ
Bot: กำลังหาโปรแกรมจาก HackerOne...
Bot: พบ 5 โปรแกรมน่าสนใจ:
    1. Company A - $500-10k
    2. Company B - $1k-50k ⭐
    3. Company C - $100-5k

User: 2
Bot:  เลือก Company B
Bot:  Mission #12345 เริ่มแล้ว
Bot: Target: api.company.com
Bot: สถานะ: Reconnaissance (Est. 10 min)

[10 minutes later]
Bot:  Phase 1 เสร็จแล้ว
Bot: พบ 8 subdomains, 32 endpoints
Bot: กำลังสแกนช่องโหว่...

[30 minutes later]
Bot:  สแกนมา 30 นาทีแล้วยังไม่เจอ
Bot: จะหยุดพักไหม? (กด /resume 12345 เพื่อทำต่อ)

User: /resume 12345
Bot:  กลับมาทำต่อ...

[5 minutes later]
Bot:  พบช่องโหว่!
Bot: Type: IDOR in order endpoint
Bot: Severity: High
Bot: Bounty Estimate: $2,000 - $5,000
Bot: ดูรายละเอียด: /findings 12345
```

## Technical Stack

```
Core: Python 3.11+
Database: SQLite (simple, portable)
AI: UniversalAIClient (multi-provider)
Scraping: playwright + beautifulsoup4
Telegram: python-telegram-bot
Monitoring: threading + asyncio
Storage: JSON (state) + SQLite (data)
```

## Token Cost Estimation

| Phase | Tokens | Cost (GPT-4) | Duration |
|-------|--------|--------------|----------|
| Discovery | 5,000 | $0.15 | 5 min |
| Recon | 20,000 | $0.60 | 10 min |
| Scanning | 50,000 | $1.50 | 20 min |
| Deep Test | 100,000 | $3.00 | 30 min |
| Report | 10,000 | $0.30 | 5 min |
| **Total** | **185,000** | **$5.55** | **70 min** |

**Safety Limits:**
- Pause after $5 spent
- Daily limit: $20
- Alert at 50% budget

## Implementation Order

**Week 1:**
- Day 1-2: HackerOne API + Public Scraper
- Day 3-4: Program Prioritizer (scoring algorithm)
- Day 5: Integration test

**Week 2:**
- Day 1-2: Token Manager
- Day 3-4: Pause/Resume System
- Day 5: Smart Scanner integration

**Week 3:**
- Day 1-2: Telegram Bridge
- Day 3-4: Notification system
- Day 5: End-to-end testing

**Week 4:**
- Day 1-2: Polish + Bug fixes
- Day 3-4: Documentation
- Day 5: Release

## Success Metrics

- User can say "หาเงินให้หน่อย" and AI handles rest
- Average time to first finding: < 2 hours
- Token efficiency: <$10 per finding
- User satisfaction: Can control via Telegram anytime
- Safety: 0 unauthorized scans (scope validation)

## Risk Mitigation

1. **Token Burn:** Strict limits + auto-pause
2. **Scope Violation:** Validate before every scan
3. **Legal Issues:** Clear authorization prompts
4. **False Positives:** Human verification before report
5. **Rate Limiting:** Respectful scraping (1 req/min)
