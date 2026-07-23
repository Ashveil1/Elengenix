# LLM Built-in Reasoning vs External Reasoning: Do We Need CoT on Top?

**Date:** 2026-07-17
**Sources:** 33 findings from 25+ papers, official docs from OpenAI/Anthropic

---

## Executive Summary

**คำตอบสั้น:** 
- **CoT prompting บน reasoning models = ไม่จำเป็น และอาจทำให้แย่ลง**
- **External reasoning architecture = ยังจำเป็นมาก และได้ผลจริง**
- **ไม่ใช่ LLM คิดไม่ดี แต่ LLM คิดคนเดียวไม่พอ**

---

## 1. LLM Reasoning Models มี CoT อยู่แล้ว

### วิธีการทำงานของ Reasoning Models

| Model | Internal Mechanism | Control |
|-------|-------------------|---------|
| **OpenAI o1/o3/o4/o5** | Hidden "reasoning tokens" | `reasoning_effort` parameter |
| **Claude (extended thinking)** | `thinking` content blocks | `budget_tokens` parameter |
| **Gemini (thinking)** | Hidden thinking tokens | API parameters |
| **DeepSeek-R1** | Emergent reasoning via RL | Self-learned |

### OpenAI พูดชัดเจน

> "**Avoid chain-of-thought prompts**: Since these models perform reasoning internally, prompting them to 'think step by step' or 'explain your reasoning' is unnecessary."
> 
> -- [OpenAI Reasoning Best Practices](https://platform.openai.com/docs/guides/reasoning-best-practices)

### หลักฐานจาก Benchmark

| Model | CoT Prompting? | MATH Score |
|-------|---------------|------------|
| GPT-4o (non-reasoning) | With CoT | ~76.6% |
| o1-preview (reasoning) | No CoT | ~94.8% |
| DeepSeek-R1 (reasoning) | No CoT | ~97.3% |

**Conclusion:** Reasoning models ชนะ non-reasoning + CoT อย่างมีนัยสำคัญ

---

## 2. External CoT บน Reasoning Models = ไม่จำเป็น

### สิ่งที่เกิดขึ้นเมื่อใส่ CoT บน Reasoning Model

```
ปัญหา:
1. Model คิดอยู่แล้ว内部 → ใส่ CoT ซ้ำ = waste tokens
2. CoT อาจ constrain model's natural reasoning flow
3. ได้ผลแย่ลงในบางกรณี
```

### สิ่งที่ได้ผลจริงบน Reasoning Models

| วิธี | ผลลัพธ์ |
|------|---------|
| ✅ Provide domain context | เพิ่ม accuracy |
| ✅ Add constraints | ลด hallucination |
| ✅ Set success criteria | ปรับปรุง focus |
| ✅ Few-shot examples | ปรับปรุง format |
| ❌ "Think step by step" | ไม่ช่วย หรือทำให้แย่ลง |

---

## 3. แต่ External Reasoning Architecture = ยังจำเป็นมาก

### ทำไม LLM คนเดียวไม่พอ

**ปัญหา 6 ข้อของ Pure LLM Reasoning:**

| ปัญหา | หลักฐาน |
|--------|---------|
| **Myopic Planning** | LLMs ignore deep lookahead nodes (Chen 2026) |
| **Inconsistency** | Same prompt -> different reasoning chains (ZERO-APT 2026) |
| **Hallucination** | Fabricate causal links that violate OS physics (HunterAgent 2026) |
| **Long-horizon failure** | End-to-end pipelines only 31% success (PentestEval) |
| **State management** | Context window limits cause lost state (Cochise 2026) |
| **No backtracking** | Can't explore multiple paths simultaneously |

### ระบบ External Reasoning ที่พิสูจน์แล้วว่าได้ผล

| System | External Component | Performance | vs Pure LLM |
|--------|-------------------|-------------|-------------|
| **CHECKMATE** | Classical PDDL planner | +20% success, -50% cost | vs Claude Code |
| **ZERO-APT** | Architectural enforcement | 79% success | vs PentestGPT 39% |
| **G-CTR** | Symbolic game theory | 2x success, 5.2x variance reduction | vs neural only |
| **Pen-Strategist** | CNN classifier for action selection | CNN beats LLMs by 28% | for step prediction |
| **NeuroLog** | Datalog + SMT verification | $0.005 per extraction | vs pure LLM |
| **Code-Augur** | Guided fuzzer | 22 new vulns found | vs Claude Mythos |

---

## 4. คำตอบสำหรับ Elengenix

### สิ่งที่ไม่ต้องทำ

```
❌ ใส่ "Let's think step by step" บน reasoning model
❌ เพิ่ม CoT prompting บน o1/o3/Claude thinking
❌ สร้าง CoT engine ที่เลียนแบบ reasoning model
```

### สิ่งที่ต้องทำ

```
✅ ใช้ reasoning model (o3, Claude thinking) เป็น default
✅ เพิ่ม external planner สำหรับ long-horizon planning
✅ เพิ่ม symbolic verifier สำหรับ causal consistency
✅ แยก planning จาก execution
✅ ใช้ CNN/classifier สำหรับ action selection
✅ สร้าง architectural constraints ไม่ใช่ prompt constraints
```

### Architecture ที่แนะนำ

```
┌─────────────────────────────────────────────────┐
│                  Elengenix Phase 2               │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌─────────────┐    ┌─────────────────────┐    │
│  │   LLM       │    │  External Planner   │    │
│  │ (o3/Claude) │◄──►│  (PDDL/Classical)   │    │
│  │  Reasoning  │    │  Long-horizon plan  │    │
│  └─────────────┘    └─────────────────────┘    │
│         │                      │                │
│         ▼                      ▼                │
│  ┌─────────────┐    ┌─────────────────────┐    │
│  │  Symbolic   │    │  CNN Classifier     │    │
│  │  Verifier   │    │  Action Selection   │    │
│  │ (Causal OK?)│    │  (Not LLM)          │    │
│  └─────────────┘    └─────────────────────┘    │
│                                                 │
└─────────────────────────────────────────────────┘

Key Insight: LLM for hypothesis generation
             External for verification/selection
```

---

## 5. สรุป

| คำถาม | คำตอบ |
|--------|--------|
| LLM มี CoT ในตัวแล้วไหม? | **ใช่** -- reasoning models มี internal reasoning |
| ใส่ CoT บน reasoning model ได้ไหม? | **ไม่ควร** -- อาจทำให้แย่ลง |
| External reasoning จำเป็นไหม? | **ใช่** -- สำหรับ verification, planning, consistency |
| Elengenix ควรทำอะไร? | **ใช้ reasoning model + external planner + symbolic verifier** |

**คำตอบสั้น:** อย่าใส่ CoT บน reasoning model แต่ให้เพิ่ม external reasoning architecture สำหรับสิ่งที่ LLM ทำไม่ได้ (planning, verification, consistency)

---

## Sources

1. OpenAI. "Reasoning Models Documentation." https://platform.openai.com/docs/guides/reasoning
2. OpenAI. "Reasoning Best Practices." https://platform.openai.com/docs/guides/reasoning-best-practices
3. Anthropic. "Extended Thinking Documentation." https://docs.anthropic.com/en/docs/build-with-claude/extended-thinking
4. DeepSeek-AI. "DeepSeek-R1." arXiv:2501.12948, Nature vol. 645
5. Snell et al. (2024). "Scaling LLM Test-Time Compute." arXiv:2408.03314
6. Muennighoff et al. (2025). "s1: Simple Test-Time Scaling." arXiv:2501.19393
7. Chen et al. (2026). "Extracting Search Trees from LLM Reasoning Traces." arXiv:2605.06840
8. Wang et al. (2025). "CHECKMATE: Automated Penetration Testing with Classical Planning." arXiv:2512.11143
9. Zheng & Zhu (2026). "ZERO-APT." arXiv:2606.05567
10. Mayoral-Vilches et al. (2026). "Towards Cybersecurity Superintelligence." arXiv:2601.14614
11. Ginige et al. (2026). "Pen-Strategist." arXiv:2605.04499
12. Happe & Cito (2026). "Cochise: A Reference Harness." arXiv:2605.11671
13. Rawat (2026). "NeuroLog." arXiv:2606.00669
14. Luo et al. (2026). "Code-Augur." arXiv:2606.18619
15. Bao et al. (2026). "DIG." arXiv:2606.13037
