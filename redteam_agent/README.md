# Red Team Agent Framework

A lightweight, reasoning-first AI Red Team framework. Built from scratch with no framework bloat (no CrewAI, no LangChain). The AI thinks, plans, and executes shell commands directly on your system.

## Structure

```
redteam_agent/
├── __init__.py       # Package marker
├── config.py         # Loads API keys from .env
├── llm.py            # Multi-provider LLM client (Gemini, OpenAI, NVIDIA, Anthropic, Ollama)
├── governance.py     # Safety gate — blocks destructive commands
├── executor.py       # Runs shell commands, saves raw logs to logs/raw/
├── state.py          # Shared blackboard (logs/mission_state.json)
├── prompts.py        # System prompts for Strategist and Specialist agents
└── main.py           # CLI entry point and agent loop
```

## How to Run

```bash
python3 run.py
```

Or via module:
```bash
python3 -m redteam_agent.main
```

## How It Works

1. **You type an objective** (e.g. `scan 10.0.0.1 for open ports and identify services`)
2. **Strategist** reads the objective and generates a task list
3. **Specialist** executes tasks one-by-one via shell commands, updates discovered intel
4. **Strategist** replans every 5 cycles based on new findings
5. Loop continues until mission is complete or you interrupt

## Providers

Set `ACTIVE_AI_PROVIDER` in `.env` to switch providers:
- `nvidia` — NVIDIA Nemotron (default)
- `gemini` — Google Gemini
- `openai` — OpenAI GPT
- `anthropic` — Anthropic Claude
- `custom` — Any OpenAI-compatible API (set `CUSTOM_API_BASE` + `CUSTOM_API_KEY`)
- `ollama` — Local Ollama

## Safety

- **Blocked automatically**: `rm -rf`, `shred`, `dd if=`, `mkfs`, `halt`, fork bombs
- **Requires your approval**: `sudo`, `apt install`, `pip install`
- **Runs freely**: everything else

## Logs

- `logs/raw/` — Full output of every command
- `logs/mission_state.json` — Current blackboard state (tasks, intel, history)

## Customizing Behavior

Edit `redteam_agent/prompts.py` to change how agents think. The Strategist controls task planning, the Specialist controls execution reasoning.
