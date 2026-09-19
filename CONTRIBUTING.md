# Contributing to Elengenix

Thank you for your interest in contributing to Elengenix.

## Project Structure

```
Elengenix/
  main.py                  # CLI entry point and command router
  elengenix/               # Canonical package
    agent/                 # VulnAgent (true AI agent) + memory + skills
    chat/                  # Interactive chat agent (brain, agent, orchestrator)
    scanning/              # Scan context, decision engine, scan loop
    reports/               # Report generation (Markdown, HTML, PDF, CVSS)
    scope.py               # Target validation & scope
    governance.py          # Governance layer
    brain.py               # Planning engine
    loop.py                # Main agent loop
    api/ auth/ graphql/    # API server, sessions, GraphQL
  mcp/                     # Model Context Protocol integration
  cli.py equivalents:      # see cli/ below
  cli/                     # Interactive CLI, TUI, wizard, doctor, ui_components
  integrations/bot.py      # Telegram bot gateway
  tools/                   # Security tool modules (dependency_manager, menus)
  commands/                # CLI command handlers
  tui/                     # Textual TUI application
  prompts/                 # AI system prompts
  knowledge/               # Methodology documentation
  tests/                   # Unit, integration, and brutal test suites
  data/                    # Runtime data (logs, state, database)
```

Generated reports live under `~/.elengenix/reports/` (not in the repo).

## Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd Elengenix

# Development install (editable, includes test deps)
pip install -e ".[dev]"

# Configure your API key
echo "GEMINI_API_KEY=your-key-here" >> .env

# Verify installation
elengenix doctor
# or:
python3 main.py doctor
```

## Code Standards

### Style Rules

- **Python 3.10+** required
- **4-space indentation** everywhere (no tabs, no 2-space)
- **No emoji** in any terminal output, log messages, or comments
- Use text markers: `[OK]`, `[FAIL]`, `[WARN]`, `[INFO]`, `[RUN]`, `[SKIP]`
- Use `rich` library for all terminal UI (panels, tables, spinners)

### UI Components

All modules must import from `cli/ui_components.py` instead of creating their own:

```python
# Correct
from cli.ui_components import console, print_success, print_error

# Incorrect
console = Console()  # Do not create separate instances
```

### Docstrings

Every module, class, and public function must have a docstring:

```python
def scan_target(target: str, timeout: int = 600) -> dict:
    """Run a security scan on the specified target.

    Args:
        target: Domain name or IP address.
        timeout: Maximum scan duration in seconds.

    Returns:
        Dictionary with 'findings', 'status', and 'report_path' keys.
    """
```

### Security

- **Never use `shell=True`** in `subprocess` calls
- **Always validate targets** before passing to external tools
- **Never store API keys** in `config.yaml` -- use `.env` file
- **Sanitize all user input** before shell execution

### Logging

Use structured logging with the module-specific logger:

```python
import logging
logger = logging.getLogger("elengenix.module_name")

logger.info("[OK] Operation completed")
logger.error("[FAIL] Operation failed: %s", error)
logger.warning("[WARN] Potential issue: %s", detail)
```

## Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
python3 -m pytest tests/ -v

# Run a specific test
python3 -m pytest tests/test_security.py -v
```

## Configuration

| File | Purpose | Git tracked? |
|------|---------|:---:|
| `config.yaml.example` | Template configuration | Yes |
| `config.yaml` | Active configuration (no secrets) | No |
| `.env.example` | Template for API keys | Yes |
| `.env` | Actual API keys | No |

## Commit Messages

Use clear, descriptive commit messages:

```
fix: resolve asyncio crash in llm_client.py
feat: add gau and ffuf to dependency manager
docs: update CONTRIBUTING.md with code standards
refactor: extract command handlers from main.py
```

## Questions?

Open an issue on the repository or contact the maintainers.
