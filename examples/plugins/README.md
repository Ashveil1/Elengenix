# Elengenix Plugin SDK

Build your own tools, commands, AI providers, and finding pipelines for Elengenix.

## Quick Start

### 1. Create a plugin folder

```bash
mkdir -p ~/.elengenix/plugins/my_plugin
cd ~/.elengenix/plugins/my_plugin
```

### 2. Create the manifest (`plugin.yaml`)

```yaml
name: my_plugin                    # Unique slug (lowercase, underscores)
version: 1.0.0                     # Semver
author: Your Name <you@example.com>
description: One-line summary
sdk_version: "1.0.0"
entry_point: __init__.py
capabilities:                      # What your plugin needs
  - network                        # Can make HTTP requests
  # - filesystem                  # Can read/write FS
  # - subprocess                  # Can spawn processes
  # - secrets                     # Can read API keys
  # - ai_api                      # Calls AI providers
dependencies: []                   # pip packages (auto-installed)
enabled: true
tags:
  - recon
license: MIT
```

### 3. Create the entry point (`__init__.py`)

```python
from tools.ecosystem import ToolResult

def register(api):
    # Register a custom security tool
    api.register_tool("lookup", _lookup, description="Look up a domain")

    # Register a custom CLI command
    api.register_command("scan-extra", _scan_cmd, description="Extra scan")

    # Register a finding hook to enrich every finding
    api.register_finding_hook("enrich", _enrich, priority=10)

def _lookup(domain: str) -> ToolResult:
    # Do work here...
    return ToolResult(success=True, data={"ip": "1.2.3.4"})

def _scan_cmd(args):
    print("Running custom scan...")
    return 0

def _enrich(finding: dict) -> dict:
    finding["enriched_by_my_plugin"] = True
    return finding
```

### 4. Use it

```bash
# Elengenix auto-discovers and loads the plugin
python3 main.py
# ... or use the marketplace:
python3 main.py marketplace install my_plugin
```

## API Reference

### `register(api: PluginAPI)`

Called by the host after manifest validation. Use the `api` object to register functionality.

### `PluginAPI` methods

| Method | Purpose |
|--------|---------|
| `register_tool(name, func, description, tags)` | Add a custom security tool |
| `register_command(name, func, description, usage)` | Add a custom CLI command |
| `register_ai_provider(name, chat_func, list_models_func)` | Add a custom AI provider |
| `register_finding_hook(name, hook, priority)` | Hook into finding pipeline |
| `get_config(key, default)` | Read config values |
| `has_capability(cap)` | Check if you declared a capability |
| `plugin_name` | Your plugin's name (read-only) |
| `logger` | Plugin-namespaced logger |

### `ToolResult`

Standard result format for tools:

```python
ToolResult(
    success=True,                # Required
    data={"key": "value"},       # Custom payload
    findings=[...],              # List of finding dicts (will go through hooks)
    error=None,                  # Error message if success=False
    duration_s=1.23,             # Tool execution time
)
```

### Capabilities (declared in manifest)

| Capability | What it means |
|------------|---------------|
| `network` | Can make HTTP/network requests |
| `filesystem` | Can read/write outside sandbox |
| `subprocess` | Can spawn subprocesses |
| `secrets` | Can access API keys/credentials |
| `ai_api` | Calls external AI providers |
| `subfinder` | Needs the `subfinder` Go binary |
| `nuclei` | Needs the `nuclei` Go binary |
| `elevated` | Needs root / privileged access |

## Examples

See `examples/plugins/` for full working examples:

- `hello_world/` — minimal: tool + command + hook
- `ollama_local/` — custom AI provider (Ollama)

## Distribution

Plugins are git repositories. To publish:

1. Push your plugin to GitHub
2. Add it to the [marketplace index](https://github.com/Elengenix/marketplace-index) via PR
3. Users install with: `python3 main.py marketplace install <name>`

## SDK Versioning

- **Major version** (`1.0.0` → `2.0.0`): breaking API changes
- **Minor version** (`1.0.0` → `1.1.0`): new features, backward-compatible
- **Patch version** (`1.0.0` → `1.0.1`): bug fixes

Plugins declare `sdk_version` in manifest. Host checks compatibility:
- Same major.minor → load
- Different major → reject
- Plugin needs newer minor → reject
- Plugin needs older minor → load (forward compat)
