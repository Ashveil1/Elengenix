#!/usr/bin/env python3
"""Check 8: Scan transcripts for denied read-only commands and propose allow rules."""

import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

TRANSCRIPT_DIRS = [
    os.path.expanduser("~/.claude/projects/-home-aponith"),
    os.path.expanduser("~/.claude/projects/-home-aponith-Elengenix"),
]

# Read-only Bash patterns
BASH_READONLY_PATTERNS = [
    r'^git status',
    r'^git log',
    r'^git diff',
    r'^git show',
    r'^git branch(?!\s+(-d|-D|-m|-M|--delete|--move))',
    r'^git stash\s+(list|show)',
    r'^git tag\s*(-l|-n|--list)',
    r'^git worktree\s+list',
    r'^git shortlog',
    r'^git describe',
    r'^git blame',
    r'^git grep',
    r'^git rev-parse',
    r'^git rev-list',
    r'^git for-each-ref',
    r'^git ls-tree',
    r'^git ls-files',
    r'^git config',
    r'^git remote',
    r'^git submodule\s+status',
    r'^git cat-file',
    r'^git hash-object',
    r'^git check-attr',
    r'^git check-ignore',
    r'^git cherry',
    r'^git count-objects',
    r'^ls\b',
    r'^cat\b',
    r'^head\b',
    r'^tail\b',
    r'^wc\b',
    r'^pwd\b',
    r'^echo\b',
    r'^which\b',
    r'^type\b',
    r'^file\b',
    r'^date\b',
    r'^whoami\b',
    r'^id\b',
    r'^uname\b',
    r'^hostname',
    r'^printenv',
    r'^env\b',
    r'^python3\s+-c',
    r'^python\s+-c',
    r'^gh pr view\b',
    r'^gh pr list\b',
    r'^gh issue view\b',
    r'^gh issue list\b',
    r'^gh run view\b',
    r'^gh run list\b',
    r'^gh repo list\b',
    r'^gh search\b',
    r'^gh status\b',
    r'^gh --help',
    r'^find\b(?!.*\s+(-exec|-delete|-ok)\b)',
    r'^grep\b',
    r'^sort\b',
    r'^uniq\b',
    r'^comm\b',
    r'^diff\b(?!.*-u.*-)',
    r'^cmp\b',
    r'^cut\b',
    r'^tr\b',
    r'^readlink',
    r'^realpath',
    r'^dirname',
    r'^basename',
    r'^stat\b',
    r'^du\b',
    r'^df\b',
    r'^time\b',
    r'^sleep\b',
    r'^nproc',
    r'^nohup\b',
    r'^nice\b',
    r'^chsh',
    r'^tty\b',
    r'^logname',
    r'^groups',
    r'^users\b',
    r'^w\b',
    r'^uptime',
    r'^lscpu',
    r'^lsblk',
    r'^lspci',
    r'^lsusb',
    r'^free\b',
    r'^vmstat',
    r'^iostat',
    r'^mpstat',
    r'^pip\s+list',
    r'^pip3\s+list',
    r'^npm\s+list',
    r'^npm\s+audit',
    r'^npm\s+view',
]

BASH_WRITE_PATTERNS = [
    r'^git (push|commit|add|reset|merge|rebase|cherry-pick|revert|fetch|pull|clean|rm|mv|stash (pop|drop|apply|save|push)|tag (-d|-a)|worktree (add|remove|prune)|branch (-d|-D|-m|-M|--delete|--move)|submodule (add|update))',
    r'^(rm|mv|cp|mkdir|touch|chmod|chown|ln|dd|truncate)\b',
    r'^(curl|wget)\b',
    r'^(npm|yarn|pnpm)\s+(install|publish|add|remove|update|run|run-script)\b',
    r'^(pip|pip3|gem|bundle)\s+(install|update)\b',
    r'^(apt|apt-get|pacman|yum|dnf|zypper|brew|port)\b',
    r'^sudo\b',
    r'^gh api\b',
    r'^gh pr (create|merge|close|reopen|ready|review|checks|edit)',
    r'^gh issue (create|close|reopen|lock|unlock|edit)',
    r'^gh run (rerun|cancel|watch)',
    r'^gh release (create|upload|download|edit)',
    r'^gh workflow run',
    r'^gh variable set',
    r'^gh secret set',
    r'^find\s+.*(-exec|-delete|-ok)\b',
    r'^sed\s+.*-i',
    r'^tee\s+.*-a',
]


def is_readonly_bash(cmd):
    """Determine if a bash command is read-only based on its invocation."""
    cmd = cmd.strip()

    # Exclude write commands first
    for wp in BASH_WRITE_PATTERNS:
        if re.search(wp, cmd):
            return False

    # Check known read-only patterns
    for rp in BASH_READONLY_PATTERNS:
        if re.search(rp, cmd):
            return True

    # For git commands not matched above, be conservative
    if re.match(r'^git\s', cmd):
        return False

    # For gh commands not matched above
    if re.match(r'^gh\s', cmd):
        return False

    # For find with args but no exec/delete
    if re.match(r'^find\s', cmd):
        return True

    return False


def is_readonly_mcp(tool_name):
    """Determine if an MCP tool is read-only by its name."""
    name = tool_name.replace("mcp__", "")
    read_only_prefixes = ("get_", "list_", "read_", "search_", "lookup_", "query_", "describe_", "show_")
    return any(name.startswith(p) for p in read_only_prefixes)


def extract_tool_calls(entry):
    """Extract tool_use blocks from an assistant entry's message content."""
    tool_calls = {}
    msg = entry.get("message", {})
    if not isinstance(msg, dict):
        return tool_calls
    content = msg.get("content", [])
    if not isinstance(content, list):
        return tool_calls
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            tid = block.get("id", "")
            tool_calls[tid] = block
    return tool_calls


def check_tool_result(block, assistant_calls, denials, source, skip_mcp_fallback=False):
    """Check a tool_result block for denials. Returns True if denial found."""
    # Method 1: modern toolDenialKind
    denial_kind = block.get("toolDenialKind")
    tool_use_id = block.get("tool_use_id", "")

    if denial_kind:
        tool_call = assistant_calls.get(tool_use_id, {})
        denials.append({
            "tool_name": tool_call.get("name", ""),
            "tool_use_id": tool_use_id,
            "input": tool_call.get("input", {}),
            "denial_kind": denial_kind,
            "method": source,
        })
        return True

    # Method 2: fallback is_error with denial text
    is_error = block.get("is_error")
    if not is_error:
        return False

    content = block.get("content", "")
    content_text = ""
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                content_text += item.get("text", "") + " "
    elif isinstance(content, str):
        content_text = content

    # Skip MCP in fallback mode (forged denial text)
    tool_call = assistant_calls.get(tool_use_id, {})
    tool_name = tool_call.get("name", "")
    if skip_mcp_fallback and tool_name.startswith("mcp__"):
        return False

    for indicator in ["doesn't want to proceed", "The user doesn't want", "Permission to use", "Permission for this"]:
        if indicator in content_text:
            denials.append({
                "tool_name": tool_name,
                "tool_use_id": tool_use_id,
                "input": tool_call.get("input", {}),
                "denial_kind": "user-rejected",
                "method": source + "-fallback",
            })
            return True

    return False


def get_bash_pattern(cmd):
    """Get a normalized pattern key for a Bash command."""
    parts = cmd.strip().split()
    if not parts:
        return "Bash(?)"
    cmd0 = parts[0]

    if cmd0 == "git" and len(parts) > 1:
        return f"Bash(git {parts[1]})"
    if cmd0 == "gh" and len(parts) > 2:
        return f"Bash(gh {parts[1]} {parts[2]})"
    if cmd0 == "gh" and len(parts) > 1:
        return f"Bash(gh {parts[1]})"
    if cmd0 in ("python", "python3") and len(parts) > 1:
        return f"Bash({cmd0} -c)"
    if cmd0 == "find":
        return "Bash(find)"
    return f"Bash({cmd0})"


def process_transcript(filepath):
    """Process a transcript file and return denied tool info."""
    denials = []

    try:
        with open(filepath, "r", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"  Error reading {filepath}: {e}", file=sys.stderr)
        return denials

    assistant_calls = {}

    # Pass 1: primary method using toolDenialKind
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        etype = entry.get("type", "")

        if etype == "assistant":
            assistant_calls.update(extract_tool_calls(entry))
        elif etype == "user":
            # Check message.content for tool_result blocks
            msg = entry.get("message", {})
            if isinstance(msg, dict):
                content = msg.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            check_tool_result(block, assistant_calls, denials, "msg.content")
            # Check old format: toolUseResult.task
            tur = entry.get("toolUseResult", {})
            if isinstance(tur, dict):
                task = tur.get("task", {})
                if isinstance(task, dict):
                    check_tool_result(task, assistant_calls, denials, "toolUseResult")

    # Pass 2: fallback is_error with denial text (skip MCP)
    if not denials:
        assistant_calls = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            etype = entry.get("type", "")
            if etype == "assistant":
                assistant_calls.update(extract_tool_calls(entry))
            elif etype == "user":
                msg = entry.get("message", {})
                if isinstance(msg, dict):
                    content = msg.get("content", [])
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_result":
                                check_tool_result(block, assistant_calls, denials,
                                                  "fallback", skip_mcp_fallback=True)

    return denials


def read_existing_rules():
    """Read all existing allow/deny rules from settings cascade."""
    paths = [
        os.path.expanduser("~/.claude/settings.json"),
        os.path.expanduser("~/.claude/settings.local.json"),
        os.path.expanduser("~/.claude/projects/-home-aponith-Elengenix/.claude/settings.json"),
        os.path.expanduser("~/.claude/projects/-home-aponith-Elengenix/.claude/settings.local.json"),
    ]
    rules = set()
    for sp in paths:
        if os.path.isfile(sp):
            try:
                with open(sp) as f:
                    data = json.load(f)
                for r in data.get("permissions", {}).get("allow", []):
                    rules.add(r)
                for r in data.get("permissions", {}).get("deny", []):
                    rules.add(r)
            except Exception:
                pass
    return rules


def main():
    # Gather all transcript files (non-subagent), sorted by mtime, take 50
    all_files = []
    for d in TRANSCRIPT_DIRS:
        if os.path.isdir(d):
            for fn in os.listdir(d):
                fp = os.path.join(d, fn)
                if fn.endswith(".jsonl") and os.path.isfile(fp):
                    all_files.append(fp)

    all_files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
    all_files = all_files[:50]

    print(f"Scanning {len(all_files)} transcript files...\n")

    all_denials = []

    for fp in all_files:
        denials = process_transcript(fp)
        if denials:
            fname = os.path.basename(fp)
            print(f"  {fname}: {len(denials)} denial(s)")
        all_denials.extend(denials)

    print(f"\nTotal denial records found: {len(all_denials)}")

    if all_denials:
        print("\nDenial details:")
        for d in all_denials:
            tool = d["tool_name"]
            kind = d["denial_kind"]
            method = d["method"]
            inp = d["input"]
            if tool == "Bash":
                cmd = inp.get("command", "")[:150]
            elif tool.startswith("mcp__"):
                cmd = tool
            else:
                cmd = tool
            print(f"  [{method}/{kind}] {cmd}")
    else:
        print("\n  (no denials found)")

    # Aggregate by pattern
    pattern_stats = defaultdict(lambda: {"tool": "", "count": 0, "kind_mix": defaultdict(int), "inputs": []})

    for d in all_denials:
        tool = d["tool_name"]
        inp = d["input"]
        kind = d["denial_kind"]

        if tool == "Bash":
            cmd = inp.get("command", "")
            pattern = get_bash_pattern(cmd)
        else:
            pattern = tool

        ps = pattern_stats[pattern]
        ps["tool"] = tool
        ps["count"] += 1
        ps["kind_mix"][kind] += 1
        ps["inputs"].append(inp.get("command", "") if tool == "Bash" else str(inp))

    existing_rules = read_existing_rules()
    print(f"\nExisting allow/deny rules: {json.dumps(sorted(existing_rules)) if existing_rules else 'none'}")

    # Build denied patterns list
    denied_patterns = []
    proposed_rules = []

    for pattern, ps in sorted(pattern_stats.items(), key=lambda x: -x[1]["count"]):
        tool = ps["tool"]
        ex_input = ps["inputs"][0] if ps["inputs"] else ""
        is_ro = False
        ro_reason = ""
        exact_pattern = pattern

        if tool == "Bash":
            is_ro = is_readonly_bash(ex_input)
            if is_ro:
                exact_pattern = f"Bash({ex_input})"
                ro_reason = "read-only bash command"
        else:
            is_ro = is_readonly_mcp(tool)
            if is_ro:
                ro_reason = "read-only MCP tool"

        if not is_ro:
            continue

        existing_match = exact_pattern in existing_rules

        dp = {
            "pattern": exact_pattern,
            "tool": tool,
            "denialCount": ps["count"],
            "kindMix": dict(ps["kind_mix"]),
            "isReadOnly": is_ro,
            "readOnlyReason": ro_reason,
            "existingDenyAskMatch": existing_match,
            "proposedRule": exact_pattern,
        }
        denied_patterns.append(dp)
        if not existing_match:
            proposed_rules.append(exact_pattern)

    result = {
        "scanWindow": {
            "oldest": "N/A",
            "newest": "N/A",
            "sessions": len(all_files),
            "days": 0,
        },
        "deniedPatterns": denied_patterns,
        "proposedRules": proposed_rules,
    }

    print("\n\n=== RESULT ===")
    print(json.dumps(result, indent=2))

    with open("/tmp/check8_result.json", "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nWritten to /tmp/check8_result.json")


if __name__ == "__main__":
    main()
