import json
import os

MEMORY_FILE = "data/learnings.json"

def save_learning(target, discovery):
    """
    Saves a technical learning for a specific target.
    Example: {"google.com": ["Found /v2/api-docs", "Needs WAF bypass for SQLi"]}
    """
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    
    memory = {}
    if os.path.exists(MEMORY_FILE):
        with open(MEMORY_FILE, "r") as f:
            try:
                memory = json.load(f)
            except:
                memory = {}

    if target not in memory:
        memory[target] = []
    
    if discovery not in memory[target]:
        memory[target].append(discovery)
        # Keep only the last 10 important learnings per target
        memory[target] = memory[target][-10:]

    with open(MEMORY_FILE, "w") as f:
        json.dump(memory, f, indent=4)

def get_learnings(target):
    """
    Retrieves previous memories for a specific target.
    """
    if not os.path.exists(MEMORY_FILE):
        return ""
    
    with open(MEMORY_FILE, "r") as f:
        memory = json.load(f)
    
    if target in memory:
        return "\n".join([f"- Previous Discovery: {item}" for item in memory[target]])
    return "No previous memory for this target."
