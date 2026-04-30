import re
import os

files_to_update = [
    "tools_menu.py",
    "live_display.py",
    "main.py",
    "orchestrator.py",
    "elengenix_launcher.py",
    "tools/omni_scan.py",
    "tools/config_wizard.py",
]

# Standard replacements for Rich colors
replacements = {
    "bold cyan": "bold red",
    "cyan": "red",
    "yellow": "grey70",
    "green": "bold white",
    "blue": "grey70",
    "ansigreen": "ansired",
    "ansicyan": "ansiwhite",
}

for file_path in files_to_update:
    if not os.path.exists(file_path):
        print(f"Skipping {file_path} (not found)")
        continue
        
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    for old, new in replacements.items():
        # Match colors in Rich tags like [bold cyan] or [cyan]
        content = content.replace(f"[{old}]", f"[{new}]")
        content = content.replace(f"[/{old}]", f"[/{new}]")
        # Match colors in strings like "cyan" or 'cyan'
        content = content.replace(f'"{old}"', f'"{new}"')
        content = content.replace(f"'{old}'", f"'{new}'")
        # Match HTML-like tags for prompt_toolkit
        content = content.replace(f"<{old}>", f"<{new}>")
        content = content.replace(f"</{old}>", f"</{new}>")

    if content != original:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {file_path}")
    else:
        print(f"No changes for {file_path}")

print("Update complete.")
