import ast
import os
import sys

def get_imports(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read())
        except SyntaxError:
            return set()
            
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                imports.add(name.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split('.')[0])
    return imports

stdlib = set(sys.builtin_module_names) | {
    "os", "sys", "re", "json", "time", "datetime", "pathlib", "logging", "asyncio",
    "collections", "typing", "subprocess", "argparse", "importlib", "urllib", "threading",
    "shutil", "concurrent", "functools", "ipaddress", "stat", "ast", "select", "traceback",
    "math", "socket", "sqlite3", "queue", "signal", "tempfile", "uuid", "hashlib", "base64",
    "csv", "dataclasses", "enum", "inspect", "itertools", "random", "string", "warnings"
}

all_imports = set()
for root, _, files in os.walk('.'):
    if 'venv' in root or '__pycache__' in root or '.git' in root:
        continue
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            all_imports.update(get_imports(filepath))

local_modules = {f[:-3] for f in os.listdir('.') if f.endswith('.py')} | {"tools", "agents", "prompts", "custom_scripts"}

third_party = all_imports - stdlib - local_modules
print("Third-party imports:")
for imp in sorted(third_party):
    print(imp)
