import re
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.document import Document

commands = ['/clear', '/quit', '/exit', '/help', '/mode', '/target', '/thinking']
completer = WordCompleter(commands, ignore_case=True, pattern=re.compile(r'[^ \n]+'))

# Simulate typing "/think"
print("Typing /think")
for text in ['/', '/t', '/th', '/thi', '/thin', '/think']:
    doc = Document(text, cursor_position=len(text))
    comps = [c.text for c in completer.get_completions(doc, None)]
    print(f"  {text!r} -> {comps}")

# Simulate backspacing back to "/t"
print("\nBackspacing back to /t")
for text in ['/thin', '/thi', '/th', '/t', '/']:
    doc = Document(text, cursor_position=len(text))
    comps = [c.text for c in completer.get_completions(doc, None)]
    print(f"  {text!r} -> {comps}")
