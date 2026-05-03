from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.document import Document

commands = ['/clear', '/quit', '/exit', '/help', '/mode', '/target', '/thinking']
completer = NestedCompleter.from_nested_dict({c: None for c in commands})

# Simulate backspacing back to "/t"
for text in ['/thin', '/thi', '/th', '/t', '/']:
    doc = Document(text, cursor_position=len(text))
    comps = [c.text for c in completer.get_completions(doc, None)]
    print(f"  {text!r} -> {comps}")
