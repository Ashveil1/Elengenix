import re
from prompt_toolkit.document import Document
from prompt_toolkit.completion import WordCompleter

for pat in [r'/?\w*', r'[/\w]+', r'^[a-zA-Z0-9_/]+$', r'[^ \n]+']:
    doc1 = Document('/t', cursor_position=2)
    word = doc1.get_word_before_cursor(pattern=re.compile(pat))
    print(f"Pattern {pat!r} -> Word: {word!r}")
    
    completer = WordCompleter(['/clear', '/quit', '/target'], ignore_case=True, pattern=re.compile(pat))
    print("  Completions:", [c.text for c in completer.get_completions(doc1, None)])
