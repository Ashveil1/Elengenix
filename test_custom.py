from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document

class SlashCommandCompleter(Completer):
    def __init__(self, commands):
        self.commands = commands

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor.lstrip()
        if not text.startswith('/'):
            return
            
        word = text.split(' ')[0].lower()
        for cmd in self.commands:
            if cmd.startswith(word):
                yield Completion(cmd, start_position=-len(word))

commands = ['/clear', '/quit', '/exit', '/help', '/mode', '/target', '/thinking']
completer = SlashCommandCompleter(commands)

for text in ['/thin', '/thi', '/th', '/t', '/']:
    doc = Document(text, cursor_position=len(text))
    comps = [c.text for c in completer.get_completions(doc, None)]
    print(f"  {text!r} -> {comps}")
