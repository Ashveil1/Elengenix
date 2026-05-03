from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit import PromptSession
from prompt_toolkit.filters import Always

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

session = PromptSession(
    completer=SlashCommandCompleter(['/clear', '/quit', '/exit', '/target', '/thinking']),
    complete_while_typing=Always()
)

print("Type /think, then hit Backspace a few times. Press Ctrl-D to exit.")
try:
    session.prompt("> ")
except EOFError:
    pass
