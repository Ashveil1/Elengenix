import re
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

commands = ['/clear', '/quit', '/exit', '/help', '/mode', '/target', '/thinking']
completer = WordCompleter(commands, ignore_case=True, pattern=re.compile(r'[^ \n]+'))
session = PromptSession(completer=completer, complete_while_typing=True)

print("Type slash commands. Press Ctrl+D to exit.")
try:
    session.prompt("> ")
except EOFError:
    pass
