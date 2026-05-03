from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.filters import Always

completer = WordCompleter(['/target', '/thinking'])
# Just syntax checking
