import re

with open('ui_components.py', 'r') as f:
    content = f.read()

# Replacements
replacements = {
    '"gold3"': '"red"',
    '"steel_blue"': '"grey70"',
    '"dark_olive_green2"': '"white"',
    '"dark_orange"': '"grey70"',
    '"indian_red"': '"red"',
    'gold3': 'red',
    'steel_blue': 'grey70',
    'dark_olive_green2': 'white',
    'dark_orange': 'grey70',
    'indian_red': 'red',
    'cyan': 'red',
}

for old, new in replacements.items():
    content = content.replace(old, new)

# Update Banner ASCII
old_banner = """    banner = (
        "\\n"
        "[bold red]  ____ _                             _     [/bold red]\\n"
        "[bold red] |  __| | ___ _ __   __ _  ___ _ __ (_)_  __[/bold red]\\n"
        "[bold red] | |_ | |/ _ \\ '_ \\ / _` |/ _ \\ '_ \\| \\ \\/ /[/bold red]\\n"
        "[bold red] |  _|| |  __/ | | | (_| |  __/ | | | |>  < [/bold red]\\n"
        "[bold red] |_|  |_|\\___|_| |_|\\__, |\\___|_| |_|_/_/\\_\\[/bold red]\\n"
        "[bold red]                    |___/                   [/bold red]\\n"
        "[dim red] ────────────────────────────────────────── [/dim red]\\n"
        "[bold white]      Universal AI & Bug Bounty Agent       [/bold white]\\n"
        "[dim red]           Aegis Protocol Active            [/dim red]\\n\\n"
        "                  [bold red]v2.0.0[/bold red]                  \\n"
    )"""

new_banner = """    banner = (
        "\\n"
        "[bold red] ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗[/bold red]\\n"
        "[bold red] ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝[/bold red]\\n"
        "[bold red] █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ [/bold red]\\n"
        "[bold red] ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ [/bold red]\\n"
        "[bold red] ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗[/bold red]\\n"
        "[bold red] ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝[/bold red]\\n"
        "[dim grey70] ─────────────────────────────────────────────────────────────────────────── [/dim grey70]\\n"
        "[bold white]                   Universal AI & Bug Bounty Agent                   [/bold white]\\n"
        "[dim grey70]                        Aegis Protocol Active                        [/dim grey70]\\n\\n"
        "                               [bold red]v2.0.0[/bold red]                                \\n"
    )"""

content = content.replace(old_banner, new_banner)

with open('ui_components.py', 'w') as f:
    f.write(content)
print("Updated ui_components.py")
