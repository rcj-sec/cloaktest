from colorama import Fore, Back, Style, init

from rich.table import Table
from rich.console import Console

init(autoreset=True)

def sucess(message):
    print(Fore.GREEN + Style.BRIGHT + message)

def warning(message):
    print(Fore.YELLOW + str(message))

def error(message):
    print(Fore.RED + Style.BRIGHT + str(message))

def info(message):
    print(Fore.CYAN + str(message))

def critical(message):
    print(Fore.MAGENTA + Style.BRIGHT + str(message))

def header(message):
    print(Fore.WHITE + Back.BLACK + Style.BRIGHT + str(message))

def table(title, headers=[], rows=[], lines=True):
    console = Console()
    richtable = Table(title=title, show_lines=True, safe_box=True)

    for header in headers:
        richtable.add_column(header, style='bold cyan', no_wrap=True)

    for row in rows:
        string_row = [str(cell) for cell in row]
        richtable.add_row(*string_row)

    console.print(richtable)
