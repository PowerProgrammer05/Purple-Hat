from typing import Callable, List, Dict, Any
from enum import Enum
import sys


class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    BLACK = '\033[30m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    INVERT = '\033[7m'
    RESET = '\033[0m'
    
    BG_PURPLE = '\033[105m'
    BG_CYAN = '\033[106m'
    BG_BLUE = '\033[104m'
    BG_RED = '\033[101m'


class Symbol:
    ARROW = "→"
    BULLET = "•"
    CHECK = "✓"
    CROSS = "✗"
    STAR = "★"
    LIGHTNING = "⚡"
    BOMB = "💣"
    LOCK = "🔒"
    UNLOCK = "🔓"
    SHIELD = "🛡️"
    TARGET = "🎯"
    FIRE = "🔥"
    SKULL = "💀"
    HEART = "❤"
    CLOCK = "🕐"
    SETTINGS = "⚙️"
    FOLDER = "📁"
    FILE = "📄"
    TERMINAL = "▌▌▌"


class UIRenderer:
    def __init__(self):
        self.width = 100
    
    def print_banner(self):
        banner = f"""
{Color.PURPLE}{Color.BOLD}
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                          ║
║                          {Color.CYAN}██████╗ ██╗   ██╗██╗     ██████╗ ██╗     ███████╗     {Color.PURPLE}║
║                          {Color.CYAN}██╔══██╗██║   ██║██║     ██╔══██╗██║     ██╔════╝     {Color.PURPLE}║
║                          {Color.CYAN}██████╔╝██║   ██║██║     ██████╔╝██║     █████╗       {Color.PURPLE}║
║                          {Color.CYAN}██╔═══╝ ██║   ██║██║     ██╔═══╝ ██║     ██╔══╝       {Color.PURPLE}║
║                          {Color.CYAN}██║     ╚██████╔╝███████╗██║     ███████╗███████╗     {Color.PURPLE}║
║                          {Color.CYAN}╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚══════╝     {Color.PURPLE}║
║                                                                                                          ║
║                                 {Color.GREEN}Modern Security Testing Framework{Color.PURPLE}             ║
║                                                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝
{Color.RESET}"""
        print(banner)
    
    def print_header(self, title: str, icon: str = Symbol.STAR):
        line = "─" * (self.width - len(title) - 8)
        print(f"\n{Color.CYAN}{Color.BOLD}{icon} {title} {line}{Color.RESET}")
    
    def print_section(self, title: str):
        self.print_header(title, Symbol.SHIELD)
    
    def print_success(self, message: str):
        print(f"{Color.GREEN}{Symbol.CHECK} {message}{Color.RESET}")
    
    def print_error(self, message: str):
        print(f"{Color.RED}{Symbol.CROSS} {message}{Color.RESET}")
    
    def print_warning(self, message: str):
        print(f"{Color.YELLOW}{Symbol.LIGHTNING} {message}{Color.RESET}")
    
    def print_info(self, message: str):
        print(f"{Color.BLUE}{Symbol.BULLET} {message}{Color.RESET}")
    
    def print_option(self, number: int, text: str, description: str = ""):
        desc_text = f" {Color.DIM}({description}){Color.RESET}" if description else ""
        print(f"  {Color.CYAN}{number:2d}{Color.RESET} {Color.WHITE}{text}{desc_text}{Color.RESET}")
    
    def print_table(self, headers: List[str], rows: List[List[str]]):
        col_widths = [max(len(h), max((len(str(r[i])) for r in rows), default=0)) + 2 for i, h in enumerate(headers)]
        
        print(f"\n{Color.CYAN}{''.join(h.ljust(w) for h, w in zip(headers, col_widths))}{Color.RESET}")
        print(f"{Color.DIM}{''.join('─' * w for w in col_widths)}{Color.RESET}")
        
        for row in rows:
            print(f"{Color.WHITE}{''.join(str(c).ljust(w) for c, w in zip(row, col_widths))}{Color.RESET}")
    
    def print_result_box(self, title: str, content: str):
        print(f"\n{Color.PURPLE}{Color.BOLD}┌{'─' * (self.width - 2)}┐{Color.RESET}")
        print(f"{Color.PURPLE}{Color.BOLD}│{Color.RESET} {Color.CYAN}{title.ljust(self.width - 3)}{Color.RESET} {Color.PURPLE}{Color.BOLD}│{Color.RESET}")
        print(f"{Color.PURPLE}{Color.BOLD}├{'─' * (self.width - 2)}┤{Color.RESET}")
        
        for line in content.split('\n'):
            print(f"{Color.PURPLE}{Color.BOLD}│{Color.RESET} {line.ljust(self.width - 3)} {Color.PURPLE}{Color.BOLD}│{Color.RESET}")
        
        print(f"{Color.PURPLE}{Color.BOLD}└{'─' * (self.width - 2)}┘{Color.RESET}")
    
    def print_loading(self, message: str = "Loading"):
        import time
        symbols = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        for i in range(10):
            sys.stdout.write(f"\r{Color.CYAN}{symbols[i % len(symbols)]} {message}...{Color.RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()
    
    def input_prompt(self, prompt: str, color: str = Color.CYAN) -> str:
        return input(f"{color}{Symbol.ARROW} {prompt}{Color.RESET}: ")
    
    def input_choice(self, prompt: str) -> str:
        return input(f"{Color.CYAN}{Symbol.ARROW} {prompt}{Color.RESET}: ")
    
    def clear_screen(self):
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_divider(self):
        print(f"{Color.DIM}{'═' * self.width}{Color.RESET}")
