from typing import List

class CommandInjectionModule:
    def __init__(self):
        self.name = "Command Injection"
        self.description = "명령어 주입 취약점 페이로드"

    def generate_payloads(self) -> List[str]:
        return [
            "; ls",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "&& id",
        ]

    def detect_injection(self, user_input: str) -> bool:
        return any(c in user_input for c in [';', '|', '&', '`', '$'])
