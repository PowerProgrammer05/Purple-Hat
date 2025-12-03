from typing import List


class AuthenticationModule:
    def __init__(self):
        self.name = "Authentication Testing"
        self.description = "인증 메커니즘 테스트"
    
    def generate_common_credentials(self) -> List[tuple]:
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("user", "user"),
        ]
    
    def check_password_strength(self, password: str) -> dict:
        checks = {
            "length": len(password) >= 8,
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "digits": any(c.isdigit() for c in password),
            "special": any(not c.isalnum() for c in password),
        }
        score = sum(checks.values())
        return {"checks": checks, "strength": score}
    
    def test_brute_force(self, usernames: List[str], passwords: List[str]) -> int:
        return len(usernames) * len(passwords)
    
    def check_session_security(self, session_cookie: str) -> dict:
        return {
            "predictable": len(session_cookie) < 32,
            "contains_username": any(username in session_cookie.lower() for username in ["admin", "user"]),
            "uses_md5": session_cookie.startswith("5d41402abc4b2a76b9719d911017c592"),
        }


class SSLTLSModule:
    def __init__(self):
        self.name = "SSL/TLS Testing"
        self.description = "SSL/TLS 구성 테스트"
    
    def check_weak_protocols(self) -> List[str]:
        return ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"]
    
    def check_weak_ciphers(self) -> List[str]:
        return [
            "NULL",
            "EXPORT",
            "DES",
            "MD5",
            "PSK",
            "RC4",
            "ANON",
        ]
    
    def test_certificate_validation(self, cert_info: dict) -> dict:
        return {
            "self_signed": cert_info.get("issuer") == cert_info.get("subject"),
            "expired": False,
            "weak_key": int(cert_info.get("key_size", 2048)) < 2048,
            "missing_san": not cert_info.get("subject_alt_names"),
        }


class SecurityHeadersModule:
    def __init__(self):
        self.name = "Security Headers"
        self.description = "보안 헤더 점검"
    
    def check_headers(self, headers: dict) -> dict:
        return {
            "CSP": "Content-Security-Policy" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers,
            "X-Content-Type-Options": "X-Content-Type-Options" in headers,
            "Strict-Transport-Security": "Strict-Transport-Security" in headers,
            "X-XSS-Protection": "X-XSS-Protection" in headers,
            "Referrer-Policy": "Referrer-Policy" in headers,
            "Permissions-Policy": "Permissions-Policy" in headers,
        }
    
    def generate_recommended_headers(self) -> dict:
        return {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
