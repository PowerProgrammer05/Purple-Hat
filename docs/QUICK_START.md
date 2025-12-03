# PURPLE HAT Quick Reference Guide

## 🚀 Quick Start (5 minutes)

### Installation
```bash
git clone https://github.com/PowerProgrammer05/Purple-Hat.git
cd Purple-Hat
./install.sh
```

### Running
```bash
# Web Interface (Recommended for beginners)
python3 -m ui.webapp_v3
# Open: http://127.0.0.1:5000

# Terminal Interface
python3 main.py
```

### Login
- **Username**: admin
- **Password**: ADMIN1234
- ⚠️ **Change before production use!**

## 📊 Operating Modes

### Ready-To-Go Mode
**Best for**: Quick vulnerability checks, automation
```
Select Ready-To-Go when launching
→ Automatic scanning with sensible defaults
→ 5-10 second scans
→ Limited payloads for speed
```

### Professional Mode
**Best for**: Thorough security assessments
```
Select Professional when launching
→ Full customization available
→ Extended scanning time
→ Complete payload database
→ Advanced logging
```

## 🔧 Common Tasks

### SQL Injection Testing
1. Go to: Scan → Enter Target URL
2. Check: "SQL Injection" module
3. Select Mode: Ready-To-Go or Professional
4. Click: "Start Scan"

### Port Scanning
1. Go to: Scan → Enter Target Host
2. Check: "Port Scanner" module
3. Set Port Range: 1-1000 (or custom)
4. Start scan

### XSS Detection
1. Go to: Scan → Enter Target URL
2. Check: "XSS Detection" module
3. Enter Parameters: search, q, id, etc.
4. Start scan

### Full Site Assessment
1. Go to: Scan → Enter Target
2. Check: All modules
3. Select Mode: Professional (recommended)
4. Start comprehensive scan

## 📈 Reviewing Results

1. **View Results**: Results menu
2. **Filter by Severity**: Critical, High, Medium, Low
3. **Generate Report**: Export as HTML/PDF/JSON
4. **Download Report**: Save for presentation

## ⚙️ Configuration

### Via Web Interface
1. Settings menu
2. Adjust parameters
3. Click "Save Settings"

### Via config.json
```json
{
  "settings": {
    "timeout": 10,
    "retries": 5,
    "verify_ssl": true
  }
}
```

### Environment Variables
```bash
export PURPLEHAT_PROXY_ENABLED=true
export PURPLEHAT_PROXY_URL=http://proxy.com:8080
export PURPLEHAT_SQLMAP_PATH=/path/to/sqlmap.py
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
lsof -ti:5000 | xargs kill -9
# OR use different port
FLASK_PORT=8000 python3 -m ui.webapp_v3
```

### SSL Certificate Errors
```json
{
  "settings": {
    "verify_ssl": false
  }
}
```
⚠️ Only for testing!

### Module Not Found
```bash
pip install -r requirements.txt
pip install -e .
```

### Performance Issues
```json
{
  "settings": {
    "sql_injection_threads": 5,
    "port_scan_threads": 20
  }
}
```

## 🔐 Security Checklist

Before going to production:
- [ ] Change default credentials
- [ ] Set `verify_ssl: true`
- [ ] Enable HTTPS/SSL
- [ ] Configure firewall rules
- [ ] Update SECRET_KEY
- [ ] Review audit logs
- [ ] Backup configurations
- [ ] Test in staging first

## 📱 Docker Quick Start

```bash
# Build
docker build -t purple-hat .

# Run
docker run -d -p 5000:5000 purple-hat

# Or with compose
docker-compose up -d
```

## 🎯 Module Reference

| Module | Purpose | Best Mode |
|--------|---------|-----------|
| SQL Injection | Database attacks | Professional |
| XSS Detection | Script injection | Ready-To-Go |
| Port Scanner | Open ports | Ready-To-Go |
| SSL/TLS | Certificate analysis | Professional |
| Auth Testing | Credential strength | Professional |
| Command Injection | OS command attacks | Professional |
| CSRF | Cross-site requests | Ready-To-Go |
| File Upload | Upload vulnerabilities | Professional |

## 📊 Scan Types

### Quick Scan (2-5 min)
```
Mode: Ready-To-Go
Modules: SQL, XSS, Port Scanner
Target: Single URL
```

### Standard Scan (10-20 min)
```
Mode: Ready-To-Go
Modules: All enabled
Target: Multiple URLs
```

### Deep Scan (30+ min)
```
Mode: Professional
Modules: All enabled
Options: Full customization
Target: Complex application
```

## 💡 Tips & Tricks

### Speed Up Scans
- Use Ready-To-Go mode
- Increase thread count
- Reduce port range
- Select specific modules

### Improve Accuracy
- Use Professional mode
- Increase timeout
- Enable SSL verification
- Use full payload database

### Save Time
- Create custom presets
- Use batch scanning
- Schedule recurring scans
- Export configurations

### Better Results
- Test in staging first
- Review each finding
- Check false positives
- Verify remediation

## 📞 Getting Help

**In Application**:
- Click "Help" in web interface
- Type "help" in terminal menu
- Read integrated documentation

**Online Resources**:
- GitHub Wiki: Detailed guides
- Issues: Bug reports & features
- Discussions: Q&A forum
- Documentation: README & guides

**Community**:
- Security Stack Exchange
- OWASP communities
- Bug bounty platforms
- Security forums

## 🔗 Quick Links

| Resource | URL |
|----------|-----|
| GitHub | https://github.com/PowerProgrammer05/Purple-Hat |
| Issues | github.com/.../issues |
| Discussions | github.com/.../discussions |
| Wiki | github.com/.../wiki |
| Email | security@purplehat.io |

## 📚 Learning Resources

- OWASP Top 10: https://owasp.org/Top10
- Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com
- DVWA: http://www.dvwa.co.uk

## ✅ Pre-Flight Checklist

Before each scan:
- [ ] Target authorization confirmed
- [ ] Network connectivity verified
- [ ] Mode selected appropriately
- [ ] Modules configured correctly
- [ ] Backup created (for databases)
- [ ] Team notified
- [ ] Scope clearly defined
- [ ] Time window confirmed

## 🎓 Next Steps

1. **Read**: README.md for full features
2. **Install**: Follow INSTALLATION.md
3. **Configure**: Customize settings
4. **Test**: Try on test application
5. **Learn**: Study found vulnerabilities
6. **Deploy**: Use in production
7. **Contribute**: Share improvements

## 📝 Version

- **Current**: 2.0.0
- **Released**: 2025-12-03
- **Latest**: github.com/PowerProgrammer05/Purple-Hat/releases

---

**Remember**: Always test on authorized systems only. Unauthorized testing is illegal.

For more information: https://github.com/PowerProgrammer05/Purple-Hat
