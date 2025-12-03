# 🎭 PURPLE HAT v2.0 - Modern Security Testing Framework

**Enterprise-Grade Security Testing & Vulnerability Assessment Platform**

![Version](https://img.shields.io/badge/version-2.0.0-blueviolet)
![Python](https://img.shields.io/badge/python-3.8+-blueviolet)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Production%20Ready-green)

---

## ✨ Overview

PURPLE HAT is a comprehensive, production-ready security testing framework designed for penetration testers, security professionals, and developers. It combines powerful automation with granular control through two distinct operating modes:

- **Ready-To-Go Mode** ⚡ - Automated scanning with intelligent defaults (5-10 seconds)
- **Professional Mode** 🔧 - Advanced customization for thorough assessments (15+ seconds)

### Key Highlights

✅ **Database-Backed** - User accounts, scan history, findings storage  
✅ **Modern Web UI** - Professional dashboard with real-time monitoring  
✅ **Production Ready** - Docker support, Render deployment, comprehensive docs  
✅ **100% English** - No Korean content, fully internationalized  
✅ **Professional Branding** - Custom logo integration across UI  
✅ **Two Operating Modes** - Automated or customizable workflows  

---

## 🚀 Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/PowerProgrammer05/Purple-Hat.git
cd Purple-Hat
pip install -r requirements.txt

# Initialize database
python -m flask --app ui.webapp_v3 db upgrade

# Create admin user
python -m flask --app ui.webapp_v3 create-admin

# Run
python -m ui.webapp_v3
# Access: http://localhost:5000
```

### Docker Deployment

```bash
docker-compose up -d
# Access: http://localhost:5000
```

### Render.com Deployment

```bash
# Start command
gunicorn --bind 0.0.0.0:$PORT --workers 4 --threads 2 --worker-class gthread ui.webapp_v3:app
```

---

## 🎯 Features

### Two Operating Modes

#### Ready-To-Go Mode
- Automated scanning with optimized defaults
- 5-10 second execution time
- 50 payloads per module
- Common port range (1-1000)
- Perfect for CI/CD pipelines

#### Professional Mode
- Full customization control
- 15+ second execution time
- Complete payload database (500+ payloads)
- Full port range (1-65535)
- Advanced logging and reporting

### Web Interface Features

| Feature | Description |
|---------|-------------|
| **Dashboard** | Real-time statistics, recent scans, quick actions |
| **Scan Management** | Create, monitor, and view all security scans |
| **Findings Viewer** | Detailed vulnerability reports with filtering |
| **Report Generation** | Export in JSON, HTML, CSV, PDF formats |
| **User Accounts** | Secure registration and authentication |
| **Settings** | Customizable scan parameters per user |

### Security Testing Modules

#### Injection Testing
- SQL Injection (Union, Time-based, Boolean, Error-based, Stacked)
- Command Injection (OS command execution)
- LDAP Injection (LDAP query injection)
- XPath Injection (XML path injection)

#### Web Security
- XSS (Reflected, Stored, DOM-based)
- CSRF (Cross-Site Request Forgery)
- File Upload Vulnerabilities
- XXE (XML External Entity)
- Authentication Testing
- SSL/TLS Configuration
- Security Headers Analysis

#### Network Reconnaissance
- Port Scanning (TCP/UDP)
- DNS Enumeration
- Banner Grabbing
- Service Detection
- Proxy Configuration

#### Encoding/Decoding
- Base64, URL, Hex, HTML, ROT13
- Multiple hashing algorithms
- Real-time encoding/decoding

---

## 📋 Web API Endpoints

### Authentication
```
POST   /register           - User registration
POST   /login              - User login
GET    /logout             - User logout
```

### Dashboard & Scans
```
GET    /dashboard          - Main dashboard
GET    /scans              - View all scans
POST   /scan/new           - Create new scan
GET    /scan/<id>          - View specific scan
```

### Findings & Reports
```
GET    /findings           - View all vulnerabilities
GET    /reports            - View generated reports
POST   /api/report/generate - Generate report
```

### API Routes
```
GET    /api/config/modes   - Get available modes
POST   /api/scan/start     - Start scan via API
GET    /api/scan/<id>      - Get scan status
GET    /api/stats          - Get user statistics
PUT    /api/settings       - Update settings
```

---

## 🔧 Configuration

### Default Credentials
- **Username**: `admin`
- **Password**: `ADMIN1234`

⚠️ Change these in production!

### Environment Variables

```bash
FLASK_ENV=production
SECRET_KEY=your-very-secure-key-here
DATABASE_URL=sqlite:///purplehat.db
PORT=5000
```

### Configuration File (`config.json`)

```json
{
  "webui": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false
  },
  "settings": {
    "timeout": 5,
    "retries": 3
  }
}
```

---

## 📊 Web Dashboard Features

### User Registration
- Email verification
- Strong password requirements
- Profile management

### Dashboard
- Real-time scan statistics
- Severity breakdown (Critical/High/Medium/Low)
- Recent scan history
- Quick action buttons

### Scan Management
- Create new scans with target input
- Select mode (Ready-To-Go or Professional)
- Monitor scan progress
- View detailed results

### Findings Analysis
- Filter by type and severity
- Copy payloads to clipboard
- View remediation advice
- Export findings

### Report Generation
- Multiple export formats
- Customizable templates
- Scheduled reports (coming soon)

---

## 🛠️ System Requirements

- **Python**: 3.8+
- **Database**: SQLite (default), MySQL, PostgreSQL
- **Memory**: 512MB minimum
- **Disk Space**: 1GB minimum
- **Network**: Internet connection for updates

### Platform Support

| OS | Status | Notes |
|----|--------|-------|
| Linux | ✅ Fully Supported | Ubuntu 18.04+ recommended |
| macOS | ✅ Fully Supported | 10.14+ recommended |
| Windows | ✅ Fully Supported | Windows 10+ (WSL2 recommended) |

---

## 📦 Deployment Options

### Local Development
```bash
python -m ui.webapp_v3
```

### Docker
```bash
docker build -t purple-hat:latest .
docker run -p 5000:5000 purple-hat:latest
```

### Docker Compose
```bash
docker-compose up -d
```

### Render.com
See `RENDER_DEPLOYMENT.md` for detailed instructions

### Production (Gunicorn + Nginx)
```bash
gunicorn --workers 4 --threads 2 --worker-class gthread ui.webapp_v3:app
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [INSTALLATION.md](INSTALLATION.md) | Platform-specific installation |
| [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md) | Render.com deployment |
| [QUICK_START.md](QUICK_START.md) | 5-minute quick reference |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Developer guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) | v2.0 enhancements |

---

## 🔒 Security

### Best Practices
- ✅ Change default credentials immediately
- ✅ Use HTTPS in production
- ✅ Enable database backups
- ✅ Regular security updates
- ✅ Monitor access logs
- ✅ Use strong SECRET_KEY

### Reporting Security Issues
Please report security vulnerabilities responsibly to: security@purplehat.io

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Format code
black ui/ core/ modules/ utils/

# Lint
flake8 ui/ core/ modules/ utils/
```

---

## 📈 Roadmap

### Version 2.1 (Q1 2025)
- [ ] Machine Learning detection
- [ ] GraphQL testing module
- [ ] API security assessment
- [ ] WebSocket testing

### Version 2.2 (Q2 2025)
- [ ] Custom payload editor
- [ ] Exploit generation
- [ ] Advanced reporting
- [ ] CVSS scoring

### Version 3.0 (Q3 2025)
- [ ] Distributed scanning
- [ ] REST API v2
- [ ] Browser extension
- [ ] CLI improvements

---

## 📞 Support & Contact

- **GitHub Issues**: Bug reports and features
- **GitHub Discussions**: Questions and ideas
- **Email**: security@purplehat.io
- **Documentation**: Full docs in `/docs`

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

⚠️ **Disclaimer**: PURPLE HAT is for authorized security testing only. Unauthorized access to computer systems is illegal.

---

## 🙏 Acknowledgments

Built with modern Python frameworks:
- Flask 2.0+
- SQLAlchemy 1.4+
- Flask-Login
- Docker
- Gunicorn

---

## 🎉 Version History

### v2.0.0 (December 2025)
- ✨ Complete overhaul from v1.0
- ✨ Database integration with user accounts
- ✨ Modern web dashboard
- ✨ Two operating modes (Ready-To-Go & Professional)
- ✨ 100% English internationalization
- ✨ Docker & Render deployment support
- ✨ Comprehensive documentation
- ✨ Professional branding with logo

### v1.0.0 (Previous)
- Basic security testing framework
- Korean language interface
- Terminal-only UI

---

**PURPLE HAT v2.0 - Ready for Production Deployment** 🚀

Last Updated: December 3, 2025  
Status: ✅ Production Ready  
Quality: ⭐⭐⭐⭐⭐


### 환경 변수 (선택)
- 로컬에 포함된 sqlmap을 사용하려면 `PURPLEHAT_SQLMAP_PATH` 환경 변수로 `sqlmap.py`의 경로를 지정할 수 있습니다.
	예: `export PURPLEHAT_SQLMAP_PATH="/Users/krx/Documents/Hack/PURPLEHAT/sqlmap-master copy/sqlmap.py"`

### 권장 실행 방법 (macOS)
1. 의존성 확인: Python 3.7 이상 설치
2. (옵션) 터미널에서 sqlmap을 사용할 경우 환경변수 설정:

```bash
export PURPLEHAT_SQLMAP_PATH="/absolute/path/to/sqlmap.py"
```

3. 아래로 이동 후 실행:

```bash
cd DEEP_PURPLE
python3 main.py
```

### GUI (웹 앱) — 더 읽기 쉬운 인터페이스
PURPLE HAT은 간단한 로컬 웹 UI를 제공합니다. 의존성을 먼저 설치하세요:

```bash
cd DEEP_PURPLE
python3 -m pip install -r requirements.txt
```

웹 앱을 실행하려면:

```bash
python3 -m ui.webapp
```

브라우저에서 http://127.0.0.1:5000/ 로 접속하면 자동화 워크플로(포트 스캔, sqlmap 검사, XSS 시도)를 실행할 수 있습니다. 결과는 구조화된 JSON과 원시 출력을 바로 확인하고 파일로 저장할 수 있습니다.

### 기본 로그인 정보
웹 UI 기본 계정 (config.json에 저장됨):
- Username: ADMIN
- Password: ADMIN1234

변경하려면 `config.json` → `webui` 섹션에서 수정하세요.

### 실행 팁
- `Findings & Reports` 메뉴에서 탐지 결과를 확인하고, raw output을 파일로 저장할 수 있습니다.
- `Network Tools → Port Scanner`는 배너 샘플과 서비스 정보를 자동으로 보여주고, 결과는 보고서에 구조화된 항목으로 기록됩니다.

## 🎨 인터페이스 특징

- **모던 디자인**: 컬러풀한 터미널 UI
- **직관적 네비게이션**: 계층적 메뉴 구조
- **실시간 클립보드 복사**: 페이로드 즉시 복사
- **상세 결과 표시**: 박스 형식의 깔끔한 출력

## 📦 프로젝트 구조

```
DEEP_PURPLE/
├── core/              # 핵심 엔진
│   └── engine.py     # 모든 모듈 통합
├── modules/          # 기능 모듈
│   ├── injection/    # 주입 공격 모듈
│   ├── web_security/ # 웹 보안 모듈
│   ├── encoding/     # 인코딩 모듈
│   └── network/      # 네트워크 모듈
├── ui/               # 사용자 인터페이스
│   ├── renderer.py   # 터미널 렌더링
│   └── menu.py       # 메뉴 시스템
├── utils/            # 유틸리티
│   └── helpers.py    # 헬퍼 함수
└── main.py           # 메인 애플리케이션
```

## 사용 예시

### SQL Injection 페이로드 생성

```
1. Main Menu → Injection Testing
2. SQL Injection Techniques
3. Union Based Payloads
4. 원하는 페이로드 선택
5. 자동으로 클립보드에 복사됨
```

### XSS 페이로드 테스트

```
1. Main Menu → Web Security
2. XSS Testing
3. 원하는 XSS 페이로드 선택
4. 클립보드에 복사
```

### 포트 스캔

```
1. Main Menu → Network Tools
2. Port Scanner
3. 호스트 주소 입력
4. Common Ports 또는 Custom Range 선택
```

## 🛡️ 보안 고지사항

> **중요**: Purple Hat은 **교육 목적** 및 **정당한 보안 테스트**에만 사용해주세요.
> 
> 타인의 시스템에 대한 무단 테스트는 불법입니다.
> 사용자는 모든 법적 책임을 져야 합니다.
> **이 소프트웨어를 불법적으로 사용하여 발생하는 모든 책임은 사용자에게 있으며,**
> **개발자는 어떠한 법적·물리적 손해에 대해서도 책임을 지지 않습니다.**

## 💡 기술 스택

- **Python 3**: 핵심 로직
- **ANSI Escape Codes**: 터미널 색상 및 스타일
- **Standard Library**: 네트워크, 암호화 등

## 🔄 지속적 개선 로드맵

- [ ] 웹 드라이버 기반 자동화 (Selenium)
- [ ] 분산 스캔 및 병렬 처리
- [ ] 고급 필터 우회 기법
- [ ] GUI 인터페이스 (PyQt6)
- [ ] API 모드 (REST)
- [ ] 결과 보고서 생성 (PDF, HTML)

## 📄 라이센스

MIT License - 자유롭게 사용, 수정, 배포 가능

## 🙏 기여

버그 리포트 및 기능 제안은 환영합니다!

---

**Made with LOVE FOR Security Researchers**
