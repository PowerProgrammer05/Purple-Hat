# 🎯 PURPLE HAT - Modern Security Testing Framework


> 보안 테스트 통합 프레임워크

## 주요 기능

### Injection Testing (주입 공격 테스트)
- **SQL Injection**: Union-based, Time-based, Boolean-based, Error-based, Stacked
- **Command Injection**: 시스템 명령어 주입 테스트
- **LDAP Injection**: LDAP 쿼리 주입
- **XPath Injection**: XML 경로식 주입

### Web Security (웹 보안)
- **XSS (Cross-Site Scripting)**: Reflected, Stored, DOM-based
- **CSRF (Cross-Site Request Forgery)**: CSRF HTML 생성
- **File Upload**: 악의적 파일명, 웹쉘 생성
- **XXE (XML External Entity)**: XXE 페이로드
- **Authentication**: 비밀번호 강도 분석, 공통 인증정보
- **SSL/TLS**: 약한 프로토콜/암호 검사
- **Security Headers**: 보안 헤더 점검

### Encoding/Decoding (인코딩/디코딩)
- Base64, URL, Hex, HTML, ROT13, Caesar
- 다양한 해싱 알고리즘 (MD5, SHA1, SHA256, SHA512)
- 실시간 인코딩/디코딩

### Network Tools (네트워크 도구)
- **Port Scanner**: TCP 포트 스캔, 서비스 감지
- **DNS Enumeration**: DNS 정보 수집, 서브도메인 열거
- **Network Reconnaissance**: 배너 그래빙, 정보 수집
- **Proxy Configuration**: 프록시 설정

### Help System (도움말)
- 모든 기능에 대한 상세 설명
- 공격 기법별 예시 페이로드
- 즉시 클립보드 복사 기능

## 설치 및 실행

### 요구사항
- Python 3.7+
- macOS/Linux/Windows

### 빠른 시작

```bash
cd DEEP_PURPLE
python3 main.py
```

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
