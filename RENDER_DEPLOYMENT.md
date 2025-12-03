# Render.com 배포 가이드

## 빠른 배포

### 방법 1: Render Dashboard에서 직접 설정

1. **Render.com 가입** → https://render.com
2. **New+ → Web Service** 클릭
3. **GitHub 연결** → Purple-Hat 레포지토리 선택

### 방법 2: render.yaml 사용 (권장)

```bash
# 1. 레포지토리에 render.yaml 파일이 있음 (자동 인식)
# 2. Render Dashboard에서 "New+" → "Web Service"
# 3. GitHub 레포 선택 → render.yaml 자동 로드
```

---

## 수동 배포 설정

### Web Service 설정값

| 설정 | 값 |
|------|-----|
| **Runtime** | Python 3.11 |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `gunicorn --bind 0.0.0.0:$PORT --workers 4 --threads 2 --worker-class gthread ui.webapp_v3:app` |
| **Health Check Path** | `/health` |
| **Environment** | production |

### 환경 변수 설정

Render Dashboard → Environment 탭에서 추가:

```
FLASK_ENV=production
SECRET_KEY=[자동생성 또는 임의의 강력한 키]
PYTHONUNBUFFERED=1
```

---

## 포트 설정

Render는 **자동으로 $PORT 환경변수** 할당 (기본값: 10000)

- ✅ `--bind 0.0.0.0:$PORT` 사용 필수
- ✅ Config.json의 포트는 무시됨
- ✅ 공개 URL 자동 생성

---

## Start Command 옵션

### 기본 (권장)
```bash
gunicorn --bind 0.0.0.0:$PORT --workers 4 --threads 2 --worker-class gthread ui.webapp_v3:app
```

### 개발용 (낮은 리소스)
```bash
gunicorn --bind 0.0.0.0:$PORT --workers 2 ui.webapp_v3:app
```

### 고성능 (더 많은 리소스)
```bash
gunicorn --bind 0.0.0.0:$PORT --workers 8 --threads 2 --worker-class gthread ui.webapp_v3:app
```

### 디버깅 (개발 전용)
```bash
python -c "from ui.webapp_v3 import app; app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))"
```

---

## 배포 후 확인

### 헬스 체크
```bash
curl https://your-app-name.onrender.com/health
# 응답: {"status": "ok", "version": "2.0.0"}
```

### 메인 페이지
```
https://your-app-name.onrender.com
```

### 로그 확인
- Render Dashboard → Logs 탭
- 실시간 로그 모니터링

---

## 트러블슈팅

### Issue: Port error (Address already in use)
```
❌ 원인: 고정 포트 사용
✅ 해결: --bind 0.0.0.0:$PORT 사용 확인
```

### Issue: Module not found
```
❌ 원인: requirements.txt 누락 패키지
✅ 해결: pip install -r requirements.txt 실행 확인
```

### Issue: Static files 404
```
❌ 원인: ui/static/ 폴더 구조 문제
✅ 해결: 
- logo.png 위치 확인: ui/static/images/logo.png
- CSS 위치 확인: ui/static/css/style.css
- JS 위치 확인: ui/static/js/main.js
```

### Issue: Database connection
```
❌ 원인: config.json DB 설정 오류
✅ 해결: SQLite 사용 또는 RDS 연결 문자열 확인
```

---

## 보안 권장사항

### 배포 전 확인 사항

```python
# config.json 확인
✅ debug: false
✅ SECRET_KEY: 복잡한 문자열
✅ verify_ssl: true
✅ proxy_enabled: 필요시만 활성화
```

### 환경 변수 최소화
```bash
FLASK_ENV=production
SECRET_KEY=[강력한 키]
# 다른 민감 정보는 Render Secrets 사용
```

---

## 성능 최적화

### Gunicorn 워커 설정
```
Free Plan: --workers 2
Standard Plan: --workers 4-8
Professional: --workers 8-16
```

### 메모리 제한
```bash
# Render Free: 512MB
# 기본 Flask: ~100MB
# 기본 DB 커넥션 풀: ~200MB
# 여유: ~200MB
```

---

## 모니터링

### Render 메트릭스
- CPU 사용률
- 메모리 사용률
- 응답 시간 (ms)
- 요청/분

### 로그 레벨 설정
```python
# webapp_v3.py
import logging
logging.basicConfig(level=logging.INFO)  # INFO 권장
```

---

## 비용 절감 팁

- Free Tier: 이론적으로 무료 (다만 활동 필요)
- Paid Tier 필요시: $7/월부터 시작
- DB 추가: Render PostgreSQL $7/월

---

## 다음 단계

✅ render.yaml 파일로 배포
✅ 헬스 체크 엔드포인트 확인 (/health)
✅ 환경 변수 설정 완료
✅ 로그 모니터링 설정
✅ 정기적 백업 설정

---

**PURPLE HAT v2.0 - Render.com 준비 완료! 🚀**
