import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from core import PurpleHatEngine
from modules.automation.advanced_automator import AdvancedAutomator
from utils.database import init_db, get_db, Target, Scan, Result, ScanStatusEnum, VulnerabilityTypeEnum, SessionLocal
from dotenv import load_dotenv
import json
from datetime import datetime
from functools import wraps

load_dotenv()

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('PURPLEHAT_SESSION_KEY', 'purplehat-session-secret')
app.results_history = []

try:
    init_db()
except Exception as e:
    print(f"Database init warning: {e}")

engine = PurpleHatEngine()
automator = engine.get_module('automation', 'automator')
advanced_automator = AdvancedAutomator()


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('user'):
            return f(*args, **kwargs)
        return redirect(url_for('login'))
    return wrapped


@app.route('/', methods=['GET'])
def index():
    if session.get('user'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    cfg = {}
    try:
        cfg = json.load(open(os.path.join(os.path.dirname(__file__), '..', 'config.json')))
    except Exception:
        pass
    webui = cfg.get('webui', {})
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        if user == webui.get('user') and pw == webui.get('password'):
            session['user'] = user
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    db = SessionLocal()
    try:
        stats = {
            'total_targets': db.query(Target).count(),
            'total_scans': db.query(Scan).count(),
            'total_results': db.query(Result).count(),
            'high_severity': db.query(Result).filter(Result.severity == 'high').count(),
        }
        recent_scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(10).all()
    finally:
        db.close()
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/scan/auto', methods=['POST'])
@login_required
def scan_auto():
    target = request.form.get('target')
    techniques = request.form.getlist('techniques') or ['port_scan', 'sql_injection', 'xss']
    threads = int(request.form.get('threads') or 8)

    if not target:
        return jsonify({'error': 'Missing target'}), 400

    result = advanced_automator.discover_and_test(target, techniques=techniques, threads=threads)

    db = SessionLocal()
    try:
        tgt = db.query(Target).filter(Target.url == target).first()
        if not tgt:
            tgt = Target(url=target, hostname=target.split('/')[2] if '//' in target else target)
            db.add(tgt)
            db.commit()

        scan = Scan(target_id=tgt.id, scan_type='auto_discovery', status=ScanStatusEnum.completed, raw_output=json.dumps(result))
        db.add(scan)
        db.commit()

        for tech, res in result.get('results', {}).items():
            title = f"{tech} - Auto Discovery"
            desc = json.dumps(res)
            vulnerability_type = VulnerabilityTypeEnum.sql_injection if 'sql' in tech else VulnerabilityTypeEnum.xss
            vuln = Result(target_id=tgt.id, scan_id=scan.id, vulnerability_type=vulnerability_type, severity='medium', title=title, description=desc)
            db.add(vuln)
        db.commit()
    finally:
        db.close()

    app.results_history.insert(0, {'type': 'auto_scan', 'target': target, 'results': result})
    return render_template('results.html', target=target, data=json.dumps(result, indent=2, default=str))


@app.route('/scan/ports', methods=['POST'])
@login_required
def scan_ports():
    host = request.form.get('host')
    ports = request.form.get('ports')
    threads = int(request.form.get('threads') or 20)
    ports_list = None
    if ports:
        try:
            ports_list = [int(p.strip()) for p in ports.split(',') if p.strip()]
        except Exception:
            ports_list = None

    sc = engine.get_module('network', 'scanner')
    results = sc.scan_ports_detailed(host, ports_list or [], threads=threads)
    entry = {'type': 'ports', 'target': host, 'results': results}
    app.results_history.insert(0, entry)

    db = SessionLocal()
    try:
        tgt = db.query(Target).filter(Target.hostname == host).first()
        if not tgt:
            tgt = Target(url=f"http://{host}", hostname=host)
            db.add(tgt)
            db.commit()

        for port, info in results.items():
            if info.get('open'):
                vuln = Result(target_id=tgt.id, vulnerability_type=VulnerabilityTypeEnum.open_port, severity='low', title=f"Port {port} Open ({info.get('service')})", description=info.get('banner', ''))
                db.add(vuln)
        db.commit()
    finally:
        db.close()

    return render_template('results.html', target=host, data=json.dumps(entry, indent=2))


@app.route('/scan/sqlmap', methods=['POST'])
@login_required
def scan_sqlmap():
    target = request.form.get('target')
    args = request.form.get('args')
    sqlmap_mod = engine.get_module('injection', 'sqlmap')
    if not sqlmap_mod or not sqlmap_mod.is_available():
        entry = {'error': 'sqlmap not available'}
        app.results_history.insert(0, {'type': 'sqlmap', 'target': target or args, 'results': entry})
        return render_template('results.html', target=target, data=json.dumps(entry, indent=2))

    if args:
        args_list = args.split()
        out = sqlmap_mod.run_and_parse(args_list)
    else:
        out = sqlmap_mod.run_and_parse(['-u', target, '--batch', '--level=1', '--risk=1'])

    entry = {'type': 'sqlmap', 'target': target, 'results': out}
    app.results_history.insert(0, entry)

    db = SessionLocal()
    try:
        tgt = db.query(Target).filter(Target.url == target).first()
        if not tgt:
            tgt = Target(url=target, hostname=target.split('/')[2] if '//' in target else target)
            db.add(tgt)
            db.commit()

        parsed = out.get('parsed', {})
        if parsed.get('issues'):
            for issue in parsed.get('issues', [])[:5]:
                vuln = Result(target_id=tgt.id, vulnerability_type=VulnerabilityTypeEnum.sql_injection, severity='high', title='SQL Injection Found', description=issue, confidence=0.85)
                db.add(vuln)
        db.commit()
    finally:
        db.close()

    return render_template('results.html', target=target, data=json.dumps(entry, indent=2, default=str))


@app.route('/scan/xss', methods=['POST'])
@login_required
def scan_xss():
    target = request.form.get('target')
    param = request.form.get('param') or 'q'
    xss_mod = engine.get_module('web_security', 'xss')
    results = []
    if xss_mod:
        import requests
        for p in xss_mod.generate_payloads()[:8]:
            try:
                r = requests.get(target, params={param: p}, timeout=8, verify=False)
                refl = p in (r.text or '')
                results.append({'payload': p, 'reflected': refl})
            except Exception as e:
                results.append({'payload': p, 'error': str(e)})

    entry = {'type': 'xss', 'target': target, 'results': results}
    app.results_history.insert(0, entry)

    db = SessionLocal()
    try:
        tgt = db.query(Target).filter(Target.url == target).first()
        if not tgt:
            tgt = Target(url=target, hostname=target.split('/')[2] if '//' in target else target)
            db.add(tgt)
            db.commit()

        xss_count = sum(1 for r in results if r.get('reflected'))
        if xss_count > 0:
            vuln = Result(target_id=tgt.id, vulnerability_type=VulnerabilityTypeEnum.xss, severity='high', title=f'XSS Reflected ({xss_count} payloads)', description=json.dumps(results), confidence=0.8)
            db.add(vuln)
            db.commit()
    finally:
        db.close()

    return render_template('results.html', target=target, data=json.dumps(entry, indent=2))


@app.route('/findings')
@login_required
def findings():
    return render_template('findings.html', items=app.results_history)


@app.route('/results')
@login_required
def view_results():
    db = SessionLocal()
    try:
        results = db.query(Result).order_by(Result.found_at.desc()).limit(50).all()
    finally:
        db.close()
    return render_template('view_results.html', results=results)


@app.route('/targets')
@login_required
def view_targets():
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
    finally:
        db.close()
    return render_template('view_targets.html', targets=targets)


@app.route('/api/auto-scan', methods=['POST'])
@login_required
def api_auto_scan():
    payload = request.json or {}
    target = payload.get('target')
    techniques = payload.get('techniques', ['port_scan', 'sql_injection', 'xss'])
    threads = payload.get('threads', 8)
    result = advanced_automator.discover_and_test(target, techniques=techniques, threads=threads)
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
