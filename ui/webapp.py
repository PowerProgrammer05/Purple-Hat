import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from core import PurpleHatEngine
import json

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('PURPLEHAT_SESSION_KEY', 'purplehat-session-secret')
app.results_history = []
engine = PurpleHatEngine()
automator = engine.get_module('automation', 'automator')


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


@app.route('/run', methods=['POST'])
def run_workflow():
    target = request.form.get('target')
    ports = request.form.get('ports')
    threads = int(request.form.get('threads') or 8)
    ports_list = None
    if ports:
        try:
            ports_list = [int(p.strip()) for p in ports.split(',') if p.strip()]
        except Exception:
            ports_list = None

    if not target:
        return jsonify({'error': 'Missing target'}), 400

    data = automator.fingerprint_and_scan(target, all_ports=ports_list, threads=threads)
    app.results_history.insert(0, {'type': 'automation', 'target': target, 'results': data})
    return render_template('results.html', target=target, data=json.dumps(data, indent=2))


@app.route('/api/run', methods=['POST'])
def api_run():
    payload = request.json or {}
    target = payload.get('target')
    ports = payload.get('ports')
    threads = payload.get('threads', 8)
    data = automator.fingerprint_and_scan(target, all_ports=ports, threads=threads)
    app.results_history.insert(0, {'type': 'automation', 'target': target, 'results': data})
    return jsonify(data)


def login_required(f):
    from functools import wraps

    @wraps(f)
    def wrapped(*args, **kwargs):
        if session.get('user'):
            return f(*args, **kwargs)
        return redirect(url_for('login'))

    return wrapped


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


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
    return render_template('results.html', target=target, data=json.dumps(entry, indent=2))


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
    return render_template('results.html', target=target, data=json.dumps(entry, indent=2))


@app.route('/findings')
@login_required
def findings():
    return render_template('findings.html', items=app.results_history)


@app.route('/result/<int:idx>')
@login_required
def view_result(idx: int):
    if idx < 0 or idx >= len(app.results_history):
        return render_template('results.html', target='', data=json.dumps({'error': 'Not found'}, indent=2))
    entry = app.results_history[idx]
    return render_template('results.html', target=entry.get('target', ''), data=json.dumps(entry, indent=2))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
