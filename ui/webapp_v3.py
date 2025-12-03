"""
PURPLE HAT Web Application - Enhanced UI with Mode Selection
"""

import os
import sys
import json
from datetime import datetime
from functools import wraps

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from core.modes import ConfigurationManager, ScanMode
from core.engine import PurpleHatEngine
from utils.advanced import SessionManager, ReportGenerator
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'purple-hat-dev-key-change-in-production')

# Load configuration
CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'config.json')
with open(CONFIG_FILE, 'r') as f:
    CONFIG = json.load(f)

# Initialize managers
config_mgr = ConfigurationManager()
engine = PurpleHatEngine()
session_mgr = SessionManager()
report_gen = ReportGenerator()

# User management
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, username, user_id=1):
        self.id = user_id
        self.username = username


@login_manager.user_loader
def load_user(user_id):
    return User(CONFIG['webui'].get('admin_username', 'admin'), user_id)


def check_credentials(username, password):
    """Check if credentials match config"""
    config_user = CONFIG['webui'].get('admin_username', 'admin')
    config_pass = CONFIG['webui'].get('admin_password', 'ADMIN1234')
    return username == config_user and password == config_pass


# Routes

@app.route('/')
def index():
    """Main landing page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if check_credentials(username, password):
            user = User(username)
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with mode selection"""
    stats = {
        'total_scans': 0,
        'vulnerabilities_found': 0,
        'recent_scans': []
    }
    return render_template('dashboard.html', stats=stats)


@app.route('/scan')
@login_required
def scan():
    """Scanning interface"""
    return render_template('scan.html', modes=['ready_to_go', 'professional'])


@app.route('/api/config/modes')
@login_required
def api_get_modes():
    """Get available scanning modes"""
    return jsonify({
        'modes': [
            {
                'id': 'ready_to_go',
                'name': 'Ready-To-Go Mode',
                'description': 'Automated scanning with intelligent defaults. Perfect for quick assessments.',
                'features': [
                    'Optimized thread counts',
                    'Limited payload sets (50 payloads)',
                    'Common port scanning (1-1000)',
                    'Fast execution (5-10 seconds)',
                    'Automatic best practices'
                ],
                'config': {
                    'timeout': 5,
                    'retries': 2,
                    'sql_injection_threads': 10,
                    'port_scan_range': '1-1000'
                }
            },
            {
                'id': 'professional',
                'name': 'Professional Mode',
                'description': 'Advanced testing with full customization. For thorough security assessments.',
                'features': [
                    'Granular control over parameters',
                    'Full payload database (500 payloads)',
                    'Complete port range (1-65535)',
                    'Extended timeout (15 seconds)',
                    'Advanced logging & verbosity'
                ],
                'config': {
                    'timeout': 15,
                    'retries': 5,
                    'sql_injection_threads': 5,
                    'port_scan_range': '1-65535'
                }
            }
        ]
    })


@app.route('/api/config/set-mode', methods=['POST'])
@login_required
def api_set_mode():
    """Set scanning mode"""
    data = request.get_json()
    mode = data.get('mode')
    
    if mode == 'ready_to_go':
        config_mgr.load_ready_to_go()
    elif mode == 'professional':
        config_mgr.load_professional()
    else:
        return jsonify({'error': 'Invalid mode'}), 400
    
    return jsonify({
        'success': True,
        'mode': mode,
        'config': config_mgr.get_config_dict()
    })


@app.route('/api/config/update', methods=['POST'])
@login_required
def api_update_config():
    """Update configuration parameters"""
    data = request.get_json()
    
    try:
        config_mgr.update_config(**data)
        return jsonify({
            'success': True,
            'config': config_mgr.get_config_dict()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/start', methods=['POST'])
@login_required
def api_start_scan():
    """Start a new scan"""
    data = request.get_json()
    target = data.get('target')
    modules = data.get('modules', [])
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        # Create scan session
        scan_id = session_mgr.create_session(target, current_user.username)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'target': target,
            'status': 'running',
            'started_at': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<scan_id>')
@login_required
def api_get_scan(scan_id):
    """Get scan details and progress"""
    try:
        # Load scan session
        session_data = session_mgr.load_session(f"{scan_id}.json")
        return jsonify(session_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 404


@app.route('/api/results')
@login_required
def api_get_results():
    """Get all scan results"""
    try:
        results_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'results')
        results = []
        
        if os.path.exists(results_dir):
            for file in os.listdir(results_dir):
                if file.endswith('.json'):
                    with open(os.path.join(results_dir, file), 'r') as f:
                        results.append(json.load(f))
        
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/report/generate', methods=['POST'])
@login_required
def api_generate_report():
    """Generate scan report"""
    data = request.get_json()
    scan_id = data.get('scan_id')
    format_type = data.get('format', 'html')
    
    try:
        # Load scan results
        session_data = session_mgr.load_session(f"{scan_id}.json")
        
        # Generate report
        report = report_gen.generate_report(
            scan_results=session_data,
            format=format_type,
            include_remediation=True,
            include_statistics=True
        )
        
        return jsonify({
            'success': True,
            'report': report,
            'format': format_type
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/results')
@login_required
def results():
    """Results page"""
    return render_template('results.html')


@app.route('/settings')
@login_required
def settings():
    """Settings page"""
    current_config = config_mgr.get_config_dict()
    return render_template('settings.html', config=current_config)


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, message='Page not found'), 404


@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {error}")
    return render_template('error.html', code=500, message='Server error'), 500


# Health check
@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'version': '2.0.0'})


if __name__ == '__main__':
    host = CONFIG['webui'].get('host', '127.0.0.1')
    port = CONFIG['webui'].get('port', 5000)
    debug = CONFIG['webui'].get('debug', False)
    
    logger.info(f"Starting PURPLE HAT Web Interface on {host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
