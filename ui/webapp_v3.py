"""
PURPLE HAT Web Application v3 - Enhanced with Database, Registration, and More Features
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

from models import db, User, Scan, Finding, Report, Config
from core.modes import ConfigurationManager, ScanMode
from core.engine import PurpleHatEngine
from modules.advanced_tools import (
    ReverseShellGenerator, WebShellGenerator, PayloadEncoder,
    ExploitPayloads, PrivilegeEscalation, CredentialTheft,
    NetworkExploit, AntiForensics, SecurityBypass
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'purple-hat-dev-key-change-in-production-2024')

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///purplehat.db')
if DATABASE_URL.startswith('sqlite:///'):
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Initialize database and login manager
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Load configuration
CONFIG_FILE = os.path.join(os.path.dirname(__file__), '..', 'config.json')
with open(CONFIG_FILE, 'r') as f:
    CONFIG = json.load(f)

# Initialize managers
config_mgr = ConfigurationManager()
engine = PurpleHatEngine()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==================== Routes ====================

@app.route('/')
def index():
    """Main landing page - show animated splash if not logged in"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    # render a splash animation then it will redirect client-side to /login
    return render_template('splash.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        
        # Validation
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        
        if not email or '@' not in email:
            errors.append('Invalid email address')
        
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters long')
        
        if password != confirm_password:
            errors.append('Passwords do not match')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists')
        
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered')
        
        if errors:
            return render_template('register.html', errors=errors, username=username, email=email, full_name=full_name)
        
        # Create new user
        try:
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                is_active=True
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            # Create default config for user
            user_config = Config(user_id=user.id)
            db.session.add(user_config)
            db.session.commit()
            
            logger.info(f"New user registered: {username}")
            
            # Auto login
            login_user(user)
            return redirect(url_for('dashboard'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            errors.append(f'Registration failed: {str(e)}')
            return render_template('register.html', errors=errors, username=username, email=email, full_name=full_name)
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Username and password required')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
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
    """Main dashboard"""
    # Get user statistics
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    total_findings = Finding.query.join(Scan).filter(Scan.user_id == current_user.id).count()
    
    # Recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).limit(5).all()
    
    # Severity breakdown
    critical = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'Critical').count()
    high = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'High').count()
    medium = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'Medium').count()
    low = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'Low').count()
    
    stats = {
        'total_scans': total_scans,
        'total_findings': total_findings,
        'critical_count': critical,
        'high_count': high,
        'medium_count': medium,
        'low_count': low,
        'recent_scans': recent_scans
    }
    
    return render_template('dashboard.html', stats=stats)


@app.route('/scans')
@login_required
def scans():
    """View all scans"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    pagination = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).paginate(page=page, per_page=per_page)
    scans_list = pagination.items
    
    return render_template('scans.html', scans=scans_list, pagination=pagination)


@app.route('/scan/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Start new scan"""
    if request.method == 'POST':
        data = request.get_json()
        
        target = data.get('target', '').strip()
        mode = data.get('mode', 'ready_to_go')
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Create scan record
        scan = Scan(
            user_id=current_user.id,
            target=target,
            mode=mode,
            status='pending'
        )
        
        db.session.add(scan)
        db.session.commit()
        
        logger.info(f"New scan created: {scan.id} on {target}")
        
        return jsonify({
            'id': scan.id,
            'target': scan.target,
            'mode': scan.mode,
            'status': scan.status,
            'created_at': scan.started_at.isoformat()
        })
    
    return render_template('scan.html')


@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """View specific scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Check authorization
    if scan.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    
    findings_list = Finding.query.filter_by(scan_id=scan_id).all()
    
    return render_template('scan_detail.html', scan=scan, findings=findings_list)


@app.route('/findings')
@login_required
def findings():
    """View all findings"""
    filter_type = request.args.get('type', '')
    filter_severity = request.args.get('severity', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    query = Finding.query.join(Scan).filter(Scan.user_id == current_user.id)
    
    if filter_type:
        query = query.filter(Finding.finding_type == filter_type)
    
    if filter_severity:
        query = query.filter(Finding.severity == filter_severity)
    
    pagination = query.order_by(Finding.created_at.desc()).paginate(page=page, per_page=per_page)
    findings_list = pagination.items
    
    return render_template('findings.html', findings=findings_list, pagination=pagination)


@app.route('/settings')
@login_required
def settings():
    """User settings"""
    user_config = Config.query.filter_by(user_id=current_user.id).first()
    
    if not user_config:
        user_config = Config(user_id=current_user.id)
        db.session.add(user_config)
        db.session.commit()
    
    return render_template('settings.html', config=user_config)


@app.route('/mypage')
@login_required
def mypage():
    """User profile and account information"""
    user = current_user
    
    # Get user statistics
    total_scans = Scan.query.filter_by(user_id=user.id).count()
    total_findings = Finding.query.join(Scan).filter(Scan.user_id == user.id).count()
    
    # Get finding severity breakdown
    critical = Finding.query.join(Scan).filter(Scan.user_id == user.id, Finding.severity == 'Critical').count()
    high = Finding.query.join(Scan).filter(Scan.user_id == user.id, Finding.severity == 'High').count()
    
    # Recent scans
    recent_scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.started_at.desc()).limit(5).all()
    
    stats = {
        'total_scans': total_scans,
        'total_findings': total_findings,
        'critical_findings': critical,
        'high_findings': high,
        'member_since': user.created_at,
        'recent_scans': recent_scans
    }
    
    return render_template('mypage.html', user=user, stats=stats)


@app.route('/reports')
@login_required
def reports():
    """View all reports"""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    pagination = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).paginate(page=page, per_page=per_page)
    reports_list = pagination.items
    
    return render_template('reports.html', reports=reports_list, pagination=pagination)


# ==================== API Routes ====================

@app.route('/api/config/modes')
@login_required
def api_get_modes():
    """Get available scanning modes"""
    return jsonify({
        'modes': [
            {
                'id': 'ready_to_go',
                'name': 'Ready-To-Go Mode',
                'description': 'Automated scanning with intelligent defaults.',
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
                    'sql_payloads': 50,
                    'port_range': '1-1000',
                    'threads': 10
                }
            },
            {
                'id': 'professional',
                'name': 'Professional Mode',
                'description': 'Advanced testing with full customization.',
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
                    'sql_payloads': 500,
                    'port_range': '1-65535',
                    'threads': 50
                }
            }
        ]
    })


@app.route('/api/scan/start', methods=['POST'])
@login_required
def api_start_scan():
    """Start a scan via API"""
    data = request.get_json()
    target = data.get('target', '').strip()
    mode = data.get('mode', 'ready_to_go')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    try:
        scan = Scan(
            user_id=current_user.id,
            target=target,
            mode=mode,
            status='running'
        )
        
        db.session.add(scan)
        db.session.commit()
        
        logger.info(f"Scan started: {scan.id}")
        
        return jsonify({
            'id': scan.id,
            'target': scan.target,
            'mode': scan.mode,
            'status': scan.status,
            'message': 'Scan started successfully'
        }), 201
    
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
@login_required
def api_get_scan(scan_id):
    """Get scan details"""
    scan = Scan.query.get_or_404(scan_id)
    
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    findings_list = Finding.query.filter_by(scan_id=scan_id).all()
    
    return jsonify({
        'id': scan.id,
        'target': scan.target,
        'mode': scan.mode,
        'status': scan.status,
        'started_at': scan.started_at.isoformat(),
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        'duration': scan.duration,
        'findings_count': len(findings_list),
        'vulnerabilities': [
            {
                'id': f.id,
                'type': f.finding_type,
                'severity': f.severity,
                'target': f.target,
                'remediation': f.remediation
            }
            for f in findings_list
        ]
    })


@app.route('/api/scan/<int:scan_id>/findings', methods=['GET'])
@login_required
def api_get_findings(scan_id):
    """Get findings for a scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    findings_list = Finding.query.filter_by(scan_id=scan_id).all()
    
    return jsonify({
        'total': len(findings_list),
        'findings': [
            {
                'id': f.id,
                'type': f.finding_type,
                'severity': f.severity,
                'target': f.target,
                'payload': f.payload,
                'remediation': f.remediation,
                'created_at': f.created_at.isoformat()
            }
            for f in findings_list
        ]
    })


@app.route('/api/settings', methods=['GET', 'PUT'])
@login_required
def api_settings():
    """Get or update user settings"""
    user_config = Config.query.filter_by(user_id=current_user.id).first()
    
    if not user_config:
        user_config = Config(user_id=current_user.id)
        db.session.add(user_config)
        db.session.commit()
    
    if request.method == 'PUT':
        data = request.get_json()
        
        if 'timeout' in data:
            user_config.timeout = int(data['timeout'])
        if 'retries' in data:
            user_config.retries = int(data['retries'])
        if 'threads' in data:
            user_config.threads_count = int(data['threads'])
        if 'ssl_verify' in data:
            user_config.ssl_verify = bool(data['ssl_verify'])
        if 'default_mode' in data:
            user_config.default_mode = data['default_mode']
        
        db.session.commit()
        logger.info(f"Settings updated for user {current_user.id}")
        
        return jsonify({'message': 'Settings updated'})
    
    return jsonify({
        'timeout': user_config.timeout,
        'retries': user_config.retries,
        'threads': user_config.threads_count,
        'ssl_verify': user_config.ssl_verify,
        'default_mode': user_config.default_mode,
        'proxy_enabled': user_config.proxy_enabled,
        'proxy_url': user_config.proxy_url
    })


@app.route('/api/report/<int:scan_id>/generate', methods=['POST'])
@login_required
def api_generate_report(scan_id):
    """Generate report for scan"""
    scan = Scan.query.get_or_404(scan_id)
    
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    report_type = request.json.get('type', 'json')
    
    try:
        findings_list = Finding.query.filter_by(scan_id=scan_id).all()
        
        report = Report(
            user_id=current_user.id,
            scan_id=scan_id,
            title=f"Report for {scan.target}",
            report_type=report_type,
            filename=f"report_{scan_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{report_type}"
        )
        
        db.session.add(report)
        db.session.commit()
        
        logger.info(f"Report generated: {report.id}")
        
        return jsonify({
            'id': report.id,
            'filename': report.filename,
            'created_at': report.created_at.isoformat()
        }), 201
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats')
@login_required
def api_stats():
    """Get user statistics"""
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    total_findings = Finding.query.join(Scan).filter(Scan.user_id == current_user.id).count()
    
    critical = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'Critical').count()
    high = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'High').count()
    medium = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'Medium').count()
    low = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity == 'Low').count()
    
    return jsonify({
        'total_scans': total_scans,
        'total_findings': total_findings,
        'severity': {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low
        }
    })


# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, message='Page not found'), 404


@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {error}")
    return render_template('error.html', code=500, message='Internal server error'), 500


@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', code=403, message='Access forbidden'), 403


# ==================== CLI Commands ====================

@app.cli.command()
def init_db():
    """Initialize the database"""
    db.create_all()
    print("Database initialized")


@app.cli.command()
def create_admin():
    """Create admin user"""
    username = input("Admin username: ")
    email = input("Admin email: ")
    password = input("Admin password: ")
    
    if User.query.filter_by(username=username).first():
        print("User already exists")
        return
    
    admin = User(
        username=username,
        email=email,
        is_admin=True,
        is_active=True
    )
    admin.set_password(password)
    
    db.session.add(admin)
    
    admin_config = Config(user_id=admin.id)
    db.session.add(admin_config)
    
    db.session.commit()
    print(f"Admin user {username} created successfully")


# ==================== Health Check ====================

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })


# ==================== Advanced Tools ====================

@app.route('/tools')
@login_required
def tools():
    """Advanced tools page"""
    return render_template('tools.html', user=current_user)


@app.route('/docs')
def docs_index():
    """List local documentation files (read-only)"""
    docs_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'docs'))
    try:
        files = [f for f in os.listdir(docs_dir) if f.endswith('.md')]
    except Exception:
        files = []

    # Map to github raw URLs as an option
    github_base = 'https://github.com/PowerProgrammer05/Purple-Hat/blob/main/docs'
    docs = []
    for f in files:
        docs.append({
            'name': f,
            'local_url': url_for('doc_view', fname=f),
            'github_url': f"{github_base}/{f}"
        })

    return render_template('docs_index.html', docs=docs)


@app.route('/docs/view/<path:fname>')
def doc_view(fname):
    """View a documentation file from docs/ directory (read-only)"""
    docs_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'docs'))
    safe_path = os.path.normpath(os.path.join(docs_dir, fname))
    # Prevent directory traversal
    if not safe_path.startswith(docs_dir) or not os.path.exists(safe_path):
        return render_template('error.html', code=404, message='Document not found'), 404

    try:
        with open(safe_path, 'r', encoding='utf-8') as fh:
            content = fh.read()
    except Exception as e:
        logger.error(f"Error reading doc {fname}: {e}")
        return render_template('error.html', code=500, message='Unable to read document'), 500

    github_url = f"https://github.com/PowerProgrammer05/Purple-Hat/blob/main/docs/{fname}"
    return render_template('docs_view.html', filename=fname, content=content, github_url=github_url)


@app.route('/api/tools/reverse-shell')
@login_required
def api_reverse_shell():
    """Generate reverse shell payload"""
    attacker_ip = request.args.get('ip')
    attacker_port = request.args.get('port')
    shell_type = request.args.get('type', 'bash')  # bash, python, nc, powershell, perl, php, ruby, jsp
    
    if not attacker_ip or not attacker_port:
        return jsonify({'error': 'Missing ip or port'}), 400
    
    try:
        attacker_port = int(attacker_port)
    except ValueError:
        return jsonify({'error': 'Invalid port number'}), 400
    
    generator = ReverseShellGenerator()
    methods = {
        'bash': generator.bash_reverse_shell,
        'python': generator.python_reverse_shell,
        'nc': generator.nc_reverse_shell,
        'powershell': generator.powershell_reverse_shell,
        'perl': generator.perl_reverse_shell,
        'php': generator.php_reverse_shell,
        'ruby': generator.ruby_reverse_shell,
        'jsp': generator.jsp_reverse_shell,
    }
    
    method = methods.get(shell_type)
    if not method:
        return jsonify({'error': 'Invalid shell type'}), 400
    
    payload = method(attacker_ip, attacker_port)
    
    return jsonify({
        'type': shell_type,
        'payload': payload,
        'description': f'{shell_type.upper()} reverse shell to {attacker_ip}:{attacker_port}',
        'difficulty': 'Medium'
    })


@app.route('/api/tools/webshell')
@login_required
def api_webshell():
    """Generate web shell"""
    shell_type = request.args.get('type', 'php')  # php, aspx, jsp
    
    generator = WebShellGenerator()
    shells = {
        'php_simple': (generator.php_simple_shell(), 'Simple PHP shell'),
        'php_advanced': (generator.php_advanced_shell(), 'Advanced PHP shell with features'),
        'aspx': (generator.aspx_shell(), 'ASP.NET shell'),
        'jsp': (generator.jsp_shell(), 'JSP shell'),
    }
    
    if shell_type not in shells:
        return jsonify({'error': 'Invalid shell type'}), 400
    
    code, description = shells[shell_type]
    
    return jsonify({
        'type': shell_type,
        'code': code,
        'description': description,
        'extension': {
            'php_simple': '.php',
            'php_advanced': '.php',
            'aspx': '.aspx',
            'jsp': '.jsp',
        }.get(shell_type),
        'method': 'File Upload',
        'difficulty': 'Hard'
    })


@app.route('/api/tools/payload-encoder')
@login_required
def api_payload_encoder():
    """Encode payload to bypass filters"""
    payload = request.args.get('payload', '')
    encoding = request.args.get('encoding', 'url')  # url, double_url, base64, hex, unicode, html, mixed_case
    
    if not payload:
        return jsonify({'error': 'Missing payload'}), 400
    
    encoder = PayloadEncoder()
    methods = {
        'url': encoder.url_encode,
        'double_url': encoder.double_url_encode,
        'base64': encoder.base64_encode,
        'hex': encoder.hex_encode,
        'unicode': encoder.unicode_encode,
        'html': encoder.html_encode,
        'mixed_case': encoder.mixed_case,
    }
    
    method = methods.get(encoding)
    if not method:
        return jsonify({'error': 'Invalid encoding type'}), 400
    
    encoded = method(payload)
    
    return jsonify({
        'original': payload,
        'encoded': encoded,
        'encoding': encoding,
        'length_reduction': f"{100 - (len(encoded)/len(payload)*100):.1f}%"
    })


@app.route('/api/tools/exploit-payloads')
@login_required
def api_exploit_payloads():
    """Get common exploitation payloads"""
    payload_type = request.args.get('type')  # sql, xss, cmd, traversal, xxe, ldap
    
    if not payload_type:
        return jsonify({
            'available_types': ['sql', 'xss', 'cmd', 'traversal', 'xxe', 'ldap'],
            'usage': '/api/tools/exploit-payloads?type=sql'
        }), 400
    
    payloads = ExploitPayloads.get_payloads_by_type(payload_type)
    
    if not payloads:
        return jsonify({'error': 'Invalid payload type'}), 400
    
    return jsonify({
        'type': payload_type,
        'count': len(payloads),
        'payloads': payloads
    })


@app.route('/api/tools/privilege-escalation')
@login_required
def api_privilege_escalation():
    """Get privilege escalation techniques"""
    os_type = request.args.get('os')  # linux, windows
    method = request.args.get('method')  # sudo, suid, capabilities, uac_bypass, privilege_check
    
    if not os_type:
        return jsonify({
            'os_types': ['linux', 'windows'],
            'linux_methods': ['sudo', 'suid', 'capabilities'],
            'windows_methods': ['uac_bypass', 'privilege_check']
        }), 400
    
    payloads = PrivilegeEscalation.get_escalation_payloads(os_type, method or 'sudo')
    
    if not payloads:
        return jsonify({'error': 'Invalid OS or method'}), 400
    
    return jsonify({
        'os': os_type,
        'method': method or 'sudo',
        'payloads': payloads,
        'risk_level': 'Critical'
    })


@app.route('/api/tools/credential-theft')
@login_required
def api_credential_theft():
    """Get credential dumping techniques"""
    os_type = request.args.get('os')  # linux, windows
    
    if not os_type or os_type not in ['linux', 'windows']:
        return jsonify({
            'os_types': ['linux', 'windows'],
            'usage': '/api/tools/credential-theft?os=linux'
        }), 400
    
    techniques = CredentialTheft.CREDENTIAL_DUMP.get(os_type, {})
    paths = CredentialTheft.CREDENTIAL_PATHS
    
    return jsonify({
        'os': os_type,
        'techniques': techniques,
        'common_paths': paths,
        'difficulty': 'Hard'
    })


@app.route('/api/tools/data-exfiltration')
@login_required
def api_data_exfiltration():
    """Generate data exfiltration queries"""
    data = request.args.get('data', 'test_data')
    exfil_type = request.args.get('type', 'dns')  # dns, http
    domain = request.args.get('domain', 'attacker.com')
    
    if exfil_type == 'dns':
        queries = NetworkExploit.generate_dns_exfiltration(data, domain)
        return jsonify({
            'type': 'dns',
            'queries': queries[:10],  # Show first 10
            'total': len(queries),
            'description': 'DNS queries to exfiltrate data via subdomains'
        })
    
    elif exfil_type == 'http':
        server_url = request.args.get('server', 'attacker.com:8080')
        requests_list = NetworkExploit.generate_http_exfiltration(data, server_url)
        return jsonify({
            'type': 'http',
            'requests': requests_list[:5],  # Show first 5
            'total': len(requests_list),
            'description': 'HTTP requests to exfiltrate data'
        })
    
    return jsonify({'error': 'Invalid exfiltration type'}), 400


@app.route('/api/tools/anti-forensics')
@login_required
def api_anti_forensics():
    """Get anti-forensics techniques"""
    os_type = request.args.get('os')  # linux, windows
    technique = request.args.get('technique')  # log_clear, timestamp
    
    if not os_type or os_type not in ['linux', 'windows']:
        return jsonify({
            'os_types': ['linux', 'windows'],
            'techniques': ['log_clear', 'timestamp']
        }), 400
    
    if technique == 'log_clear':
        commands = AntiForensics.LOG_CLEARING.get(os_type, [])
    elif technique == 'timestamp':
        commands = [AntiForensics.TIMESTAMP_MANIPULATION.get(os_type)]
    else:
        commands = []
    
    return jsonify({
        'os': os_type,
        'technique': technique,
        'commands': commands,
        'warning': 'Illegal in most jurisdictions - Educational purposes only'
    })


@app.route('/api/tools/waf-bypass')
@login_required
def api_waf_bypass():
    """Get WAF bypass techniques"""
    technique = request.args.get('technique')  # encoding, case_variation, comment_injection, whitespace
    
    techniques = SecurityBypass.WAF_BYPASS
    
    if technique and technique in techniques:
        return jsonify({
            'technique': technique,
            'methods': techniques[technique]
        })
    
    return jsonify({
        'available_techniques': list(techniques.keys()),
        'all_techniques': techniques
    })


# ==================== Main ====================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    logger.info(f"Starting PURPLE HAT Web Interface on {host}:{port}")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
