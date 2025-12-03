"""
Database Models for PURPLE HAT
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import hashlib
import os

db = SQLAlchemy()


class User(UserMixin, db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    def check_password(self, password):
        """Verify password"""
        return self.password_hash == hashlib.sha256(password.encode()).hexdigest()
    
    def __repr__(self):
        return f'<User {self.username}>'


class Scan(db.Model):
    """Scan model for tracking scans"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    mode = db.Column(db.String(50), nullable=False)  # 'ready_to_go' or 'professional'
    status = db.Column(db.String(50), nullable=False, default='pending')  # pending, running, completed, failed
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    findings_count = db.Column(db.Integer, default=0)
    vulnerabilities_count = db.Column(db.Integer, default=0)
    scan_data = db.Column(db.JSON)
    
    # Relationships
    findings = db.relationship('Finding', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    @property
    def duration(self):
        """Get scan duration in seconds"""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def __repr__(self):
        return f'<Scan {self.id} on {self.target}>'


class Finding(db.Model):
    """Finding model for vulnerabilities"""
    __tablename__ = 'findings'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    finding_type = db.Column(db.String(100), nullable=False)  # SQL Injection, XSS, etc.
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low, Info
    target = db.Column(db.String(255))
    payload = db.Column(db.Text)
    response = db.Column(db.Text)
    metadata = db.Column(db.JSON)
    remediation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Finding {self.finding_type} ({self.severity})>'


class Report(db.Model):
    """Report model for generated reports"""
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    report_type = db.Column(db.String(50), nullable=False)  # json, html, pdf, csv
    content = db.Column(db.LargeBinary)
    filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Report {self.title}>'


class Config(db.Model):
    """Configuration model for user settings"""
    __tablename__ = 'config'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    default_mode = db.Column(db.String(50), default='ready_to_go')
    timeout = db.Column(db.Integer, default=5)
    retries = db.Column(db.Integer, default=2)
    sql_payloads_count = db.Column(db.Integer, default=50)
    port_range = db.Column(db.String(50), default='1-1000')
    threads_count = db.Column(db.Integer, default=10)
    verbose = db.Column(db.Boolean, default=False)
    ssl_verify = db.Column(db.Boolean, default=True)
    proxy_enabled = db.Column(db.Boolean, default=False)
    proxy_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Config for user {self.user_id}>'
