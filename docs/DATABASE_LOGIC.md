# 📊 Database Logic & Architecture - Complete Explanation

## Table of Contents
1. [Database Overview](#overview)
2. [Initialization Flow](#initialization)
3. [Data Models](#models)
4. [CRUD Operations](#crud)
5. [Relationships](#relationships)
6. [Transaction Management](#transactions)
7. [Query Examples](#queries)
8. [Performance Tips](#performance)

---

## Overview

PURPLE HAT v2.0 uses **SQLAlchemy ORM** (Object-Relational Mapping) with SQLite as the default database.

### Key Concepts

**ORM (Object-Relational Mapping):** 
- Maps database tables to Python classes
- Automatic SQL generation from Python code
- Type-safe database operations

**SQLAlchemy:**
- Industry-standard Python ORM
- Supports multiple databases (SQLite, PostgreSQL, MySQL, etc.)
- Automatic schema management

**SQLite:**
- Serverless, file-based database
- Perfect for development and small deployments
- Automatically created at `purplehat.db`

---

## Initialization Flow

### Step 1: Database Configuration

```python
# ui/webapp_v3.py
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///purplehat.db'
db.init_app(app)
```

**What happens:**
- SQLAlchemy reads the database URI
- For SQLite: Creates/opens file `purplehat.db` in the app directory
- For PostgreSQL: Connects to remote server

### Step 2: Application Context

```python
with app.app_context():
    db.create_all()  # Create all tables
```

**Why needed:**
- Flask apps need an "application context" for database operations
- SQLAlchemy can't run queries outside Flask context
- `db.create_all()` inspects all model classes and creates missing tables

### Step 3: Table Creation

When `db.create_all()` runs:

```sql
-- Generated automatically from models.py
CREATE TABLE user (
    id INTEGER PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(120),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scan (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    target VARCHAR(255) NOT NULL,
    mode VARCHAR(50),
    status VARCHAR(50) DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE finding (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    finding_type VARCHAR(100),
    severity VARCHAR(20),
    meta JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);
```

---

## Data Models

### 1. User Model

```python
class User(UserMixin, db.Model):
    """User account and authentication"""
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('Scan', cascade='all, delete-orphan')
    reports = db.relationship('Report', cascade='all, delete-orphan')
    config = db.relationship('Config', uselist=False, cascade='all, delete-orphan')
    
    def set_password(self, password: str):
        """Hash and store password"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password: str) -> bool:
        """Verify password"""
        return check_password_hash(self.password_hash, password)
```

**Fields:**
- `id`: Primary key, auto-incremented
- `username`: Unique username for login
- `email`: Unique email address
- `password_hash`: Hashed password (NOT plaintext)
- `created_at`: Timestamp when user registered

**Password Security:**
```python
# When user registers
user = User(username='john', email='john@example.com')
user.set_password('MySecurePassword123!')  # Hashed automatically
db.session.add(user)
db.session.commit()

# When user logs in
user = User.query.filter_by(username='john').first()
if user and user.check_password('MySecurePassword123!'):
    login_user(user)  # Log in
```

### 2. Scan Model

```python
class Scan(db.Model):
    """Security scan record"""
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    mode = db.Column(db.String(50))  # 'ready_to_go' or 'professional'
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    findings_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='user_scans')
    findings = db.relationship('Finding', cascade='all, delete-orphan')
```

**Lifecycle:**
```
pending → running → completed (or failed)
```

**Example:**
```python
# User creates scan
scan = Scan(
    user_id=current_user.id,
    target='example.com',
    mode='ready_to_go',
    status='pending'
)
db.session.add(scan)
db.session.commit()
print(f"Created scan #{scan.id}")

# Update progress
scan.status = 'running'
db.session.commit()

# Scan completes
scan.status = 'completed'
scan.completed_at = datetime.utcnow()
scan.findings_count = len(scan.findings)
db.session.commit()
```

### 3. Finding Model

```python
class Finding(db.Model):
    """Vulnerability finding"""
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    finding_type = db.Column(db.String(100))  # 'SQL Injection', 'XSS', etc.
    severity = db.Column(db.String(20))  # 'Critical', 'High', 'Medium', 'Low'
    target = db.Column(db.String(255))  # URL/endpoint where found
    payload = db.Column(db.Text)  # The payload used
    response = db.Column(db.Text)  # Response from server
    remediation = db.Column(db.Text)  # How to fix it
    meta = db.Column(db.JSON)  # Additional metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = db.relationship('Scan', backref='scan_findings')
```

**Example with metadata:**
```python
finding = Finding(
    scan_id=scan.id,
    finding_type='SQL Injection',
    severity='Critical',
    target='https://example.com/login',
    payload="admin' OR '1'='1'--",
    remediation='Use parameterized queries',
    meta={
        'injection_type': 'union_based',
        'database': 'mysql',
        'columns_found': 4,
        'confidence': 95
    }
)
db.session.add(finding)
db.session.commit()
```

### 4. Config Model

```python
class Config(db.Model):
    """User configuration and settings"""
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timeout = db.Column(db.Integer, default=10)  # seconds
    retries = db.Column(db.Integer, default=3)
    threads = db.Column(db.Integer, default=10)
    ssl_verify = db.Column(db.Boolean, default=True)
    custom_payloads = db.Column(db.JSON)  # User's custom payloads
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

### 5. Report Model

```python
class Report(db.Model):
    """Security assessment report"""
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(255))
    report_type = db.Column(db.String(50))  # 'executive', 'technical', 'full'
    content = db.Column(db.Text)  # HTML/JSON content
    findings_summary = db.Column(db.JSON)  # Aggregated findings
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

---

## CRUD Operations

### CREATE (Insert)

```python
# Creating a new user
new_user = User(
    username='alice',
    email='alice@example.com',
    full_name='Alice Johnson'
)
new_user.set_password('Password123!')
db.session.add(new_user)
db.session.commit()
print(f"User created with ID: {new_user.id}")
```

**What happens in database:**
```sql
INSERT INTO user (username, email, full_name, password_hash, created_at)
VALUES ('alice', 'alice@example.com', 'Alice Johnson', 'pbkdf2:sha256:...', NOW());
-- Returns user.id = 1
```

### READ (Select)

```python
# Get single user by ID
user = User.query.get(1)

# Get user by username
user = User.query.filter_by(username='alice').first()

# Get all users
users = User.query.all()

# Filter with conditions
admin_users = User.query.filter(User.email.like('%@admin.com%')).all()

# Paginated query
page = User.query.paginate(page=1, per_page=20)
```

**SQL Generated:**
```sql
-- get(1)
SELECT * FROM user WHERE id = 1;

-- filter_by(username='alice')
SELECT * FROM user WHERE username = 'alice';

-- all()
SELECT * FROM user;

-- filter with LIKE
SELECT * FROM user WHERE email LIKE '%@admin.com%';

-- paginate
SELECT * FROM user LIMIT 20 OFFSET 0;
```

### UPDATE (Modify)

```python
# Update single field
user = User.query.get(1)
user.full_name = 'Alice Smith'
db.session.commit()

# Update multiple fields
scan = Scan.query.get(5)
scan.status = 'completed'
scan.findings_count = 15
scan.completed_at = datetime.utcnow()
db.session.commit()

# Bulk update
Scan.query.filter_by(status='pending').update({'status': 'failed'})
db.session.commit()
```

**SQL Generated:**
```sql
-- Update single user
UPDATE user SET full_name = 'Alice Smith' WHERE id = 1;

-- Update multiple fields
UPDATE scan SET status = 'completed', findings_count = 15, completed_at = NOW()
WHERE id = 5;

-- Bulk update
UPDATE scan SET status = 'failed' WHERE status = 'pending';
```

### DELETE (Remove)

```python
# Delete by instance
user = User.query.get(1)
db.session.delete(user)
db.session.commit()

# Bulk delete
Scan.query.filter_by(status='failed').delete()
db.session.commit()

# Delete with cascade
scan = Scan.query.get(1)
db.session.delete(scan)  # Automatically deletes all findings too!
db.session.commit()
```

**SQL Generated:**
```sql
-- Delete single user
DELETE FROM user WHERE id = 1;
-- Also cascades: DELETE FROM config WHERE user_id = 1;

-- Bulk delete
DELETE FROM scan WHERE status = 'failed';
-- Cascades delete all findings for those scans

-- Delete scan (with cascade)
DELETE FROM scan WHERE id = 1;
DELETE FROM finding WHERE scan_id = 1;  -- Automatic!
```

---

## Relationships

### One-to-Many (User → Scans)

```python
# Database structure
# user table:     id=1, username='alice'
# scan table:     id=1, user_id=1, target='example.com'
#                 id=2, user_id=1, target='test.com'
#                 id=3, user_id=2, target='other.com'

# Access relationship (backward)
user = User.query.get(1)
scans = user.scans  # [Scan(id=1), Scan(id=2)]

# Access relationship (forward)
scan = Scan.query.get(1)
owner = scan.user  # User(id=1)

# Filter related
scans = Scan.query.filter_by(user_id=1).all()

# Count related
count = user.scans.__len__()
```

### One-to-One (User ↔ Config)

```python
# When user registers
user = User(username='bob', email='bob@example.com')
user.set_password('pass')
db.session.add(user)
db.session.flush()  # Get user.id without committing

# Create config automatically
config = Config(user_id=user.id)
db.session.add(config)
db.session.commit()

# Access relationship
user = User.query.get(1)
user_config = user.config  # Config(id=1, timeout=10)

# Update config
user.config.timeout = 30
db.session.commit()
```

### Cascade Behavior

```python
# When user is deleted, all their records cascade delete
user = User.query.get(1)
db.session.delete(user)
db.session.commit()

# This triggers:
# 1. DELETE FROM scan WHERE user_id = 1
# 2. DELETE FROM finding WHERE scan_id IN (1, 2, 3)  (all user's scans)
# 3. DELETE FROM config WHERE user_id = 1
# 4. DELETE FROM report WHERE user_id = 1
```

**Cascade Rules:**
```python
# In models.py
class User:
    scans = db.relationship('Scan', cascade='all, delete-orphan')
    # 'all' = all cascade operations
    # 'delete-orphan' = delete related when parent is removed
```

---

## Transaction Management

### Transactions

A transaction is a sequence of operations treated as a single unit.

```python
try:
    # Start transaction (implicit)
    scan = Scan(user_id=1, target='example.com')
    db.session.add(scan)
    db.session.flush()  # Get scan.id without committing
    
    finding = Finding(scan_id=scan.id, finding_type='XSS')
    db.session.add(finding)
    
    scan.findings_count = 1
    
    db.session.commit()  # All changes saved atomically
    print("Transaction successful")
    
except Exception as e:
    db.session.rollback()  # Undo ALL changes
    print(f"Transaction failed: {e}")
```

**How it works:**

```
START TRANSACTION

INSERT INTO scan (user_id, target) VALUES (1, 'example.com')
  → scan.id = 1 (from database)

INSERT INTO finding (scan_id, finding_type) VALUES (1, 'XSS')

UPDATE scan SET findings_count = 1 WHERE id = 1

COMMIT  ← All three operations succeed together
         OR all three operations fail together
```

### Session Management

```python
# Session = connection to database
session = db.session

# Add objects
session.add(user)

# Mark changes
session.add_all([scan1, scan2, scan3])

# Commit changes
session.commit()

# Rollback changes
session.rollback()

# Clear session
session.expunge_all()

# Check if object is in session
if user in session:
    print("User is tracked")
```

---

## Query Examples

### Complex Queries

```python
# Get all scans for current user with findings
scans = Scan.query.filter_by(user_id=current_user.id).all()

# Get findings by severity
critical = Finding.query.filter_by(severity='Critical').all()

# Join query: User with their scan count
from sqlalchemy import func
users_with_count = db.session.query(
    User,
    func.count(Scan.id).label('scan_count')
).outerjoin(Scan).group_by(User.id).all()

# Date range query
from datetime import datetime, timedelta
recent_scans = Scan.query.filter(
    Scan.created_at >= datetime.utcnow() - timedelta(days=7)
).all()

# Case-insensitive search
findings = Finding.query.filter(
    Finding.finding_type.ilike('%sql%')
).all()
```

### Aggregation

```python
# Count
total_scans = Scan.query.count()
user_scans = Scan.query.filter_by(user_id=1).count()

# Sum
total_findings = db.session.query(
    func.sum(Scan.findings_count)
).scalar()

# Group by
severity_summary = db.session.query(
    Finding.severity,
    func.count(Finding.id)
).group_by(Finding.severity).all()

# Order by
recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
```

---

## Performance Tips

### 1. Use Eager Loading

```python
# ❌ Inefficient: N+1 problem
scans = Scan.query.all()
for scan in scans:
    print(scan.user.username)  # Query executed for EACH scan!

# ✅ Efficient: Load with relationship
from sqlalchemy.orm import joinedload
scans = Scan.query.options(joinedload(Scan.user)).all()
for scan in scans:
    print(scan.user.username)  # No additional queries!
```

### 2. Paginate Large Datasets

```python
# ❌ Inefficient: Load all records
all_scans = Scan.query.all()

# ✅ Efficient: Paginate
page = Scan.query.paginate(page=1, per_page=20)
scans = page.items
has_next = page.has_next
```

### 3. Use Indexing

```python
# In models.py
class Scan(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    status = db.Column(db.String(50), index=True)
    created_at = db.Column(db.DateTime, index=True)
```

### 4. Batch Operations

```python
# ❌ Inefficient: Multiple commits
for finding in findings:
    db.session.add(finding)
    db.session.commit()  # Each commit is slow

# ✅ Efficient: Single commit
db.session.add_all(findings)
db.session.commit()  # One commit for all
```

---

## Troubleshooting

### Common Issues

**Issue: "Column not found" error**
```python
# ❌ Wrong
Finding.query.filter_by(meta='value')

# ✅ Correct
Finding.query.filter(Finding.meta['key'].astext == 'value')
```

**Issue: Cascade delete not working**
```python
# Make sure cascade is defined
class Scan(db.Model):
    findings = db.relationship('Finding', cascade='all, delete-orphan')
```

**Issue: Session expired**
```python
# Refresh object from database
db.session.refresh(user)

# Or merge back into session
user = db.session.merge(user)
```

**Issue: JSON column not working**
```python
# ✅ Use JSON type
meta = db.Column(db.JSON)

# Store dict/list
finding.meta = {'type': 'sql', 'confidence': 95}
db.session.commit()

# Query JSON
Finding.query.filter(Finding.meta['type'].astext == 'sql')
```

---

## Summary

| Operation | Code | SQL |
|-----------|------|-----|
| **Create** | `db.session.add(obj)` | `INSERT` |
| **Read** | `Model.query.get(1)` | `SELECT` |
| **Update** | `obj.field = value` | `UPDATE` |
| **Delete** | `db.session.delete(obj)` | `DELETE` |
| **Commit** | `db.session.commit()` | `COMMIT` |
| **Rollback** | `db.session.rollback()` | `ROLLBACK` |

**Key Takeaways:**
- ✅ Always wrap operations in `try/except` for error handling
- ✅ Use relationships instead of manual foreign key management
- ✅ Commit frequently but batch when possible
- ✅ Use pagination for large datasets
- ✅ Define cascade rules for data integrity
- ✅ Use indexes for frequently queried columns

---

**Last Updated:** January 2025  
**Version:** 2.0.0  
**Database:** SQLAlchemy + SQLite
