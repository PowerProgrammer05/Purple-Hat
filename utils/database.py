import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Float, Boolean, Text, ForeignKey, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime
import enum

load_dotenv()

db_host = os.getenv('DATABASE_HOST', 'localhost')
db_user = os.getenv('DATABASE_USER', 'purplehat')
db_pass = os.getenv('DATABASE_PASSWORD', 'purplehat_pass123')
db_name = os.getenv('DATABASE_NAME', 'purplehat_db')
db_port = os.getenv('DATABASE_PORT', '3306')

DATABASE_URL = f"mysql+mysqlconnector://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanStatusEnum(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class VulnerabilityTypeEnum(str, enum.Enum):
    sql_injection = "sql_injection"
    xss = "xss"
    csrf = "csrf"
    file_upload = "file_upload"
    xxe = "xxe"
    command_injection = "command_injection"
    ldap_injection = "ldap_injection"
    xpath_injection = "xpath_injection"
    weak_auth = "weak_auth"
    weak_headers = "weak_headers"
    open_port = "open_port"


class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True)
    url = Column(String(500), unique=True, index=True)
    hostname = Column(String(255))
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), default="http")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime, nullable=True)
    
    scans = relationship("Scan", back_populates="target")
    results = relationship("Result", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), index=True)
    scan_type = Column(String(100))
    status = Column(Enum(ScanStatusEnum), default=ScanStatusEnum.pending)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    raw_output = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    
    target = relationship("Target", back_populates="scans")
    results = relationship("Result", back_populates="scan")


class Result(Base):
    __tablename__ = "results"
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    vulnerability_type = Column(Enum(VulnerabilityTypeEnum), index=True)
    severity = Column(String(20))
    confidence = Column(Float, default=0.0)
    title = Column(String(255))
    description = Column(Text)
    payload = Column(Text, nullable=True)
    proof = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    found_at = Column(DateTime, default=datetime.utcnow)
    
    target = relationship("Target", back_populates="results")
    scan = relationship("Scan", back_populates="results")


class AutomationRule(Base):
    __tablename__ = "automation_rules"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    enabled = Column(Boolean, default=True)
    techniques = Column(Text)
    options = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
