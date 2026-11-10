from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), default="auditor")  # "admin" atau "auditor"

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    # Whitelist disimpan dipisahkan koma, misal: "www.stas-rg.com,ms.stas-rg.com,127.0.0.1"
    allowed_domains = Column(Text, nullable=False)
    allowed_ips = Column(Text, nullable=False)     # misal: "103.21.244.0/24,127.0.0.1"
    created_at = Column(DateTime, default=datetime.utcnow)
    scans = relationship("Scan", back_populates="project")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    target_url = Column(String(255), nullable=False)
    resolved_ip = Column(String(50))
    modules_executed = Column(String(255))         # "headers,cookies,sqli,nmap"
    score = Column(Integer, default=100)           # 0 - 100
    grade = Column(String(2), default="A")         # A, B, C, D, E, F
    baseline_scan_id = Column(Integer, nullable=True) # Untuk komparasi Retesting
    auditor_name = Column(String(100), default="Dwi Alfa Rizki")
    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    module = Column(String(50), nullable=False)    # HTTP Security Headers, Cookie, SQLi, Nmap
    title = Column(String(200), nullable=False)
    severity = Column(String(20), nullable=False)  # High, Medium, Low, Info
    status = Column(String(30), default="Suspected") # Suspected, Confirmed, False Positive, Fixed
    technical_evidence = Column(Text)              # Bukti teks respons header/payload/port
    auditor_notes = Column(Text, default="")       # Catatan analisis manual & rekomendasi mitigasi

    scan = relationship("Scan", back_populates="findings")

class KnowledgeBase(Base):
    __tablename__ = "knowledge_base"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    severity = Column(String(20), nullable=False)
    wstg_code = Column(String(50))                 # Contoh: WSTG-CONF-07
    mitigation_template = Column(Text, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    username = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False)
    action_type = Column(String(50), nullable=False) # Scan Completed, Scope Validation, Scope Modified
    target = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)      # SUCCESS, BLOCKED, AUDIT
    detail = Column(Text, nullable=False)