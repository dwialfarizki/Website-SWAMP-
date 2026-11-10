from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import List, Optional

import models
from database import engine, get_db, SessionLocal
from scope_guard import validate_target_scope
from scanners import (
    scan_http_headers,
    scan_cookie_attributes,
    scan_sqli_heuristic,
    scan_nmap_ports,
    calculate_security_score,
)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SWAMP API - Scoped Web Assessment & Management Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Skema Request Pydantic ---
class ScanRequest(BaseModel):
    project_id: int
    target_url: str
    modules: List[str]  # ["headers", "cookies", "sqli", "nmap"]
    username: str = "Dwi Alfa Rizki"
    role: str = "AUDITOR"
    baseline_scan_id: Optional[int] = None


class FindingUpdateRequest(BaseModel):
    status: str  # Suspected, Confirmed, False Positive, Fixed
    technical_evidence: str
    auditor_notes: str
    username: str = "Dwi Alfa Rizki"
    role: str = "AUDITOR"


class ScopeUpdateRequest(BaseModel):
    allowed_domains: str
    allowed_ips: str
    username: str = "Admin Lab"
    role: str = "ADMIN"


class SingleDomainScopeRequest(BaseModel):
    domain: str
    username: str = "Admin Lab"
    role: str = "ADMIN"


class KBCreateRequest(BaseModel):
    title: str
    severity: str
    wstg_code: str
    mitigation_template: str
    role: str = "ADMIN"


# --- Seeder Data Awal (Otomatis Mengisi Proyek CoE STAS-RG & KB Saat Pertama Jalan) ---
@app.on_event("startup")
def seed_initial_data():
    db = SessionLocal()
    if db.query(models.Project).count() == 0:
        default_proj = models.Project(
            name="Audit CoE STAS-RG",
            allowed_domains="www.stas-rg.com,ms.stas-rg.com,stas-rg.com,localhost,127.0.0.1",
            allowed_ips="103.21.244.0/24,127.0.0.1",
        )
        db.add(default_proj)

        kb_samples = [
            models.KnowledgeBase(
                title="Content-Security-Policy (CSP) Baseline",
                severity="High",
                wstg_code="WSTG-CONF-07",
                mitigation_template="Tambahkan header Content-Security-Policy dengan direktif default-src 'self' untuk memitigasi injeksi skrip berbahaya (XSS).",
            ),
            models.KnowledgeBase(
                title="Strict-Transport-Security (HSTS) Enforcement",
                severity="Medium",
                wstg_code="WSTG-CONF-07",
                mitigation_template="Konfigurasikan Strict-Transport-Security: max-age=31536000; includeSubDomains pada server HTTPS.",
            ),
            models.KnowledgeBase(
                title="Cookie SameSite & HttpOnly Flags",
                severity="Low",
                wstg_code="WSTG-SESS-02",
                mitigation_template="Sertakan atribut Secure, HttpOnly, dan SameSite Lax/Strict pada setiap pembuatan Set-Cookie.",
            ),
            models.KnowledgeBase(
                title="SQL Injection Parameter Remediation",
                severity="High",
                wstg_code="WSTG-INPV-05",
                mitigation_template="Gunakan Prepared Statements (Parameterized Queries) dan validasi tipe input di sisi server.",
            ),
        ]
        db.add_all(kb_samples)
        db.commit()
    db.close()


# --- 1. Endpoint Proyek & Validasi Scope Real-Time ---
@app.get("/api/projects")
def get_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).all()


@app.get("/api/scope/check")
def check_scope(project_id: int, target_url: str, db: Session = Depends(get_db)):
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyek tidak ditemukan.")
    return validate_target_scope(target_url, project.allowed_domains, project.allowed_ips)


@app.put("/api/projects/{project_id}/scope")
def update_project_scope(
    project_id: int, req: ScopeUpdateRequest, db: Session = Depends(get_db)
):
    if req.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="RBAC Ditolak: Hanya Administrator yang dapat mengubah Whitelist Scope.",
        )

    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyek tidak ditemukan.")

    project.allowed_domains = req.allowed_domains
    project.allowed_ips = req.allowed_ips

    db.add(
        models.AuditLog(
            username=req.username,
            role="ADMIN",
            action_type="Scope Modified",
            target=project.name,
            status="AUDIT",
            detail=f"Memperbarui whitelist domain: {req.allowed_domains}",
        )
    )
    db.commit()
    db.refresh(project)
    return project


@app.post("/api/projects/{project_id}/scope/domain")
def add_single_scope_domain(
    project_id: int, req: SingleDomainScopeRequest, db: Session = Depends(get_db)
):
    """Menambahkan 1 domain baru ke allowed_domains pada Project."""
    if req.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="RBAC Ditolak: Hanya Administrator yang dapat menambah Whitelist Scope.",
        )

    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyek tidak ditemukan.")

    # Bersihkan input jika user menempelkan URL penuh seperti https://igracias.telkomuniversity.ac.id/
    clean_dom = req.domain.strip().lower()
    clean_dom = (
        clean_dom.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
    )

    if not clean_dom:
        raise HTTPException(status_code=400, detail="Nama domain tidak boleh kosong.")

    current_domains = [
        d.strip() for d in (project.allowed_domains or "").split(",") if d.strip()
    ]
    if clean_dom in current_domains:
        raise HTTPException(
            status_code=400,
            detail=f"Domain '{clean_dom}' sudah ada di dalam whitelist.",
        )

    current_domains.append(clean_dom)
    project.allowed_domains = ",".join(current_domains)

    db.add(
        models.AuditLog(
            username=req.username,
            role="ADMIN",
            action_type="Scope Domain Added",
            target=project.name,
            status="AUDIT",
            detail=f"Menambahkan domain '{clean_dom}' ke whitelist. Total: {project.allowed_domains}",
        )
    )
    db.commit()
    db.refresh(project)
    return project


@app.delete("/api/projects/{project_id}/scope/domain/{domain_name}")
def delete_single_scope_domain(
    project_id: int,
    domain_name: str,
    username: str = "Admin Lab",
    role: str = "ADMIN",
    db: Session = Depends(get_db),
):
    """Menghapus 1 domain dari allowed_domains pada Project."""
    if role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="RBAC Ditolak: Hanya Administrator yang dapat menghapus Whitelist Scope.",
        )

    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Proyek tidak ditemukan.")

    clean_dom = domain_name.strip().lower()
    current_domains = [
        d.strip() for d in (project.allowed_domains or "").split(",") if d.strip()
    ]

    if clean_dom not in current_domains:
        raise HTTPException(
            status_code=404,
            detail=f"Domain '{clean_dom}' tidak ditemukan di dalam whitelist.",
        )

    if len(current_domains) <= 1:
        raise HTTPException(
            status_code=400,
            detail="Minimal harus tersisa 1 domain di dalam cakupan proyek.",
        )

    current_domains.remove(clean_dom)
    project.allowed_domains = ",".join(current_domains)

    db.add(
        models.AuditLog(
            username=username,
            role="ADMIN",
            action_type="Scope Domain Removed",
            target=project.name,
            status="AUDIT",
            detail=f"Menghapus domain '{clean_dom}' dari whitelist. Sisa: {project.allowed_domains}",
        )
    )
    db.commit()
    db.refresh(project)
    return project


# --- 2. Endpoint Eksekusi Pemindaian Terpadu (4 Modul + Scope Protection) ---
@app.post("/api/scans/run")
def run_integrated_scan(req: ScanRequest, db: Session = Depends(get_db)):
    project = (
        db.query(models.Project).filter(models.Project.id == req.project_id).first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Proyek tidak ditemukan.")

    # Validasi Scope Protection sebelum scanner berjalan
    scope_res = validate_target_scope(
        req.target_url, project.allowed_domains, project.allowed_ips
    )
    if not scope_res["valid"]:
        db.add(
            models.AuditLog(
                username=req.username,
                role=req.role.upper(),
                action_type="Scope Validation",
                target=scope_res["hostname"],
                status="BLOCKED",
                detail=scope_res["reason"],
            )
        )
        db.commit()
        raise HTTPException(status_code=403, detail=scope_res["reason"])

    # Normalisasi URL
    full_url = (
        req.target_url if "://" in req.target_url else f"https://{req.target_url}"
    )

    collected_findings = []
    if "headers" in req.modules:
        collected_findings.extend(scan_http_headers(full_url))
    if "cookies" in req.modules:
        collected_findings.extend(scan_cookie_attributes(full_url))
    if "sqli" in req.modules:
        collected_findings.extend(scan_sqli_heuristic(full_url))
    if "nmap" in req.modules:
        collected_findings.extend(scan_nmap_ports(scope_res["hostname"]))

    score_info = calculate_security_score(collected_findings)

    new_scan = models.Scan(
        project_id=project.id,
        target_url=full_url,
        resolved_ip=scope_res["resolved_ip"],
        modules_executed=",".join(req.modules),
        score=score_info["score"],
        grade=score_info["grade"],
        baseline_scan_id=req.baseline_scan_id,
        auditor_name=req.username,
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    for item in collected_findings:
        db.add(models.Finding(scan_id=new_scan.id, **item))

    db.add(
        models.AuditLog(
            username=req.username,
            role=req.role.upper(),
            action_type="Scan Completed",
            target=scope_res["hostname"],
            status="SUCCESS",
            detail=f"{len(req.modules)} modul dieksekusi, menghasilkan Grade {score_info['grade']} ({score_info['score']}/100).",
        )
    )
    db.commit()
    return get_scan_detail(new_scan.id, db)


# --- 3. Endpoint Detail Scan & Ruang Kerja Verifikasi (Authoring Workspace) ---
@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    return db.query(models.Scan).order_by(models.Scan.id.desc()).all()


@app.get("/api/scans/{scan_id}")
def get_scan_detail(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=404, detail="Data pemindaian tidak ditemukan."
        )
    score_info = calculate_security_score(scan.findings)
    return {
        "scan": scan,
        "findings": scan.findings,
        "deductions": score_info["deductions"],
    }


@app.put("/api/findings/{finding_id}")
def update_finding_verification(
    finding_id: int, req: FindingUpdateRequest, db: Session = Depends(get_db)
):
    finding = (
        db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Temuan tidak ditemukan.")

    finding.status = req.status
    finding.technical_evidence = req.technical_evidence
    finding.auditor_notes = req.auditor_notes
    db.commit()

    # Hitung ulang skor & Grade A-F jika ada temuan yang diubah ke False Positive / Fixed
    scan = db.query(models.Scan).filter(models.Scan.id == finding.scan_id).first()
    recalc = calculate_security_score(scan.findings)
    scan.score = recalc["score"]
    scan.grade = recalc["grade"]

    db.add(
        models.AuditLog(
            username=req.username,
            role=req.role.upper(),
            action_type="Finding Verified",
            target=f"Finding #{finding.id}",
            status="AUDIT",
            detail=f"Status temuan '{finding.title}' diubah menjadi '{req.status}'. Skor diperbarui ke Grade {scan.grade}.",
        )
    )
    db.commit()
    return get_scan_detail(scan.id, db)


# --- 4. Endpoint Komparasi Pengujian Ulang (Retesting Comparison) ---
@app.get("/api/scans/compare/{baseline_id}/{retest_id}")
def compare_retesting_scans(
    baseline_id: int, retest_id: int, db: Session = Depends(get_db)
):
    base_scan = db.query(models.Scan).filter(models.Scan.id == baseline_id).first()
    retest_scan = db.query(models.Scan).filter(models.Scan.id == retest_id).first()

    if not base_scan or not retest_scan:
        raise HTTPException(
            status_code=404, detail="Data scan pembanding tidak ditemukan."
        )

    base_map = {
        f.title: f for f in base_scan.findings if f.status != "False Positive"
    }
    retest_map = {
        f.title: f for f in retest_scan.findings if f.status != "False Positive"
    }

    comparison_rows = []
    for title, bf in base_map.items():
        if title not in retest_map or retest_map[title].status == "Fixed":
            comparison_rows.append(
                {
                    "module": bf.module,
                    "title": title,
                    "baseline_status": f"Unmitigated ({bf.severity})",
                    "retest_status": "Verified Clean / Remediated",
                    "delta": "FIXED",
                }
            )
        else:
            comparison_rows.append(
                {
                    "module": bf.module,
                    "title": title,
                    "baseline_status": f"Unmitigated ({bf.severity})",
                    "retest_status": f"Unmitigated ({retest_map[title].severity})",
                    "delta": "STILL OPEN",
                }
            )

    for title, rf in retest_map.items():
        if title not in base_map and rf.status != "Fixed":
            comparison_rows.append(
                {
                    "module": rf.module,
                    "title": title,
                    "baseline_status": "Not Detected",
                    "retest_status": f"Detected ({rf.severity})",
                    "delta": "NEW FINDING",
                }
            )

    return {
        "baseline": base_scan,
        "retest": retest_scan,
        "score_diff": retest_scan.score - base_scan.score,
        "comparison": comparison_rows,
    }


# --- 5. Endpoint Knowledge Base (CRUD) & Audit Log ---
@app.get("/api/kb")
def list_kb(db: Session = Depends(get_db)):
    return db.query(models.KnowledgeBase).all()


@app.post("/api/kb")
def create_kb(req: KBCreateRequest, db: Session = Depends(get_db)):
    if req.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Hanya Administrator yang dapat menambah Knowledge Base.",
        )

    item = models.KnowledgeBase(
        title=req.title,
        severity=req.severity,
        wstg_code=req.wstg_code,
        mitigation_template=req.mitigation_template,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@app.delete("/api/kb/{kb_id}")
def delete_kb(kb_id: int, role: str = "ADMIN", db: Session = Depends(get_db)):
    if role.upper() != "ADMIN":
        raise HTTPException(
            status_code=403,
            detail="Hanya Administrator yang dapat menghapus Knowledge Base.",
        )

    item = (
        db.query(models.KnowledgeBase)
        .filter(models.KnowledgeBase.id == kb_id)
        .first()
    )
    if item:
        db.delete(item)
        db.commit()
    return {"deleted": True}


@app.get("/api/audit-logs")
def list_audit_logs(db: Session = Depends(get_db)):
    return db.query(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(50).all()