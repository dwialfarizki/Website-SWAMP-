import subprocess
import time
import urllib.parse
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socket
import urllib3.util.connection as urllib3_cn


urllib3_cn.allowed_gai_family = lambda: socket.AF_INET

# Nonaktifkan peringatan SSL untuk target lab lokal / self-signed certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
}


def fetch_headers_via_curl(target_url: str) -> tuple:
    """Fallback menggunakan curl -4 -s -D (GET request) untuk menghindari blokir bot Cloudflare."""
    # Menggunakan metode GET (-L -s) dan dump header ke file sementara atau parsing stdout
    cmd = [
        "curl", "-4", "-s", "-L", "-k",
        "--max-time", "25",
        "-A", BROWSER_HEADERS["User-Agent"],
        "-H", "Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
        "-o", "/dev/null",
        "-D", "-",  # Cetak header ke stdout
        target_url
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise requests.exceptions.ConnectionError("Koneksi gagal baik via Python maupun curl -4.")

    headers_dict = {}
    status_line = "200 OK"
    for line in proc.stdout.splitlines():
        line_strip = line.strip()
        if line_strip.upper().startswith("HTTP/"):
            parts = line_strip.split(" ", 2)
            status_line = parts[1] + (" " + parts[2] if len(parts) > 2 else "")
            headers_dict.clear()
        elif ":" in line_strip:
            k, v = line_strip.split(":", 1)
            headers_dict[k.strip()] = v.strip()
    return status_line, headers_dict

def get_http_session() -> requests.Session:
    """
    Membuat sesi HTTP dengan mekanisme auto-retry untuk menghindari
    kesalahan baca sementara (false timeout / connection reset).
    """
    session = requests.Session()
    retry_strategy = Retry(
        total=2,
        backoff_factor=1,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def scan_http_headers(target_url: str) -> list:
    """Modul 1: Analisis Keberadaan & Konfigurasi HTTP Security Headers."""
    findings = []
    session = get_http_session()
    headers_lower = {}
    raw_headers = ""
    status_text = "200 OK"

    try:
        try:
            resp = session.get(
                target_url,
                timeout=12,
                headers=BROWSER_HEADERS,
                verify=False,
                allow_redirects=True,
            )
            status_text = f"{resp.status_code} {resp.reason}"
            raw_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            # Jika Python requests timeout/gagal TLS, otomatis gunakan curl -4
            status_text, curl_headers = fetch_headers_via_curl(target_url)
            raw_headers = "\n".join([f"{k}: {v}" for k, v in curl_headers.items()])
            headers_lower = {k.lower(): v for k, v in curl_headers.items()}

        required_headers = [
            (
                "Content-Security-Policy",
                "Missing Content-Security-Policy (CSP)",
                "High",
                "Tambahkan direktif Content-Security-Policy pada konfigurasi web server (Nginx/Apache) untuk membatasi sumber eksekusi skrip dan mencegah serangan XSS (OWASP WSTG-CONF-07).",
            ),
            (
                "Strict-Transport-Security",
                "Missing Strict-Transport-Security (HSTS)",
                "Medium",
                "Aktifkan header Strict-Transport-Security: max-age=31536000; includeSubDomains agar komunikasi selalu terenkripsi melalui HTTPS.",
            ),
            (
                "X-Frame-Options",
                "Missing X-Frame-Options Header",
                "Medium",
                "Tambahkan header X-Frame-Options: SAMEORIGIN atau DENY guna mencegah penyalahgunaan halaman melalui teknik Clickjacking.",
            ),
            (
                "X-Content-Type-Options",
                "Missing X-Content-Type-Options",
                "Low",
                "Tetapkan header X-Content-Type-Options: nosniff untuk mencegah browser melakukan MIME-sniffing terhadap respons server.",
            ),
        ]

        for header_key, title, severity, mitigation in required_headers:
            if header_key.lower() not in headers_lower:
                evidence = (
                    f"# HTTP Diagnostic Trace for {target_url}\n"
                    f"HTTP/1.1 {status_text}\n"
                    f"{raw_headers}\n\n"
                    f"[!] {header_key}: <MISSING> (Header tidak ditemukan pada respons server)"
                )
                findings.append({
                    "module": "HTTP Security Headers",
                    "title": title,
                    "severity": severity,
                    "status": "Suspected",
                    "technical_evidence": evidence,
                    "auditor_notes": mitigation,
                })
    except Exception as e:
        findings.append({
            "module": "HTTP Security Headers",
            "title": "Target HTTP Unreachable / Timeout",
            "severity": "Info",
            "status": "Suspected",
            "technical_evidence": f"Gagal menghubungi {target_url}: {str(e)}",
            "auditor_notes": "Pastikan layanan web target sedang aktif dan dapat diakses dari lingkungan penguji.",
        })
    return findings


def scan_cookie_attributes(target_url: str) -> list:
    """Modul 2: Pemeriksaan Atribut Keamanan Cookie (Secure, HttpOnly, SameSite)."""
    findings = []
    session = get_http_session()
    try:
        resp = session.get(
            target_url,
            timeout=15,
            headers=BROWSER_HEADERS,
            verify=False,
            allow_redirects=True,
        )
        raw_set_cookie = resp.headers.get("Set-Cookie", "")

        if not resp.cookies and not raw_set_cookie:
            return findings

        cookie_analyze_text = raw_set_cookie.lower()
        missing_flags = []

        if target_url.startswith("https://") and "secure" not in cookie_analyze_text:
            missing_flags.append("Secure")
        if "httponly" not in cookie_analyze_text:
            missing_flags.append("HttpOnly")
        if "samesite" not in cookie_analyze_text:
            missing_flags.append("SameSite")

        if missing_flags:
            flags_str = ", ".join(missing_flags)
            findings.append({
                "module": "Cookie Attributes",
                "title": f"Session Cookie Missing Security Flags ({flags_str})",
                "severity": "Low" if len(missing_flags) == 1 else "Medium",
                "status": "Suspected",
                "technical_evidence": (
                    f"# Set-Cookie Header Trace on {target_url}\n"
                    f"Set-Cookie: {raw_set_cookie or '[Detected via CookieJar]'}\n"
                    f"[!] Missing Attributes: {flags_str}"
                ),
                "auditor_notes": (
                    f"Konfigurasikan atribut {flags_str} pada pembuatan session cookie "
                    f"di sisi aplikasi untuk melindungi sesi dari pencurian via XSS atau pengiriman lintas situs (OWASP WSTG-SESS-02)."
                ),
            })
    except Exception:
        pass
    return findings


def scan_sqli_heuristic(target_url: str) -> list:
    """
    Modul 3: Deteksi Indikasi SQL Injection secara Heuristik Terkendali.
    Tidak melakukan eksploitasi destruktif atau perubahan data pada database target.
    """
    findings = []
    parsed = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    # Jika URL tidak memiliki parameter query (misal ?id=1), uji dengan parameter simulasi ringan
    if not query_params:
        test_url_base = target_url.rstrip("/") + "/?id=1"
        parsed = urllib.parse.urlparse(test_url_base)
        query_params = urllib.parse.parse_qs(parsed.query)

    sql_error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "psql: error",
        "syntax error at or near",
        "sqlite3.operationalerror",
        "ora-01756",
    ]

    for param in query_params.keys():
        # 1. Uji Error-Based Heuristic (karakter kutip tunggal terkendali)
        mutated_params = query_params.copy()
        mutated_params[param] = [f"{query_params[param][0]}'"]
        new_query = urllib.parse.urlencode(mutated_params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        try:
            start_t = time.time()
            resp = requests.get(target_url, timeout=12, headers=BROWSER_HEADERS, verify=False, allow_redirects=True)
            elapsed = time.time() - start_t
            body_lower = resp.text.lower()

            for sig in sql_error_signatures:
                if sig in body_lower:
                    findings.append({
                        "module": "SQL Injection Heuristic",
                        "title": f"Error-Based SQL Injection Indication in Param '{param}'",
                        "severity": "High",
                        "status": "Suspected",
                        "technical_evidence": (
                            f"# Controlled Heuristic SQLi Probe\n"
                            f"Test URL : {test_url}\n"
                            f"Payload  : ' (Single Quote Syntax Probe)\n"
                            f"HTTP Code: {resp.status_code} ({elapsed:.2f}s)\n"
                            f"[!] Matched Database Error Signature: '{sig}'"
                        ),
                        "auditor_notes": (
                            "Gunakan Prepared Statements (Parameterized Queries) atau ORM binding "
                            "pada pemrosesan parameter input serta matikan pesan error database mentah di produksi (OWASP WSTG-INPV-05)."
                        ),
                    })
                    break
        except Exception:
            pass
    return findings


def scan_nmap_ports(hostname: str) -> list:
    """Modul 4: Pemindaian Port Layanan Jaringan & Versi menggunakan Nmap."""
    findings = []
    try:
        # Menjalankan Nmap cepat pada port layanan populer + deteksi versi ringan
        cmd = ["nmap", "-F", "-sV", "--version-light", "--open", hostname]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout

        open_ports = []
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())

        # Tandai port non-standar atau port manajemen yang terekspos selain 80/443
        risky_ports = [p for p in open_ports if not (p.startswith("80/") or p.startswith("443/"))]

        if risky_ports:
            ports_summary = ", ".join([p.split()[0] for p in risky_ports])
            findings.append({
                "module": "Nmap Port & Service",
                "title": f"Exposed Non-Standard Network Port ({ports_summary})",
                "severity": "Medium",
                "status": "Suspected",
                "technical_evidence": (
                    f"# Nmap Service & Port Scan Output ({hostname})\n"
                    f"Command: {' '.join(cmd)}\n\n"
                    + "\n".join(open_ports)
                ),
                "auditor_notes": (
                    "Tutup akses publik terhadap port layanan non-standar/manajemen menggunakan "
                    "firewall (UFW/iptables) atau batasi akses hanya melalui jaringan internal/VPN."
                ),
            })
    except FileNotFoundError:
        findings.append({
            "module": "Nmap Port & Service",
            "title": "Nmap Binary Not Found on Host System",
            "severity": "Info",
            "status": "Suspected",
            "technical_evidence": "Perintah 'nmap' tidak ditemukan pada PATH sistem operasi Linux/WSL.",
            "auditor_notes": "Pastikan paket nmap telah terpasang di lingkungan Kali Linux / Ubuntu WSL (sudo apt install nmap).",
        })
    except Exception as e:
        findings.append({
            "module": "Nmap Port & Service",
            "title": "Nmap Execution Interrupted",
            "severity": "Info",
            "status": "Suspected",
            "technical_evidence": str(e),
            "auditor_notes": "Periksa konektivitas jaringan ke host target.",
        })
    return findings


def calculate_security_score(findings_list: list) -> dict:
    """
    Menghitung Skor Keamanan (0-100) dan Grade (A-F) secara transparan.
    Jika target Unreachable/Timeout, mengembalikan Grade 'N/A' dan Score 0.
    Temuan berstatus 'False Positive' atau 'Fixed' tidak mengurangi skor.
    """
    # 1. Cek terlebih dahulu apakah target gagal dijangkau (Unreachable / Timeout)
    for f in findings_list:
        status = f.get("status", "Suspected") if isinstance(f, dict) else f.status
        title = f.get("title", "") if isinstance(f, dict) else f.title
        if status not in ["False Positive", "Fixed"] and (
            "Unreachable" in title or "Timeout" in title
        ):
            return {
                "score": 0,
                "grade": "N/A",
                "deductions": [
                    "Target tidak dapat dijangkau (Unreachable / Connection Timeout) — Skor tidak dapat dihitung"
                ],
            }

    # 2. Jika target berhasil dijangkau, hitung pengurangan poin normal
    deduction_weights = {"High": 15, "Medium": 8, "Low": 4, "Info": 0}
    score = 100
    deductions_detail = []

    for f in findings_list:
        status = f.get("status", "Suspected") if isinstance(f, dict) else f.status
        if status in ["False Positive", "Fixed"]:
            continue

        sev = f.get("severity", "Low") if isinstance(f, dict) else f.severity
        title = f.get("title", "") if isinstance(f, dict) else f.title
        penalty = deduction_weights.get(sev, 0)
        if penalty > 0:
            score -= penalty
            deductions_detail.append(f"-{penalty} {title}")

    score = max(0, score)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    elif score >= 50:
        grade = "E"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "deductions": deductions_detail}