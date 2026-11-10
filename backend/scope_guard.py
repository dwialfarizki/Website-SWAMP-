import ipaddress
import socket
import urllib.parse


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def check_ip_in_whitelist(ip_str: str, allowed_ips_csv: str) -> bool:
    if not allowed_ips_csv or "*" in allowed_ips_csv or "0.0.0.0/0" in allowed_ips_csv:
        return True
    try:
        target_ip = ipaddress.ip_address(ip_str)
        for item in allowed_ips_csv.split(","):
            item = item.strip()
            if not item:
                continue
            if "/" in item:
                if target_ip in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if target_ip == ipaddress.ip_address(item):
                    return True
    except ValueError:
        return False
    return False


def validate_target_scope(target_url: str, allowed_domains_csv: str, allowed_ips_csv: str) -> dict:
    """
    Memvalidasi apakah URL target berada di dalam cakupan (Scope Protection)
    agar platform dapat digunakan secara dinamis oleh berbagai mitra.
    """
    raw = (target_url or "").strip()
    if not raw:
        return {
            "valid": False,
            "hostname": "",
            "resolved_ip": "-",
            "reason": "URL target tidak boleh kosong.",
        }

    normalized = raw if "://" in raw else f"https://{raw}"
    parsed = urllib.parse.urlparse(normalized)
    hostname = (parsed.hostname or "").lower().strip()

    if not hostname:
        return {
            "valid": False,
            "hostname": raw,
            "resolved_ip": "-",
            "reason": "Format URL atau hostname tidak valid.",
        }

    allowed_domains = [
        d.strip().lower() for d in (allowed_domains_csv or "").split(",") if d.strip()
    ]

    # 1. Resolusi DNS ke IPv4 (atau IPv6 jika IPv4 tidak ada)
    resolved_ip = "Unresolved"
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        try:
            info = socket.getaddrinfo(hostname, None)
            if info:
                resolved_ip = info[0][4][0]
        except Exception:
            resolved_ip = "DNS Lookup Failed"

    # 2. Jika input berupa alamat IP langsung (misal: http://127.0.0.1 atau http://103.21.244.10)
    if is_ip_address(hostname):
        if hostname in allowed_domains or check_ip_in_whitelist(hostname, allowed_ips_csv):
            return {
                "valid": True,
                "hostname": hostname,
                "resolved_ip": hostname,
                "reason": f"Scope Protection Tervalidasi: Endpoint IP '{hostname}' sesuai dengan whitelist proyek.",
            }
        return {
            "valid": False,
            "hostname": hostname,
            "resolved_ip": hostname,
            "reason": f"Akses Ditolak: IP '{hostname}' berada di luar cakupan jaringan yang diizinkan.",
        }

    # 3. Jika input berupa Nama Domain (misal: ms.stas-rg.com atau domain mitra baru)
    domain_matched = False
    for allowed in allowed_domains:
        if allowed.startswith("*."):
            base_dom = allowed[2:]
            if hostname == base_dom or hostname.endswith("." + base_dom):
                domain_matched = True
                break
        elif hostname == allowed:
            domain_matched = True
            break

    if not domain_matched:
        return {
            "valid": False,
            "hostname": hostname,
            "resolved_ip": resolved_ip,
            "reason": f"Scope Protection Aktif: Domain '{hostname}' tidak terdaftar dalam Whitelist Cakupan Proyek.",
        }

    if resolved_ip == "DNS Lookup Failed":
        return {
            "valid": False,
            "hostname": hostname,
            "resolved_ip": "-",
            "reason": f"Domain '{hostname}' terdaftar di whitelist, namun gagal melakukan resolusi DNS (Host tidak ditemukan).",
        }

    return {
        "valid": True,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "reason": f"Scope Protection Tervalidasi: Domain '{hostname}' ({resolved_ip}) sesuai dengan whitelist cakupan.",
    }