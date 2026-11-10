import React, { useState, useEffect } from "react";

const API_BASE = "http://localhost:8000/api";

const DEFAULT_STITCH_DATA = {
  scan: {
    id: 1,
    target_url: "https://ms.stas-rg.com",
    resolved_ip: "103.21.244.12",
    score: 82,
    grade: "B",
    auditor_name: "Dwi Alfa Rizki",
    created_at: "05 Nov 2026 14:32 WIB",
  },
  deductions: [
    "-10 Hilang CSP (Content-Security-Policy)",
    "-8 Port Terbuka (TCP 8080 Management Proxy)",
  ],
  findings: [
    {
      id: 1,
      module: "HTTP Security Headers",
      title: "Missing Content-Security-Policy (CSP)",
      subtitle: "CWE-1021 Kebijakan script-src yang ketat hilang dari baseline HTTP",
      severity: "High",
      status: "Suspected",
      technical_evidence:
        "# HTTP/1.1 Diagnostic Trace for https://ms.stas-rg.com\nHTTP/1.1 200 OK\nDate: Thu, 05 Nov 2026 14:32:04 GMT\nServer: nginx/1.24.0\nStrict-Transport-Security: max-age=31536000; includeSubDomains\nX-Frame-Options: SAMEORIGIN\nX-Content-Type-Options: nosniff\n[!] Content-Security-Policy: <MISSING> (XSS mitigation disabled)",
      auditor_notes:
        "Teramati skrip inline dinamis disuntikkan via parameter pengguna. Disarankan menerapkan Content-Security-Policy dengan direktif default-src 'self' untuk mencegah eksekusi skrip tidak tepercaya (XSS).",
    },
    {
      id: 2,
      module: "Nmap Port & Service",
      title: "Exposed Non-Standard HTTP Port 8080",
      subtitle:
        "Terdeteksi Apache Tomcat / JMX Console terbuka ke antarmuka publik eksternal",
      severity: "Medium",
      status: "Confirmed",
      technical_evidence:
        "# Nmap Service & Port Scan Output (ms.stas-rg.com)\nPORT STATE SERVICE VERSION\n80/tcp open http nginx 1.24.0\n443/tcp open ssl/http nginx 1.24.0\n8080/tcp open http-proxy Apache Tomcat/9.0.82",
      auditor_notes:
        "Tutup akses publik terhadap port manajemen 8080 menggunakan firewall atau batasi akses hanya melalui jaringan internal laboratorium.",
    },
    {
      id: 3,
      module: "Cookie Attributes",
      title: "Session Cookie Missing SameSite Strict",
      subtitle:
        "Token Set-Cookie tidak memiliki spesifikasi Lax/Strict; default ke None (Bahaya lintas situs)",
      severity: "Low",
      status: "Confirmed",
      technical_evidence:
        "Set-Cookie: session_id=8f4a21e99c; Path=/; Secure; HttpOnly\n[!] Missing Attribute: SameSite Strict/Lax",
      auditor_notes:
        "Konfigurasikan atribut SameSite Lax atau SameSite Strict pada pembuatan session cookie di sisi server.",
    },
  ],
};

export default function App() {
  const [activeTab, setActiveTab] = useState("scanner-report");
  const [role, setRole] = useState("Auditor");

  // Toast Notification State
  const [toast, setToast] = useState(null);
  const showToast = (type, title, message) => {
    setToast({ type, title, message });
  };

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  const [activeProject, setActiveProject] = useState({
    id: 1,
    name: "Audit CoE STAS-RG",
    allowed_domains: "www.stas-rg.com,ms.stas-rg.com,stas-rg.com,localhost,127.0.0.1",
    allowed_ips: "103.21.244.0/24,127.0.0.1",
  });

  const [targetUrl, setTargetUrl] = useState("https://ms.stas-rg.com");
  const [scopeCheck, setScopeCheck] = useState({
    valid: true,
    reason:
      "Scope Protection Tervalidasi: Domain 'ms.stas-rg.com' & DNS IP sesuai whitelist.",
  });

  const [selectedModules, setSelectedModules] = useState({
    headers: true,
    cookies: true,
    sqli: true,
    nmap: true,
  });

  const [loadingScan, setLoadingScan] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [currentScanData, setCurrentScanData] = useState(DEFAULT_STITCH_DATA);
  const [expandedRowId, setExpandedRowId] = useState(1);
  const [findingFilter, setFindingFilter] = useState("ALL");

  const [editForm, setEditForm] = useState({
    status: "Suspected",
    technical_evidence: DEFAULT_STITCH_DATA.findings[0].technical_evidence,
    auditor_notes: DEFAULT_STITCH_DATA.findings[0].auditor_notes,
  });

  const [baselineId, setBaselineId] = useState("");
  const [retestId, setRetestId] = useState("");
  const [comparisonData, setComparisonData] = useState(null);

  const [kbList, setKbList] = useState([
    {
      id: 1,
      title: "Content-Security-Policy (CSP) Baseline",
      severity: "High",
      wstg_code: "WSTG-CONF-07",
      mitigation_template:
        "Tambahkan header Content-Security-Policy dengan direktif default-src 'self' untuk memitigasi injeksi skrip berbahaya (XSS).",
    },
    {
      id: 2,
      title: "Strict-Transport-Security (HSTS) Enforcement",
      severity: "Medium",
      wstg_code: "WSTG-CONF-07",
      mitigation_template:
        "Konfigurasikan Strict-Transport-Security: max-age=31536000; includeSubDomains pada server HTTPS.",
    },
  ]);

  const [newKb, setNewKb] = useState({
    title: "",
    severity: "High",
    wstg_code: "WSTG-CONF-07",
    mitigation_template: "",
  });

  const [newDomainInput, setNewDomainInput] = useState("");

  const [auditLogs, setAuditLogs] = useState([
    {
      id: 1,
      timestamp: "2026-11-05 14:32:05",
      username: "Dwi Alfa Rizki",
      role: "AUDITOR",
      action_type: "Scan Completed",
      target: "ms.stas-rg.com",
      status: "SUCCESS",
      detail: "4 modul dieksekusi, menghasilkan Grade B (82/100).",
    },
  ]);

  useEffect(() => {
    syncWithBackend(true);
  }, []);

  const syncWithBackend = async (loadLatestScan = false) => {
    try {
      const [projRes, scansRes, kbRes, logsRes] = await Promise.all([
        fetch(`${API_BASE}/projects`),
        fetch(`${API_BASE}/scans`),
        fetch(`${API_BASE}/kb`),
        fetch(`${API_BASE}/audit-logs`),
      ]);

      if (projRes.ok) {
        const projs = await projRes.json();
        if (projs.length > 0) setActiveProject(projs[0]);
      }

      if (scansRes.ok) {
        const scans = await scansRes.json();
        setScanHistory(scans);
        if (loadLatestScan && scans.length > 0) {
          await handleSelectScanHistory(scans[0].id, false);
        }
        if (scans.length >= 2) {
          setBaselineId(scans[scans.length - 1].id);
          setRetestId(scans[0].id);
        }
      }

      if (kbRes.ok) {
        const kbs = await kbRes.json();
        if (kbs.length > 0) setKbList(kbs);
      }

      if (logsRes.ok) {
        const logs = await logsRes.json();
        if (logs.length > 0) setAuditLogs(logs);
      }
    } catch {
      // Gunakan data default jika backend belum menyala
    }
  };

  const handleSelectScanHistory = async (scanId, notify = true) => {
    try {
      const detailRes = await fetch(`${API_BASE}/scans/${scanId}`);
      if (detailRes.ok) {
        const detail = await detailRes.json();
        setCurrentScanData(detail);
        if (detail.findings?.length > 0) {
          setExpandedRowId(detail.findings[0].id);
          setEditForm({
            status: detail.findings[0].status,
            technical_evidence: detail.findings[0].technical_evidence || "",
            auditor_notes: detail.findings[0].auditor_notes || "",
          });
        } else {
          setExpandedRowId(null);
        }
        if (notify) {
          showToast(
            "info",
            "Riwayat Dimuat",
            `Menampilkan hasil Scan #${scanId} (${detail.scan.target_url}) - Grade ${detail.scan.grade}.`
          );
        }
      }
    } catch {
      showToast("error", "Gagal Memuat", "Tidak dapat memuat detail riwayat pemindaian.");
    }
  };

  useEffect(() => {
    if (!activeProject || !targetUrl.trim()) return;
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(
          `${API_BASE}/scope/check?project_id=${activeProject.id}&target_url=${encodeURIComponent(
            targetUrl
          )}`
        );
        if (res.ok) {
          setScopeCheck(await res.json());
          return;
        }
      } catch {
        // Fallback lokal
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [targetUrl, activeProject]);

  const handleExpandRow = (finding) => {
    if (expandedRowId === finding.id) {
      setExpandedRowId(null);
      return;
    }
    setExpandedRowId(finding.id);
    setEditForm({
      status: finding.status,
      technical_evidence: finding.technical_evidence || "",
      auditor_notes: finding.auditor_notes || "",
    });
  };

  const handleStartScan = async () => {
    const activeMods = Object.keys(selectedModules).filter((k) => selectedModules[k]);
    if (activeMods.length === 0) {
      showToast("error", "Modul Kosong", "Pilih minimal 1 modul pemindaian sebelum memulai!");
      return;
    }
    setLoadingScan(true);
    try {
      const res = await fetch(`${API_BASE}/scans/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: activeProject.id,
          target_url: targetUrl,
          modules: activeMods,
          username: "Dwi Alfa Rizki",
          role: role.toUpperCase(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast("error", "Diblokir oleh Scope Protection", data.detail);
        syncWithBackend(false);
      } else {
        setCurrentScanData(data);
        if (data.findings?.length > 0) {
          setExpandedRowId(data.findings[0].id);
          setEditForm({
            status: data.findings[0].status,
            technical_evidence: data.findings[0].technical_evidence || "",
            auditor_notes: data.findings[0].auditor_notes || "",
          });
        }
        syncWithBackend(false);
        showToast(
          "success",
          "Pemindaian Selesai",
          `Target ${data.scan.target_url} memperoleh Grade ${data.scan.grade} (Score: ${data.scan.score}/100).`
        );
      }
    } catch {
      showToast(
        "error",
        "Koneksi Gagal",
        "Gagal menghubungi server backend FastAPI di port 8000."
      );
    } finally {
      setLoadingScan(false);
    }
  };

  const handleStatusChangeInline = async (finding, newStatus) => {
    const updatedList = currentScanData.findings.map((f) =>
      f.id === finding.id ? { ...f, status: newStatus } : f
    );
    setCurrentScanData({ ...currentScanData, findings: updatedList });
    if (expandedRowId === finding.id) {
      setEditForm((prev) => ({ ...prev, status: newStatus }));
    }

    try {
      const res = await fetch(`${API_BASE}/findings/${finding.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: newStatus,
          technical_evidence: finding.technical_evidence || "",
          auditor_notes: finding.auditor_notes || "",
          username: "Dwi Alfa Rizki",
          role: role.toUpperCase(),
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setCurrentScanData(updated);
        syncWithBackend(false);
        showToast(
          "success",
          "Status Diperbarui",
          `Temuan diubah ke '${newStatus}'. Skor disesuaikan ke Grade ${updated.scan.grade} (${updated.scan.score}/100).`
        );
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleSaveVerification = async (findingId) => {
    try {
      const res = await fetch(`${API_BASE}/findings/${findingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...editForm,
          username: "Dwi Alfa Rizki",
          role: role.toUpperCase(),
        }),
      });
      if (res.ok) {
        const updated = await res.json();
        setCurrentScanData(updated);
        syncWithBackend(false);
        showToast(
          "success",
          "Verifikasi Tersimpan",
          `Bukti teknis & catatan auditor disimpan. Skor terkini: Grade ${updated.scan.grade} (${updated.scan.score}/100).`
        );
      }
    } catch {
      showToast(
        "success",
        "Tersimpan Lokal",
        "Perubahan verifikasi telah diperbarui pada antarmuka."
      );
    }
  };

  const handleExportHTML = () => {
    const { scan, findings, deductions } = currentScanData;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Laporan Audit SWAMP - ${scan.target_url}</title>
<style>body{font-family:Inter,sans-serif;padding:32px;color:#0f172a}table{width:100%;border-collapse:collapse;margin-top:16px}th,td{border:1px solid #e2e8f0;padding:12px;text-align:left}pre{background:#0f172a;color:#34d399;padding:12px;border-radius:6px;overflow-x:auto}</style></head>
<body><h1>SWAMP - Laporan Asesmen Keamanan Web</h1>
<p><strong>URL Target:</strong> ${scan.target_url} (${scan.resolved_ip}) | <strong>Score:</strong> ${scan.score}/100 (Grade ${scan.grade}) | <strong>Auditor:</strong> ${scan.auditor_name}</p>
<h3>Rincian Pengurangan Skor:</h3><ul>${deductions
        .map((d) => `<li>${d}</li>`)
        .join("")}</ul>
<h3>Daftar Temuan Asesmen:</h3>
<table><thead><tr><th>Modul</th><th>Kerentanan</th><th>Severity</th><th>Status</th><th>Bukti Teknis & Catatan</th></tr></thead>
<tbody>${findings
        .map(
          (f) =>
            `<tr><td>${f.module}</td><td><strong>${f.title}</strong></td><td>${f.severity}</td><td>${f.status}</td><td><pre>${f.technical_evidence}</pre><p>${f.auditor_notes}</p></td></tr>`
        )
        .join("")}</tbody></table></body></html>`;

    const blob = new Blob([html], { type: "text/html" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `SWAMP-Report-${scan.id}.html`;
    a.click();
    showToast(
      "info",
      "Laporan HTML Diunduh",
      `File SWAMP-Report-${scan.id}.html berhasil disimpan.`
    );
  };

  const handleCompareScans = async () => {
    if (!baselineId || !retestId) return;
    try {
      const res = await fetch(`${API_BASE}/scans/compare/${baselineId}/${retestId}`);
      if (res.ok) {
        setComparisonData(await res.json());
        showToast(
          "info",
          "Komparasi Selesai",
          `Membandingkan Scan #${baselineId} dengan Scan #${retestId}.`
        );
      }
    } catch (e) {
      console.error(e);
    }
  };

  // --- FUNGSI TAMBAH DOMAIN WHITELIST (DENGAN PEMBERSIH URL OTOMATIS) ---
  const handleAddWhitelistDomain = async () => {
    if (role !== "Admin") {
      showToast(
        "error",
        "Akses RBAC Ditolak",
        "Beralihlah ke peran Admin di pojok kanan atas untuk mengubah Whitelist Scope."
      );
      return;
    }
    if (!newDomainInput.trim()) return;

    // Bersihkan jika user menempelkan https://igracias.telkomuniversity.ac.id/
    const cleanDom = newDomainInput
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .split("/")[0]
      .split(":")[0];

    if (!cleanDom) return;

    const currentList = activeProject.allowed_domains
      .split(",")
      .map((d) => d.trim())
      .filter(Boolean);

    if (currentList.includes(cleanDom)) {
      showToast(
        "info",
        "Sudah Terdaftar",
        `Domain '${cleanDom}' sudah ada di dalam daftar whitelist.`
      );
      setNewDomainInput("");
      return;
    }

    const updatedDomains = [...currentList, cleanDom].join(",");
    setActiveProject({ ...activeProject, allowed_domains: updatedDomains });
    setNewDomainInput("");

    try {
      await fetch(`${API_BASE}/projects/${activeProject.id}/scope`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          allowed_domains: updatedDomains,
          allowed_ips: activeProject.allowed_ips,
          username: "Dwi Alfa Rizki",
          role: "ADMIN",
        }),
      });
      syncWithBackend(false);
      showToast(
        "success",
        "Scope Diperbarui",
        `Domain '${cleanDom}' berhasil ditambahkan ke whitelist.`
      );
    } catch {
      showToast("success", "Scope Diperbarui", "Whitelist berhasil diperbarui.");
    }
  };

  // --- FUNGSI HAPUS DOMAIN WHITELIST ---
  const handleRemoveWhitelistDomain = async (domainToRemove) => {
    if (role !== "Admin") {
      showToast(
        "error",
        "Akses RBAC Ditolak",
        "Hanya peran Admin yang dapat menghapus domain dari Whitelist Scope."
      );
      return;
    }

    const currentList = activeProject.allowed_domains
      .split(",")
      .map((d) => d.trim())
      .filter(Boolean);

    if (currentList.length <= 1) {
      showToast(
        "error",
        "Aksi Ditolak",
        "Minimal harus tersisa 1 domain aktif di dalam cakupan proyek."
      );
      return;
    }

    const updatedList = currentList.filter((d) => d !== domainToRemove.trim());
    const updatedDomains = updatedList.join(",");
    setActiveProject({ ...activeProject, allowed_domains: updatedDomains });

    try {
      await fetch(`${API_BASE}/projects/${activeProject.id}/scope`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          allowed_domains: updatedDomains,
          allowed_ips: activeProject.allowed_ips,
          username: "Dwi Alfa Rizki",
          role: "ADMIN",
        }),
      });
      syncWithBackend(false);
      showToast(
        "info",
        "Domain Dihapus",
        `Domain '${domainToRemove.trim()}' telah dihapus dari whitelist.`
      );
    } catch {
      showToast(
        "info",
        "Domain Dihapus",
        `Domain '${domainToRemove.trim()}' dihapus dari whitelist lokal.`
      );
    }
  };

  const handleCreateKb = async (e) => {
    e.preventDefault();
    if (role !== "Admin") {
      showToast(
        "error",
        "Akses RBAC Ditolak",
        "Hanya peran Admin yang dapat menambah template Knowledge Base."
      );
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/kb`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...newKb, role: "ADMIN" }),
      });
      if (res.ok) syncWithBackend(false);
    } catch {
      setKbList([...kbList, { id: Date.now(), ...newKb }]);
    }
    setNewKb({
      title: "",
      severity: "High",
      wstg_code: "WSTG-CONF-07",
      mitigation_template: "",
    });
    showToast(
      "success",
      "Template KB Ditambahkan",
      "Standar mitigasi baru berhasil disimpan ke Knowledge Base."
    );
  };

  const handleDeleteKb = async (kbId) => {
    if (role !== "Admin") {
      showToast(
        "error",
        "Akses RBAC Ditolak",
        "Hanya peran Admin yang dapat menghapus template Knowledge Base."
      );
      return;
    }
    try {
      await fetch(`${API_BASE}/kb/${kbId}?role=ADMIN`, { method: "DELETE" });
      syncWithBackend(false);
    } catch {
      // Fallback
    }
    setKbList(kbList.filter((k) => k.id !== kbId));
    showToast("info", "Template Dihapus", "Item Knowledge Base telah dihapus.");
  };

  const findings = currentScanData?.findings || [];
  const filteredFindings = findings.filter((f) => {
    if (findingFilter === "ALL") return true;
    return f.status === findingFilter;
  });

  const countStatus = (st) => findings.filter((f) => f.status === st).length;

  return (
    <div className="w-full min-h-screen flex flex-col bg-[#F8FAFC] font-body-md text-text-primary antialiased text-left">
      {/* HARD RESET CSS BAWAAN VITE AGAR 100% FULL-WIDTH TANPA GARIS TENGAH */}
      <style>{`
        html, body, #root {
          width: 100% !important;
          max-width: 100% !important;
          margin: 0 !important;
          padding: 0 !important;
          border: none !important;
          text-align: left !important;
          background-color: #F8FAFC !important;
          display: block !important;
        }
        @media print {
          body, #root {
            background-color: #ffffff !important;
          }
        }
      `}</style>

      {/* TOAST NOTIFICATION MODERN */}
      {toast && (
        <div className="fixed top-20 right-8 z-50 max-w-md animate-bounce print:hidden">
          <div
            className={`flex items-start gap-3 px-4 py-3.5 rounded-xl shadow-lg border ${toast.type === "error"
                ? "bg-rose-950 text-white border-rose-800"
                : toast.type === "info"
                  ? "bg-slate-900 text-white border-slate-700"
                  : "bg-emerald-950 text-white border-emerald-800"
              }`}
          >
            <span
              className={`material-symbols-outlined text-[20px] mt-0.5 ${toast.type === "error"
                  ? "text-rose-400"
                  : toast.type === "info"
                    ? "text-blue-400"
                    : "text-emerald-400"
                }`}
            >
              {toast.type === "error"
                ? "gpp_bad"
                : toast.type === "info"
                  ? "info"
                  : "task_alt"}
            </span>
            <div className="flex-1 text-left">
              <div className="text-xs font-bold tracking-wide uppercase">
                {toast.title}
              </div>
              <div className="text-xs opacity-90 mt-0.5 leading-relaxed">
                {toast.message}
              </div>
            </div>
            <button
              onClick={() => setToast(null)}
              className="text-xs opacity-70 hover:opacity-100 cursor-pointer"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* HEADER RAPI & SEJAJAR KONTEN */}
      <header className="sticky top-0 left-0 right-0 z-40 w-full bg-white border-b border-slate-200 print:hidden">
        <div className="max-w-[1440px] mx-auto px-6 lg:px-10 h-16 flex items-center justify-between gap-4">
          {/* KIRI: Logo & Subjudul Ringkas */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-emerald-400 shadow-xs">
              <span className="material-symbols-outlined text-[20px]">
                shield_lock
              </span>
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-slate-900 leading-none">
                  SWAMP
                </span>
                <span className="font-mono text-[10px] bg-slate-100 text-slate-600 border border-slate-200 px-1.5 py-0.5 rounded leading-none">
                  v2.4
                </span>
              </div>
              <span className="text-[11px] text-slate-400 font-medium mt-0.5">
                Scoped Web Assessment Platform
              </span>
            </div>
          </div>

          {/* TENGAH: Menu Navigasi */}
          <nav className="hidden md:flex items-center gap-7 h-16">
            {[
              { id: "scanner-report", label: "Scanner & Report" },
              { id: "retesting-compare", label: "Retesting Compare" },
              { id: "knowledge-base", label: "Knowledge Base (CRUD)" },
              { id: "audit-logs", label: "Audit Logs" },
            ].map((nav) => (
              <button
                key={nav.id}
                type="button"
                onClick={() => setActiveTab(nav.id)}
                className={`h-full flex items-center px-1 transition-colors border-b-2 text-xs font-medium cursor-pointer whitespace-nowrap ${activeTab === nav.id
                    ? "border-slate-900 text-slate-900 font-bold"
                    : "border-transparent text-slate-500 hover:text-slate-900"
                  }`}
              >
                {nav.label}
              </button>
            ))}
          </nav>

          {/* KANAN: Role Switcher & Profil */}
          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => {
                const nextRole = role === "Auditor" ? "Admin" : "Auditor";
                setRole(nextRole);
                showToast(
                  "info",
                  `Mode Peran: ${nextRole}`,
                  nextRole === "Admin"
                    ? "Hak akses penuh diaktifkan (Dapat menambah/menghapus Whitelist Scope & Knowledge Base)."
                    : "Mode Auditor aktif (Fokus pada pemindaian & verifikasi temuan)."
                );
              }}
              className="inline-flex items-center gap-2 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-lg text-xs text-slate-600 hover:text-slate-900 hover:border-slate-300 transition-all cursor-pointer whitespace-nowrap"
              type="button"
            >
              <span className="font-semibold uppercase text-slate-400">PERAN:</span>
              <span className="font-bold text-slate-900">{role}</span>
              <span className="text-slate-300">|</span>
              <span className="text-blue-600 font-semibold hover:underline">
                Beralih ke {role === "Auditor" ? "Admin" : "Auditor"}
              </span>
            </button>
            <div className="w-8 h-8 rounded-full bg-slate-900 flex items-center justify-center shrink-0">
              <span className="material-symbols-outlined text-white text-[16px]">
                person
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT FULL-WIDTH PROPORSIONAL */}
      <main className="w-full flex-1 px-8 xl:px-14 py-6 flex flex-col gap-6">
        {activeTab === "scanner-report" && (
          <>
            {/* 1. TARGET SCAN & SCOPE PROTECTION BOX */}
            <section className="w-full bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col gap-4 print:hidden">
              <div className="flex flex-wrap items-center gap-2">
                <div className="flex items-center gap-1.5 bg-slate-50 px-2.5 py-1 rounded border border-slate-200 whitespace-nowrap">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                  <span className="text-[11px] font-semibold uppercase text-slate-400">
                    CAKUPAN AKTIF:
                  </span>
                  <span className="text-xs font-bold text-slate-900">
                    {activeProject.name}
                  </span>
                </div>
                <span className="text-[11px] font-semibold text-slate-500 uppercase ml-1">
                  ASET DIIZINKAN:
                </span>
                {activeProject.allowed_domains
                  .split(",")
                  .map((d) => d.trim())
                  .filter(Boolean)
                  .map((dom) => (
                    <button
                      key={dom}
                      type="button"
                      onClick={() => setTargetUrl(`https://${dom}`)}
                      className="font-mono text-xs bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-800 px-2.5 py-0.5 rounded cursor-pointer transition"
                      title="Klik untuk mengisi URL Target"
                    >
                      {dom}
                    </button>
                  ))}
              </div>

              <div className="flex flex-col sm:flex-row items-stretch gap-3">
                <div className="relative flex-1 flex items-center">
                  <div className="absolute left-3.5 flex items-center gap-1 text-slate-400 pointer-events-none">
                    <span className="material-symbols-outlined text-[20px]">
                      language
                    </span>
                    <span className="material-symbols-outlined text-[16px] text-emerald-500">
                      lock
                    </span>
                  </div>
                  <input
                    aria-label="URL Target"
                    className="w-full pl-16 pr-4 py-3 bg-white border border-slate-200 rounded-lg font-mono text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600"
                    placeholder="https://domain.com atau endpoint IP"
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                  />
                </div>
                <button
                  onClick={handleStartScan}
                  disabled={loadingScan}
                  className="inline-flex items-center justify-center gap-2 bg-slate-900 text-white px-6 py-3 rounded-lg text-sm font-semibold hover:bg-slate-800 transition-colors shadow-xs cursor-pointer whitespace-nowrap disabled:opacity-50"
                  type="button"
                >
                  <span className="material-symbols-outlined text-[20px]">
                    radar
                  </span>
                  <span>
                    {loadingScan ? "Memindai Target..." : "Mulai Pemindaian"}
                  </span>
                </button>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3">
                {scopeCheck?.valid ? (
                  <div className="inline-flex items-center gap-2 bg-emerald-50 border border-emerald-200 text-emerald-700 px-3.5 py-1.5 rounded-full text-xs font-medium">
                    <span className="material-symbols-outlined text-[16px]">
                      check_circle
                    </span>
                    <span>{scopeCheck.reason}</span>
                  </div>
                ) : (
                  <div className="inline-flex items-center gap-2 bg-rose-50 border border-rose-200 text-rose-700 px-3.5 py-1.5 rounded-full text-xs font-medium">
                    <span className="material-symbols-outlined text-[16px]">
                      cancel
                    </span>
                    <span>{scopeCheck?.reason}</span>
                  </div>
                )}

                <div className="inline-flex items-center gap-1.5 bg-rose-50 border border-rose-200 text-rose-700 px-3.5 py-1.5 rounded-full text-xs font-medium">
                  <span className="material-symbols-outlined text-[16px]">
                    shield_with_heart
                  </span>
                  <span>
                    Target di luar cakupan otomatis diblokir &amp; dicatat ke log
                  </span>
                </div>
              </div>

              <div className="pt-3 border-t border-slate-200 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                  { key: "headers", title: "HTTP Headers", desc: "HSTS, CSP, X-Frame" },
                  {
                    key: "cookies",
                    title: "Cookie Flags",
                    desc: "Secure, HttpOnly, SameSite",
                  },
                  {
                    key: "sqli",
                    title: "Controlled SQLi",
                    desc: "Heuristik pasif & buta",
                  },
                  {
                    key: "nmap",
                    title: "Nmap Network",
                    desc: "Pemindaian port & audit layanan",
                  },
                ].map((mod) => (
                  <label
                    key={mod.key}
                    className="flex items-start gap-2.5 p-3 rounded-lg border border-slate-200 bg-slate-50/70 hover:bg-white transition-colors cursor-pointer"
                  >
                    <input
                      checked={selectedModules[mod.key]}
                      onChange={(e) =>
                        setSelectedModules({
                          ...selectedModules,
                          [mod.key]: e.target.checked,
                        })
                      }
                      className="mt-0.5 rounded border-slate-300 accent-slate-900 w-4 h-4"
                      type="checkbox"
                    />
                    <div className="flex flex-col text-left">
                      <span className="text-sm font-semibold text-slate-900 leading-tight">
                        {mod.title}
                      </span>
                      <span className="text-xs text-slate-500 mt-0.5">
                        {mod.desc}
                      </span>
                    </div>
                  </label>
                ))}
              </div>
            </section>

            {/* 2. KARTU RINGKASAN SKOR & GRADE A-F */}
            <section className="w-full bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6">
                <div
                  className={`w-28 h-28 shrink-0 rounded-xl border-2 flex flex-col items-center justify-center ${currentScanData.scan.grade === "N/A"
                      ? "bg-slate-100 border-slate-300 text-slate-500"
                      : currentScanData.scan.grade === "A"
                        ? "bg-emerald-50 border-emerald-400 text-emerald-600"
                        : currentScanData.scan.grade === "B"
                          ? "bg-amber-50 border-amber-400 text-amber-600"
                          : "bg-rose-50 border-rose-400 text-rose-600"
                    }`}
                >
                  <span className="text-4xl font-bold leading-none">
                    {currentScanData.scan.grade}
                  </span>
                  <span className="text-[11px] uppercase font-bold tracking-wider mt-1.5">
                    Grade
                  </span>
                </div>
                <div className="flex flex-col gap-1.5 text-left">
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-bold text-slate-900">
                      Score: {currentScanData.scan.score}
                    </span>
                    <span className="text-sm text-slate-400">/100</span>
                  </div>
                  <p className="text-sm text-slate-600 max-w-2xl">
                    Postur keamanan dievaluasi secara transparan berdasarkan tingkat
                    keparahan temuan aktif. Temuan berstatus False Positive atau Fixed
                    tidak mengurangi skor.
                  </p>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    {currentScanData.deductions?.length > 0 ? (
                      currentScanData.deductions.map((ded, idx) => (
                        <span
                          key={idx}
                          className={`font-mono text-xs px-2.5 py-1 rounded font-medium border ${idx === 0
                              ? "bg-rose-50 border-rose-200 text-rose-700"
                              : "bg-amber-50 border-amber-200 text-amber-800"
                            }`}
                        >
                          {ded}
                        </span>
                      ))
                    ) : (
                      <span className="font-mono text-xs px-2.5 py-1 bg-emerald-50 border border-emerald-200 text-emerald-700 rounded font-medium">
                        ✓ Tidak ada pengurangan poin (Konfigurasi Aman)
                      </span>
                    )}
                  </div>
                </div>
              </div>

              <div className="flex flex-col lg:items-end gap-4 border-t lg:border-t-0 pt-4 lg:pt-0 border-slate-200 shrink-0">
                <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-left lg:text-right text-xs">
                  <div>
                    <span className="text-slate-400 block">URL Target:</span>
                    <span className="font-mono font-semibold text-slate-900 whitespace-nowrap">
                      {currentScanData.scan.target_url}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">IP Terurai:</span>
                    <span className="font-mono font-semibold text-slate-900 whitespace-nowrap">
                      {currentScanData.scan.resolved_ip}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">
                      Stempel Waktu Pemindaian:
                    </span>
                    <span className="text-slate-800 font-medium whitespace-nowrap">
                      {currentScanData.scan.created_at?.includes("WIB")
                        ? currentScanData.scan.created_at
                        : new Date(
                          currentScanData.scan.created_at
                        ).toLocaleString("id-ID")}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Auditor Utama:</span>
                    <span className="text-slate-900 font-semibold whitespace-nowrap">
                      {currentScanData.scan.auditor_name} (SecOps)
                    </span>
                  </div>
                </div>

                {/* DROPDOWN RIWAYAT SCAN & TOMBOL EKSPOR */}
                <div className="flex flex-wrap items-center gap-2.5 print:hidden">
                  {scanHistory.length > 0 && (
                    <select
                      aria-label="Pilih Riwayat Scan"
                      value={currentScanData.scan.id}
                      onChange={(e) =>
                        handleSelectScanHistory(Number(e.target.value), true)
                      }
                      className="px-3 py-2 bg-slate-50 border border-slate-300 text-slate-800 rounded-lg text-xs font-medium focus:outline-none cursor-pointer"
                    >
                      {scanHistory.map((s) => (
                        <option key={s.id} value={s.id}>
                          Riwayat Scan #{s.id} {s.target_url} (Grade {s.grade})
                        </option>
                      ))}
                    </select>
                  )}

                  <button
                    onClick={() => window.print()}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-300 text-slate-800 rounded-lg text-xs font-semibold hover:bg-slate-50 transition-all cursor-pointer whitespace-nowrap"
                    type="button"
                  >
                    <span className="material-symbols-outlined text-[16px] text-rose-600">
                      picture_as_pdf
                    </span>
                    <span>Ekspor Laporan PDF</span>
                  </button>
                  <button
                    onClick={handleExportHTML}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-white border border-slate-300 text-slate-800 rounded-lg text-xs font-semibold hover:bg-slate-50 transition-all cursor-pointer whitespace-nowrap"
                    type="button"
                  >
                    <span className="material-symbols-outlined text-[16px] text-blue-600">
                      html
                    </span>
                    <span>Ekspor Laporan HTML</span>
                  </button>
                </div>
              </div>
            </section>

            {/* 3. TABEL TEMUAN ASESMEN & AUTHORING WORKSPACE */}
            <section className="w-full bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs flex flex-col">
              <div className="p-6 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="text-left">
                  <h2 className="text-lg font-bold text-slate-900">
                    Temuan Asesmen (Assessment Findings)
                  </h2>
                  <p className="text-xs text-slate-500">
                    4 modul keamanan dijalankan • {findings.length} diagnostik
                    dikatalogkan
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2 print:hidden">
                  {[
                    { id: "ALL", label: `Semua (${findings.length})` },
                    {
                      id: "Suspected",
                      label: `Perlu Ditinjau (${countStatus("Suspected")})`,
                    },
                    {
                      id: "Confirmed",
                      label: `Confirmed (${countStatus("Confirmed")})`,
                    },
                    { id: "Fixed", label: `Fixed (${countStatus("Fixed")})` },
                  ].map((pill) => (
                    <button
                      key={pill.id}
                      onClick={() => setFindingFilter(pill.id)}
                      className={`px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer transition-colors ${findingFilter === pill.id
                          ? "bg-slate-900 text-white"
                          : "bg-slate-50 text-slate-600 hover:text-slate-900 border border-slate-200"
                        }`}
                      type="button"
                    >
                      {pill.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto w-full">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold uppercase text-slate-500">
                      <th className="py-3.5 px-6">MODUL</th>
                      <th className="py-3.5 px-6">KERENTANAN / ITEM ASESMEN</th>
                      <th className="py-3.5 px-4">TINGKAT KEPARAHAN</th>
                      <th className="py-3.5 px-6">STATUS VERIFIKASI</th>
                      <th className="py-3.5 px-6 text-right print:hidden">
                        TINDAKAN
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {filteredFindings.map((item) => {
                      const isExpanded = expandedRowId === item.id;
                      return (
                        <React.Fragment key={item.id}>
                          <tr className="hover:bg-slate-50/80 transition-colors bg-white">
                            <td className="py-4 px-6 font-mono text-xs text-slate-600 whitespace-nowrap">
                              {item.module}
                            </td>
                            <td className="py-4 px-6 text-left">
                              <div className="text-sm font-bold text-slate-900">
                                {item.title}
                              </div>
                              <div className="font-mono text-xs text-slate-400 mt-0.5">
                                {item.subtitle || item.auditor_notes}
                              </div>
                            </td>
                            <td className="py-4 px-4 whitespace-nowrap">
                              <span
                                className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-bold border uppercase ${item.severity.toUpperCase() === "HIGH"
                                    ? "bg-rose-50 text-rose-700 border-rose-200"
                                    : item.severity.toUpperCase() === "MEDIUM"
                                      ? "bg-amber-50 text-amber-800 border-amber-200"
                                      : "bg-blue-50 text-blue-700 border-blue-200"
                                  }`}
                              >
                                {item.severity}
                              </span>
                            </td>
                            <td className="py-4 px-6 whitespace-nowrap">
                              <select
                                value={item.status}
                                onChange={(e) =>
                                  handleStatusChangeInline(item, e.target.value)
                                }
                                className="bg-white border border-slate-300 text-xs font-medium rounded px-2.5 py-1.5 text-slate-800"
                              >
                                <option value="Suspected">Suspected</option>
                                <option value="Confirmed">Confirmed</option>
                                <option value="False Positive">
                                  False Positive
                                </option>
                                <option value="Fixed">Fixed</option>
                              </select>
                            </td>
                            <td className="py-4 px-6 text-right whitespace-nowrap print:hidden">
                              <button
                                onClick={() => handleExpandRow(item)}
                                className="text-xs font-semibold text-blue-600 hover:underline inline-flex items-center gap-1 cursor-pointer"
                                type="button"
                              >
                                <span>{isExpanded ? "Tutup" : "Buka"}</span>
                                <span className="material-symbols-outlined text-[16px]">
                                  {isExpanded ? "expand_less" : "expand_more"}
                                </span>
                              </button>
                            </td>
                          </tr>

                          {/* PANEL INTERAKTIF DI LAYAR */}
                          {isExpanded && (
                            <tr className="print:hidden">
                              <td className="p-0" colSpan={5}>
                                <div className="bg-slate-50 border-t border-b border-slate-200 p-6 flex flex-col gap-4 text-left">
                                  <div className="flex items-center justify-between pb-2 border-b border-slate-200">
                                    <div className="flex items-center gap-2">
                                      <span className="material-symbols-outlined text-blue-600 text-[20px]">
                                        edit_note
                                      </span>
                                      <span className="text-sm font-bold text-slate-900">
                                        Ruang Kerja Verifikasi Auditor
                                      </span>
                                      <span className="font-mono text-xs px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-600">
                                        #SEC-2026-0{item.id}
                                      </span>
                                    </div>
                                    <span className="text-xs text-slate-400">
                                      STANDAR DIREKTIF: OWASP WSTG v4.2 OUTPUT
                                    </span>
                                  </div>

                                  <div className="flex flex-col gap-1.5">
                                    <label className="text-[11px] uppercase text-slate-500 font-bold">
                                      BUKTI TEKNIS (HTTP RESPONSE HEADER / PAYLOAD
                                      SQLI / PORT NMAP)
                                    </label>
                                    <textarea
                                      rows={7}
                                      value={editForm.technical_evidence}
                                      onChange={(e) =>
                                        setEditForm({
                                          ...editForm,
                                          technical_evidence: e.target.value,
                                        })
                                      }
                                      className="w-full bg-slate-900 border border-slate-800 rounded-lg p-4 font-mono text-xs text-emerald-400 leading-relaxed focus:outline-none"
                                    />
                                  </div>

                                  <div className="flex flex-col gap-1.5">
                                    <label className="text-[11px] uppercase text-slate-500 font-bold">
                                      CATATAN ANALISIS MANUAL AUDITOR &amp; MITIGASI
                                    </label>
                                    <textarea
                                      className="w-full p-3 bg-white border border-slate-300 rounded-md text-xs text-slate-800 focus:outline-none"
                                      rows={3}
                                      value={editForm.auditor_notes}
                                      onChange={(e) =>
                                        setEditForm({
                                          ...editForm,
                                          auditor_notes: e.target.value,
                                        })
                                      }
                                    />
                                  </div>

                                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 pt-2 border-t border-slate-200">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="text-[11px] font-bold uppercase text-slate-400 mr-1">
                                        Vonis:
                                      </span>
                                      {[
                                        {
                                          label: "Konfirmasi Temuan",
                                          val: "Confirmed",
                                        },
                                        {
                                          label: "Tandai False Positive",
                                          val: "False Positive",
                                        },
                                        {
                                          label: "Tandai Fixed / Retest",
                                          val: "Fixed",
                                        },
                                      ].map((v) => (
                                        <label
                                          key={v.val}
                                          onClick={() =>
                                            setEditForm({
                                              ...editForm,
                                              status: v.val,
                                            })
                                          }
                                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-300 bg-white text-xs font-medium text-slate-800 cursor-pointer hover:bg-slate-50"
                                        >
                                          <input
                                            checked={editForm.status === v.val}
                                            onChange={() =>
                                              setEditForm({
                                                ...editForm,
                                                status: v.val,
                                              })
                                            }
                                            className="accent-slate-900"
                                            name={`verdict-${item.id}`}
                                            type="radio"
                                          />
                                          <span>{v.label}</span>
                                        </label>
                                      ))}
                                    </div>
                                    <div className="flex items-center gap-2 justify-end">
                                      <button
                                        onClick={() => setExpandedRowId(null)}
                                        className="px-4 py-2 border border-slate-300 bg-white text-slate-600 hover:text-slate-900 rounded text-xs font-semibold cursor-pointer"
                                        type="button"
                                      >
                                        Buang Perubahan
                                      </button>
                                      <button
                                        onClick={() =>
                                          handleSaveVerification(item.id)
                                        }
                                        className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded text-xs font-semibold cursor-pointer"
                                        type="button"
                                      >
                                        Simpan Verifikasi
                                      </button>
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}

                          {/* BARIS KHUSUS CETAK PDF (OTOMATIS TAMPIL SAAT PRINT) */}
                          <tr className="hidden print:table-row bg-slate-50">
                            <td
                              colSpan={5}
                              className="px-6 py-3 border-t border-slate-200"
                            >
                              <div className="text-[11px] font-bold uppercase text-slate-600 mb-1">
                                Bukti Teknis (#SEC-2026-0{item.id}):
                              </div>
                              <pre className="p-3 bg-slate-900 text-emerald-400 font-mono text-[10px] rounded whitespace-pre-wrap">
                                {item.technical_evidence}
                              </pre>
                              <div className="text-xs text-slate-700 mt-2">
                                <strong>Catatan &amp; Mitigasi Auditor:</strong>{" "}
                                {item.auditor_notes}
                              </div>
                            </td>
                          </tr>
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="p-4 bg-slate-50 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between text-slate-500 text-xs gap-2">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[16px] text-emerald-600">
                    check
                  </span>
                  <span>
                    Evaluasi otomatis selesai menggunakan Direktif RFC 9110 dan OWASP
                    WSTG
                  </span>
                </div>
                <div className="font-mono text-xs text-slate-400">
                  SWAMP Core Engine Hash: 8f4a21e-2026-11
                </div>
              </div>
            </section>
          </>
        )}

        {/* TAB 2: RETESTING COMPARE */}
        {activeTab === "retesting-compare" && (
          <section className="w-full bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col gap-4 text-left">
            <div className="flex items-center justify-between border-b border-slate-200 pb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  Komparasi Pengujian Ulang (Retesting Compare)
                </h2>
                <p className="text-xs text-slate-500">
                  Analisis diferensial antara pemindaian awal (Baseline Audit) dan
                  verifikasi pengujian ulang (Retest)
                </p>
              </div>
            </div>

            {scanHistory.length >= 2 && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-500 block mb-1">
                    Scan Awal (Baseline)
                  </label>
                  <select
                    value={baselineId}
                    onChange={(e) => setBaselineId(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 rounded-lg text-xs bg-white"
                  >
                    {scanHistory.map((s) => (
                      <option key={s.id} value={s.id}>
                        Scan #{s.id} {s.target_url} (Grade {s.grade})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-[11px] font-bold uppercase text-slate-500 block mb-1">
                    Scan Ulang (Retest)
                  </label>
                  <select
                    value={retestId}
                    onChange={(e) => setRetestId(e.target.value)}
                    className="w-full p-2.5 border border-slate-200 rounded-lg text-xs bg-white"
                  >
                    {scanHistory.map((s) => (
                      <option key={s.id} value={s.id}>
                        Scan #{s.id} {s.target_url} (Grade {s.grade})
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  onClick={handleCompareScans}
                  className="px-4 py-2.5 bg-slate-900 text-white rounded-lg text-xs font-semibold cursor-pointer"
                >
                  Bandingkan Hasil Scan
                </button>
              </div>
            )}

            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold uppercase text-slate-500">
                  <th className="py-3 px-4">MODUL</th>
                  <th className="py-3 px-4">TEMUAN KERENTANAN</th>
                  <th className="py-3 px-4">STATUS AWAL (SCAN #1)</th>
                  <th className="py-3 px-4">STATUS RETEST (SCAN #2)</th>
                  <th className="py-3 px-4">DELTA REMEDIASI</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {(
                  comparisonData?.comparison || [
                    {
                      module: "HTTP Security Headers",
                      title: "Missing Strict-Transport-Security (HSTS)",
                      baseline_status: "Unmitigated (High)",
                      retest_status: "Header Present & Valid",
                      delta: "FIXED",
                    },
                    {
                      module: "HTTP Security Headers",
                      title: "Missing Content-Security-Policy (CSP)",
                      baseline_status: "Unmitigated (High)",
                      retest_status: "Unmitigated (High)",
                      delta: "STILL OPEN",
                    },
                  ]
                ).map((row, idx) => (
                  <tr key={idx}>
                    <td className="py-3.5 px-4 font-mono text-slate-600">
                      {row.module}
                    </td>
                    <td className="py-3.5 px-4 font-semibold text-slate-900">
                      {row.title}
                    </td>
                    <td className="py-3.5 px-4 text-rose-600">
                      {row.baseline_status}
                    </td>
                    <td className="py-3.5 px-4 text-slate-900">
                      {row.retest_status}
                    </td>
                    <td className="py-3.5 px-4">
                      {row.delta === "FIXED" && (
                        <span className="px-2.5 py-1 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold text-xs">
                          ✓ FIXED (RESOLVED)
                        </span>
                      )}
                      {row.delta === "STILL OPEN" && (
                        <span className="px-2.5 py-1 rounded bg-rose-50 text-rose-800 border border-rose-200 font-semibold text-xs">
                          ✕ STILL OPEN
                        </span>
                      )}
                      {row.delta === "NEW FINDING" && (
                        <span className="px-2.5 py-1 rounded bg-amber-50 text-amber-800 border border-amber-200 font-semibold text-xs">
                          ! NEW FINDING
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {/* TAB 3: KNOWLEDGE BASE (CRUD) */}
        {activeTab === "knowledge-base" && (
          <section className="w-full bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col gap-4 text-left">
            <div className="flex items-center justify-between border-b border-slate-200 pb-4">
              <div>
                <h2 className="text-lg font-bold text-slate-900">
                  Manajemen Whitelist Scope &amp; Knowledge Base (CRUD)
                </h2>
                <p className="text-xs text-slate-500">
                  Pengelolaan cakupan domain yang diizinkan serta kamus mitigasi
                  standar OWASP WSTG
                </p>
              </div>
              <span className="px-3 py-1 rounded bg-slate-900 text-white text-[11px] font-bold uppercase">
                ADMIN ROLE ONLY • RBAC ENFORCED
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="border border-slate-200 rounded-xl p-4 flex flex-col gap-2.5">
                <h3 className="text-sm font-bold text-slate-900">
                  Whitelist Cakupan ({activeProject.name})
                </h3>
                {activeProject.allowed_domains
                  .split(",")
                  .map((d) => d.trim())
                  .filter(Boolean)
                  .map((dom, i) => (
                    <div
                      key={i}
                      className="px-3 py-2 bg-slate-50 border border-slate-200 rounded flex items-center justify-between font-mono text-xs"
                    >
                      <span>{dom}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded text-[10px]">
                          AUTHORIZED
                        </span>
                        <button
                          type="button"
                          onClick={() => handleRemoveWhitelistDomain(dom)}
                          className="text-rose-600 hover:text-rose-800 hover:underline font-sans font-semibold text-xs cursor-pointer"
                          title={`Hapus ${dom} dari whitelist`}
                        >
                          Hapus
                        </button>
                      </div>
                    </div>
                  ))}
                <div className="flex gap-2 pt-2">
                  <input
                    type="text"
                    value={newDomainInput}
                    onChange={(e) => setNewDomainInput(e.target.value)}
                    placeholder="contoh: igracias.telkomuniversity.ac.id"
                    className="flex-1 px-3 py-2 border border-slate-200 rounded font-mono text-xs"
                  />
                  <button
                    type="button"
                    onClick={handleAddWhitelistDomain}
                    className="px-4 py-2 bg-slate-900 text-white rounded text-xs font-semibold cursor-pointer"
                  >
                    + Tambah
                  </button>
                </div>
              </div>

              <div className="lg:col-span-2 border border-slate-200 rounded-xl p-4 flex flex-col gap-3">
                <h3 className="text-sm font-bold text-slate-900">
                  Template Mitigasi Standar OWASP WSTG
                </h3>
                <form
                  onSubmit={handleCreateKb}
                  className="grid grid-cols-1 sm:grid-cols-3 gap-2"
                >
                  <input
                    type="text"
                    required
                    placeholder="Judul Kerentanan"
                    value={newKb.title}
                    onChange={(e) =>
                      setNewKb({ ...newKb, title: e.target.value })
                    }
                    className="px-3 py-2 border border-slate-200 rounded text-xs"
                  />
                  <select
                    value={newKb.severity}
                    onChange={(e) =>
                      setNewKb({ ...newKb, severity: e.target.value })
                    }
                    className="px-3 py-2 border border-slate-200 rounded text-xs bg-white"
                  >
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>
                  <input
                    type="text"
                    required
                    placeholder="Kode WSTG"
                    value={newKb.wstg_code}
                    onChange={(e) =>
                      setNewKb({ ...newKb, wstg_code: e.target.value })
                    }
                    className="px-3 py-2 border border-slate-200 rounded font-mono text-xs"
                  />
                  <input
                    type="text"
                    required
                    placeholder="Rekomendasi Mitigasi..."
                    value={newKb.mitigation_template}
                    onChange={(e) =>
                      setNewKb({
                        ...newKb,
                        mitigation_template: e.target.value,
                      })
                    }
                    className="sm:col-span-2 px-3 py-2 border border-slate-200 rounded text-xs"
                  />
                  <button
                    type="submit"
                    className="px-4 py-2 bg-slate-900 text-white rounded text-xs font-semibold cursor-pointer"
                  >
                    + Simpan Template KB
                  </button>
                </form>

                <table className="w-full text-left border-collapse text-xs mt-2">
                  <thead>
                    <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold uppercase text-slate-500">
                      <th className="py-2.5 px-3">KERENTANAN</th>
                      <th className="py-2.5 px-3">SEVERITY</th>
                      <th className="py-2.5 px-3">KODE WSTG</th>
                      <th className="py-2.5 px-3 text-right">AKSI</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {kbList.map((kb) => (
                      <tr key={kb.id}>
                        <td className="py-2.5 px-3">
                          <div className="font-semibold text-slate-900">
                            {kb.title}
                          </div>
                          <div className="text-slate-500 text-xs">
                            {kb.mitigation_template}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-semibold">
                          {kb.severity}
                        </td>
                        <td className="py-2.5 px-3 font-mono">{kb.wstg_code}</td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            type="button"
                            onClick={() => handleDeleteKb(kb.id)}
                            className="text-rose-600 hover:underline font-semibold cursor-pointer"
                          >
                            Hapus
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}

        {/* TAB 4: AUDIT LOGS */}
        {activeTab === "audit-logs" && (
          <section className="w-full bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col gap-4 text-left">
            <div>
              <h2 className="text-lg font-bold text-slate-900">
                Catatan Aktivitas Sistem (System Audit Logs)
              </h2>
              <p className="text-xs text-slate-500">
                Rekam jejak otomatis eksekusi pemindaian, verifikasi temuan, dan
                pemblokiran target di luar cakupan
              </p>
            </div>

            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold uppercase text-slate-500">
                  <th className="py-3 px-4">WAKTU</th>
                  <th className="py-3 px-4">PENGGUNA</th>
                  <th className="py-3 px-4">PERAN</th>
                  <th className="py-3 px-4">AKSI</th>
                  <th className="py-3 px-4">TARGET</th>
                  <th className="py-3 px-4">DETAIL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="py-3 px-4 font-mono text-slate-500 whitespace-nowrap">
                      {log.timestamp}
                    </td>
                    <td className="py-3 px-4 font-semibold whitespace-nowrap">
                      {log.username}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">{log.role}</td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      {log.action_type}
                    </td>
                    <td className="py-3 px-4 font-mono whitespace-nowrap">
                      {log.target}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-semibold mr-2 ${log.status === "SUCCESS"
                            ? "bg-emerald-50 text-emerald-800"
                            : log.status === "BLOCKED"
                              ? "bg-rose-50 text-rose-800"
                              : "bg-slate-100 text-slate-800"
                          }`}
                      >
                        {log.status}
                      </span>
                      <span>{log.detail}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}
      </main>

      {/* FOOTER FULL-WIDTH */}
      <footer className="w-full bg-white border-t border-slate-200 py-5 mt-auto print:hidden">
        <div className="w-full px-8 xl:px-14 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-900">SWAMP</span>
            <span>
              © 2026 Scoped Web Assessment &amp; Management Platform. Utilitarian
              Header &amp; Directive Audit.
            </span>
          </div>
          <div className="flex items-center gap-6">
            <span>Direktif RFC 9110</span>
            <span>Standar OWASP WSTG</span>
            <span>Observatory Engine</span>
          </div>
        </div>
      </footer>
    </div>
  );
}