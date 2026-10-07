"""
Red Agent — Live HTTP Reconnaissance Scanner.

Performs real endpoint discovery, technology fingerprinting, and
vulnerability surface mapping against a target application.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from blue_agent.logging_cfg import get_logger

log = get_logger("red.recon.scanner")

# Common paths to probe for endpoint discovery
_COMMON_PATHS = [
    "/", "/login", "/admin", "/admin/users", "/api", "/api/health",
    "/health", "/search", "/greet", "/ping", "/file", "/fetch",
    "/load", "/posts", "/comments", "/about", "/contact",
    "/register", "/signup", "/logout", "/dashboard", "/settings",
    "/profile", "/upload", "/download", "/config", "/env",
    "/debug", "/test", "/status", "/.env", "/robots.txt",
    "/sitemap.xml", "/.git/config", "/wp-admin", "/phpmyadmin",
    "/api/v1", "/api/v2", "/graphql", "/swagger", "/docs",
]

# HTTP methods to test on discovered endpoints
_METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""
    path: str
    method: str
    status_code: int
    content_type: str = ""
    response_size: int = 0
    response_time_ms: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)
    accepts_params: bool = False
    requires_auth: bool = False
    has_form: bool = False
    technologies: list[str] = field(default_factory=list)


@dataclass
class ReconReport:
    """Full reconnaissance report for a target."""
    target_url: str
    discovered_endpoints: list[EndpointInfo] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    server_info: str = ""
    potential_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    open_params: dict[str, list[str]] = field(default_factory=dict)
    scan_duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "endpoints": [
                {
                    "path": ep.path, "method": ep.method,
                    "status_code": ep.status_code,
                    "content_type": ep.content_type,
                    "response_size": ep.response_size,
                    "requires_auth": ep.requires_auth,
                    "has_form": ep.has_form,
                    "technologies": ep.technologies,
                }
                for ep in self.discovered_endpoints
            ],
            "technologies": self.technologies,
            "server_info": self.server_info,
            "potential_vulnerabilities": self.potential_vulnerabilities,
            "open_params": self.open_params,
            "scan_duration_ms": self.scan_duration_ms,
        }

    def summary(self) -> str:
        lines = [f"Target: {self.target_url}"]
        lines.append(f"Endpoints discovered: {len(self.discovered_endpoints)}")
        lines.append(f"Technologies: {', '.join(self.technologies) or 'unknown'}")
        lines.append(f"Server: {self.server_info or 'unknown'}")
        lines.append(f"Potential vulns: {len(self.potential_vulnerabilities)}")
        for vuln in self.potential_vulnerabilities:
            lines.append(f"  - [{vuln.get('severity', '?')}] {vuln.get('type', '?')}: {vuln.get('detail', '')}")
        return "\n".join(lines)


class LiveScanner:
    """
    Performs real HTTP reconnaissance against a target application.

    Safety: Only targets allowlisted hosts (localhost, target_app, etc.).
    """

    ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "target_app", "target-app"}

    def __init__(self, target_url: str, *, timeout: float = 5.0):
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        if parsed.hostname not in self.ALLOWED_HOSTS:
            raise ValueError(f"Reconnaissance restricted to local targets, got: {parsed.hostname}")
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout, follow_redirects=True)

    def close(self):
        self._client.close()

    def scan(self) -> ReconReport:
        """Run full reconnaissance scan."""
        t0 = time.perf_counter()
        report = ReconReport(target_url=self.target_url)

        # Phase 1: Endpoint discovery
        log.info("recon_phase_1_endpoint_discovery", target=self.target_url)
        self._discover_endpoints(report)

        # Phase 2: Technology fingerprinting
        log.info("recon_phase_2_tech_fingerprint", endpoints=len(report.discovered_endpoints))
        self._fingerprint_technologies(report)

        # Phase 3: Vulnerability surface mapping
        log.info("recon_phase_3_vuln_mapping")
        self._map_vulnerabilities(report)

        # Phase 4: Parameter discovery
        log.info("recon_phase_4_param_discovery")
        self._discover_parameters(report)

        report.scan_duration_ms = (time.perf_counter() - t0) * 1000
        log.info("recon_complete",
                 endpoints=len(report.discovered_endpoints),
                 vulns=len(report.potential_vulnerabilities),
                 duration_ms=round(report.scan_duration_ms, 1))
        return report

    def _discover_endpoints(self, report: ReconReport) -> None:
        """Probe common paths to find live endpoints."""
        for path in _COMMON_PATHS:
            try:
                url = urljoin(self.target_url + "/", path.lstrip("/"))
                resp = self._client.get(url)
                if resp.status_code < 500 or resp.status_code == 500:
                    ep = EndpointInfo(
                        path=path,
                        method="GET",
                        status_code=resp.status_code,
                        content_type=resp.headers.get("content-type", ""),
                        response_size=len(resp.content),
                        response_time_ms=resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0,
                        headers=dict(resp.headers),
                        requires_auth=resp.status_code == 401,
                    )
                    # Check if response contains HTML forms
                    body = resp.text[:4096]
                    if "<form" in body.lower():
                        ep.has_form = True
                    if resp.status_code != 404:
                        report.discovered_endpoints.append(ep)
            except httpx.HTTPError:
                continue

    def _fingerprint_technologies(self, report: ReconReport) -> None:
        """Identify server technologies from response headers and content."""
        techs = set()
        server_info = ""

        for ep in report.discovered_endpoints:
            # Server header
            server = ep.headers.get("server", "")
            if server:
                server_info = server
                techs.add(server)

            # Framework detection
            powered_by = ep.headers.get("x-powered-by", "")
            if powered_by:
                techs.add(powered_by)

            # Content type hints
            ct = ep.content_type.lower()
            if "json" in ct:
                techs.add("JSON API")
            if "html" in ct:
                techs.add("HTML")

            # Cookie-based detection
            cookies = ep.headers.get("set-cookie", "")
            if "flask" in cookies.lower() or "session" in cookies.lower():
                techs.add("Flask")
            if "express" in cookies.lower():
                techs.add("Express.js")

        # Try to detect Flask specifically
        try:
            resp = self._client.get(f"{self.target_url}/nonexistent_path_12345")
            if "werkzeug" in resp.text.lower() or "flask" in resp.text.lower():
                techs.add("Flask/Werkzeug")
            if "<!doctype html>" in resp.text.lower() and "not found" in resp.text.lower():
                techs.add("Flask")
        except httpx.HTTPError:
            pass

        report.technologies = sorted(techs)
        report.server_info = server_info

    def _map_vulnerabilities(self, report: ReconReport) -> None:
        """Identify potential vulnerability surfaces from discovered endpoints."""
        for ep in report.discovered_endpoints:
            # SQL injection surfaces — endpoints with query params or forms
            if ep.has_form and ep.path in ("/login", "/search", "/comments"):
                report.potential_vulnerabilities.append({
                    "type": "SQL Injection Surface",
                    "endpoint": ep.path,
                    "method": "POST" if ep.has_form else "GET",
                    "severity": "high",
                    "cwe": "CWE-89",
                    "mitre": "T1190",
                    "detail": f"Form-based input on {ep.path} may be vulnerable to SQL injection",
                })

            # XSS surfaces — endpoints that reflect input
            if ep.path in ("/greet",):
                report.potential_vulnerabilities.append({
                    "type": "Reflected XSS Surface",
                    "endpoint": ep.path,
                    "method": "GET",
                    "severity": "medium",
                    "cwe": "CWE-79",
                    "mitre": "T1189",
                    "detail": f"Reflected input on {ep.path} may allow script injection",
                })

            # Command injection — system command endpoints
            if ep.path in ("/ping",):
                report.potential_vulnerabilities.append({
                    "type": "Command Injection Surface",
                    "endpoint": ep.path,
                    "method": "GET",
                    "severity": "critical",
                    "cwe": "CWE-78",
                    "mitre": "T1059",
                    "detail": f"System command execution via {ep.path}",
                })

            # Path traversal — file access endpoints
            if ep.path in ("/file",):
                report.potential_vulnerabilities.append({
                    "type": "Path Traversal Surface",
                    "endpoint": ep.path,
                    "method": "GET",
                    "severity": "high",
                    "cwe": "CWE-22",
                    "mitre": "T1083",
                    "detail": f"File access via {ep.path} may allow directory traversal",
                })

            # SSRF surfaces
            if ep.path in ("/fetch",):
                report.potential_vulnerabilities.append({
                    "type": "SSRF Surface",
                    "endpoint": ep.path,
                    "method": "GET",
                    "severity": "high",
                    "cwe": "CWE-918",
                    "mitre": "T1190",
                    "detail": f"URL fetch on {ep.path} may allow SSRF",
                })

            # Insecure deserialization
            if ep.path in ("/load",):
                report.potential_vulnerabilities.append({
                    "type": "Insecure Deserialization Surface",
                    "endpoint": ep.path,
                    "method": "POST",
                    "severity": "critical",
                    "cwe": "CWE-502",
                    "mitre": "T1190",
                    "detail": f"Object loading via {ep.path} may allow deserialization attacks",
                })

            # Broken access control
            if ep.path.startswith("/admin") and not ep.requires_auth:
                report.potential_vulnerabilities.append({
                    "type": "Broken Access Control",
                    "endpoint": ep.path,
                    "method": "GET",
                    "severity": "high",
                    "cwe": "CWE-284",
                    "mitre": "T1078",
                    "detail": f"Admin endpoint {ep.path} accessible without authentication",
                })

        # Active probing for specific vulns
        self._probe_sql_injection(report)
        self._probe_xss(report)
        self._probe_path_traversal(report)

    def _probe_sql_injection(self, report: ReconReport) -> None:
        """Send lightweight SQL injection probes to confirm vulnerability."""
        test_payloads = [
            ("/login", "POST", {"username": "' OR '1'='1", "password": "test"}),
            ("/search", "GET", {"q": "' OR 1=1--"}),
        ]
        for path, method, params in test_payloads:
            try:
                url = f"{self.target_url}{path}"
                if method == "POST":
                    resp = self._client.post(url, data=params)
                else:
                    resp = self._client.get(url, params=params)

                # If we get a 200 on login with SQLi payload, it's vulnerable
                if path == "/login" and resp.status_code == 200:
                    body = resp.json() if "json" in resp.headers.get("content-type", "") else {}
                    if body.get("message") == "Login successful":
                        report.potential_vulnerabilities.append({
                            "type": "SQL Injection (Confirmed)",
                            "endpoint": path,
                            "method": method,
                            "severity": "critical",
                            "cwe": "CWE-89",
                            "mitre": "T1190",
                            "detail": "Authentication bypass via SQL injection confirmed",
                            "confirmed": True,
                        })
            except (httpx.HTTPError, Exception):
                continue

    def _probe_xss(self, report: ReconReport) -> None:
        """Send lightweight XSS probes."""
        try:
            resp = self._client.get(f"{self.target_url}/greet", params={"name": "<test_xss_probe>"})
            if "<test_xss_probe>" in resp.text:
                report.potential_vulnerabilities.append({
                    "type": "Reflected XSS (Confirmed)",
                    "endpoint": "/greet",
                    "method": "GET",
                    "severity": "medium",
                    "cwe": "CWE-79",
                    "mitre": "T1189",
                    "detail": "Input reflected without encoding in /greet response",
                    "confirmed": True,
                })
        except (httpx.HTTPError, Exception):
            pass

    def _probe_path_traversal(self, report: ReconReport) -> None:
        """Send lightweight path traversal probes."""
        try:
            resp = self._client.get(f"{self.target_url}/file", params={"name": "../../../../etc/hostname"})
            if resp.status_code == 200 and resp.json().get("content"):
                report.potential_vulnerabilities.append({
                    "type": "Path Traversal (Confirmed)",
                    "endpoint": "/file",
                    "method": "GET",
                    "severity": "high",
                    "cwe": "CWE-22",
                    "mitre": "T1083",
                    "detail": "Directory traversal allows reading files outside web root",
                    "confirmed": True,
                })
        except (httpx.HTTPError, Exception):
            pass

    def _discover_parameters(self, report: ReconReport) -> None:
        """Map expected parameters for each discovered endpoint."""
        # Known parameter mappings based on common web patterns
        param_tests = {
            "/login": ["username", "password"],
            "/search": ["q", "query", "search"],
            "/greet": ["name"],
            "/ping": ["host", "ip", "target"],
            "/file": ["name", "filename", "path"],
            "/fetch": ["url", "target"],
            "/comments": ["post_id", "body", "comment"],
            "/posts": ["title", "content"],
        }

        for ep in report.discovered_endpoints:
            if ep.path in param_tests:
                report.open_params[ep.path] = param_tests[ep.path]
