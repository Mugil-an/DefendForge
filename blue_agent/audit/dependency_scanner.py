"""
Dependency Scanner — identifies known-vulnerable packages
by comparing installed versions against vulnerability databases.

In a full deployment, this wraps OWASP Dependency-Check CLI.
For the MVP, it also performs a lightweight pip-audit style
check against the PyPI advisory feed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import Severity, VulnerabilityFinding

log = get_logger("audit.dependency_scanner")


# ---------------------------------------------------------------------------
# OWASP Dependency-Check wrapper
# ---------------------------------------------------------------------------
def run_dependency_check(
    target_path: str,
    output_dir: Optional[str] = None,
) -> List[VulnerabilityFinding]:
    """
    Run OWASP Dependency-Check against *target_path*.

    Returns normalized ``VulnerabilityFinding`` objects.
    Falls back gracefully if the CLI is not installed.
    """
    dc_path = settings.audit.dependency_check_path
    out = Path(output_dir) if output_dir else Path(target_path) / ".dependency-check"
    out.mkdir(parents=True, exist_ok=True)

    cmd = [
        dc_path,
        "--scan", target_path,
        "--format", "JSON",
        "--out", str(out),
        "--noupdate",           # use cached data; set False for prod
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        log.warning("dependency_check_not_found", path=dc_path)
        return []
    except subprocess.TimeoutExpired:
        log.error("dependency_check_timeout")
        return []

    if proc.returncode not in (0, 1):  # 1 = vulns found
        log.error(
            "dependency_check_failed",
            returncode=proc.returncode,
            stderr=proc.stderr[:500],
        )
        return []

    return _parse_dependency_check_json(out)


def _parse_dependency_check_json(out_dir: Path) -> List[VulnerabilityFinding]:
    """Parse the JSON report produced by dependency-check."""
    findings: List[VulnerabilityFinding] = []
    json_files = list(out_dir.glob("*.json"))
    if not json_files:
        return findings

    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("dependency_check_parse_error", file=str(jf), error=str(exc))
            continue

        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                severity = _map_cvss_severity(vuln.get("cvssv3", {}).get("baseScore", 0.0))
                cwes = vuln.get("cwes", [])
                cwe = f"CWE-{cwes[0]}" if cwes else ""
                findings.append(VulnerabilityFinding(
                    source="dependency-check",
                    cwe=cwe,
                    severity=severity,
                    component=dep.get("fileName", ""),
                    description=vuln.get("description", ""),
                    evidence=vuln.get("name", ""),
                ))
    log.info("dependency_check_findings", count=len(findings))
    return findings


def _map_cvss_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.UNKNOWN


# ---------------------------------------------------------------------------
# Lightweight pip-audit check (no external tool required)
# ---------------------------------------------------------------------------
def pip_audit_check(
    requirements_path: Optional[str] = None,
) -> List[VulnerabilityFinding]:
    """
    Run ``pip-audit`` if available.  Falls back gracefully.

    ``pip-audit`` queries the PyPI advisory database.
    """
    cmd = ["pip-audit", "--format", "json"]
    if requirements_path:
        cmd += ["--requirement", requirements_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        log.info("pip_audit_not_installed")
        return []
    except subprocess.TimeoutExpired:
        log.error("pip_audit_timeout")
        return []

    findings: List[VulnerabilityFinding] = []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return findings

    for entry in data.get("dependencies", []):
        for vuln in entry.get("vulns", []):
            findings.append(VulnerabilityFinding(
                source="pip-audit",
                cwe="",
                severity=Severity.MEDIUM,   # pip-audit doesn't always give CVSS
                component=entry.get("name", ""),
                description=vuln.get("description", vuln.get("id", "")),
                evidence=vuln.get("id", ""),
            ))

    log.info("pip_audit_findings", count=len(findings))
    return findings


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def scan_dependencies(
    target_path: Optional[str] = None,
) -> List[VulnerabilityFinding]:
    """Run all available dependency scanners and return merged findings."""
    tp = target_path or settings.audit.target_app_path
    results: List[VulnerabilityFinding] = []

    results.extend(run_dependency_check(tp))

    # Also try pip-audit on any requirements.txt we find
    root = Path(tp)
    for req_file in root.rglob("requirements*.txt"):
        results.extend(pip_audit_check(str(req_file)))

    log.info("dependency_scan_total", count=len(results))
    return results
