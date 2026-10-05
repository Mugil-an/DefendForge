"""
Bandit Scanner — runs the Bandit Python security linter against
the target application and normalizes results.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import Severity, VulnerabilityFinding

log = get_logger("audit.bandit_scanner")

# Bandit uses confidence + severity; we combine them.
_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def run_bandit(
    target_path: Optional[str] = None,
    config_path: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[VulnerabilityFinding]:
    """
    Execute ``bandit`` CLI against *target_path*.

    Parameters
    ----------
    target_path : str, optional
        Directory or file to scan.
    config_path : str, optional
        Path to a Bandit configuration file.
    extra_args : list[str], optional
        Additional CLI flags.

    Returns
    -------
    list[VulnerabilityFinding]
    """
    tp = target_path or settings.audit.target_app_path
    conf = config_path or settings.audit.bandit_config

    cmd = [
        "bandit",
        "-r",               # recursive
        "-f", "json",       # JSON output
        "-q",               # quiet (no progress bar)
        str(tp),
    ]
    if conf:
        cmd.extend(["-c", conf])
    if extra_args:
        cmd.extend(extra_args)

    log.info("bandit_starting", target=tp)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        log.warning("bandit_not_installed")
        return []
    except subprocess.TimeoutExpired:
        log.error("bandit_timeout")
        return []

    # bandit exit codes: 0=clean, 1=issues found
    if proc.returncode not in (0, 1):
        log.error(
            "bandit_error",
            returncode=proc.returncode,
            stderr=proc.stderr[:500],
        )
        return []

    return _parse_bandit_output(proc.stdout, tp)


def _parse_bandit_output(
    raw_json: str, target_path: str
) -> List[VulnerabilityFinding]:
    """Parse Bandit JSON and normalise into ``VulnerabilityFinding``."""
    findings: List[VulnerabilityFinding] = []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error("bandit_json_parse_error", error=str(exc))
        return findings

    for result in data.get("results", []):
        sev_str = result.get("issue_severity", "MEDIUM").upper()
        confidence_str = result.get("issue_confidence", "MEDIUM").upper()

        # Promote severity if confidence is HIGH
        severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
        if severity == Severity.MEDIUM and confidence_str == "HIGH":
            severity = Severity.HIGH

        # CWE — Bandit includes CWE in some rules
        cwe = ""
        cwe_data = result.get("issue_cwe", {})
        if isinstance(cwe_data, dict) and cwe_data.get("id"):
            cwe = f"CWE-{cwe_data['id']}"

        file_path = result.get("filename", "")
        try:
            file_path = str(Path(file_path).relative_to(target_path))
        except ValueError:
            pass

        finding = VulnerabilityFinding(
            source="bandit",
            cwe=cwe,
            severity=severity,
            file=file_path,
            line=result.get("line_number"),
            component=result.get("test_id", ""),
            description=result.get("issue_text", ""),
            evidence=result.get("code", ""),
        )
        findings.append(finding)

    log.info("bandit_findings_parsed", count=len(findings))
    return findings


def scan_with_bandit(
    target_path: Optional[str] = None,
) -> List[VulnerabilityFinding]:
    """Run Bandit scan — thin convenience wrapper."""
    return run_bandit(target_path)
