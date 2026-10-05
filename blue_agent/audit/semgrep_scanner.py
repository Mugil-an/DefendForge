"""
Semgrep Scanner — runs the Semgrep static analysis engine against
the target application source code and normalizes results into
``VulnerabilityFinding`` objects.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List, Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import Severity, VulnerabilityFinding

log = get_logger("audit.semgrep_scanner")

# Maps semgrep severity strings → our Severity enum
_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def run_semgrep(
    target_path: Optional[str] = None,
    rules: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[VulnerabilityFinding]:
    """
    Execute ``semgrep`` CLI against *target_path*.

    Parameters
    ----------
    target_path : str, optional
        Directory to scan.  Defaults to ``settings.audit.target_app_path``.
    rules : str, optional
        Semgrep ruleset identifier (e.g. ``p/python``, ``p/owasp-top-ten``).
        Defaults to ``settings.audit.semgrep_rules``.
    extra_args : list[str], optional
        Additional CLI flags forwarded to semgrep.

    Returns
    -------
    list[VulnerabilityFinding]
        Normalized findings.
    """
    tp = target_path or settings.audit.target_app_path
    ruleset = rules or settings.audit.semgrep_rules

    cmd = [
        "semgrep",
        "--config", ruleset,
        "--json",
        "--quiet",
        str(tp),
    ]
    if extra_args:
        cmd.extend(extra_args)

    log.info("semgrep_starting", target=tp, rules=ruleset)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        log.warning("semgrep_not_installed")
        return []
    except subprocess.TimeoutExpired:
        log.error("semgrep_timeout")
        return []

    # semgrep returns 0 = clean, 1 = findings, other = error
    if proc.returncode not in (0, 1):
        log.error(
            "semgrep_error",
            returncode=proc.returncode,
            stderr=proc.stderr[:500],
        )
        return []

    return _parse_semgrep_output(proc.stdout, tp)


def _parse_semgrep_output(
    raw_json: str, target_path: str
) -> List[VulnerabilityFinding]:
    """Parse Semgrep JSON output into ``VulnerabilityFinding`` objects."""
    findings: List[VulnerabilityFinding] = []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        log.error("semgrep_json_parse_error", error=str(exc))
        return findings

    for result in data.get("results", []):
        # Extract CWE from metadata if available
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else str(cwe_list) if cwe_list else ""

        severity_str = result.get("extra", {}).get("severity", "INFO")
        severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.UNKNOWN)

        file_path = result.get("path", "")
        # Make path relative to target for readability
        try:
            file_path = str(Path(file_path).relative_to(target_path))
        except ValueError:
            pass

        finding = VulnerabilityFinding(
            source="semgrep",
            cwe=cwe,
            severity=severity,
            file=file_path,
            line=result.get("start", {}).get("line"),
            component=result.get("check_id", ""),
            description=result.get("extra", {}).get("message", ""),
            evidence=result.get("extra", {}).get("lines", ""),
        )
        findings.append(finding)

    log.info("semgrep_findings_parsed", count=len(findings))
    return findings


def scan_with_semgrep(
    target_path: Optional[str] = None,
) -> List[VulnerabilityFinding]:
    """
    Convenience wrapper — runs semgrep with multiple rulesets.

    Runs both the language-specific ruleset and OWASP top-ten rules
    for broader coverage.
    """
    tp = target_path or settings.audit.target_app_path
    all_findings: List[VulnerabilityFinding] = []

    # Primary ruleset
    all_findings.extend(run_semgrep(tp))

    # OWASP top-ten (additional coverage)
    owasp_findings = run_semgrep(tp, rules="p/owasp-top-ten")
    # Deduplicate by (file, line, component)
    existing = {
        (f.file, f.line, f.component) for f in all_findings
    }
    for f in owasp_findings:
        key = (f.file, f.line, f.component)
        if key not in existing:
            all_findings.append(f)
            existing.add(key)

    log.info("semgrep_total_findings", count=len(all_findings))
    return all_findings
