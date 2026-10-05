"""
Audit Orchestrator — coordinates asset inventory, dependency
scanning, Semgrep, and Bandit to produce a unified ``AuditReport``.

Usage
-----
    from blue_agent.audit import run_full_audit

    report = run_full_audit("/path/to/target_app")
"""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AuditReport, Severity, VulnerabilityFinding

from blue_agent.audit.asset_inventory import collect_inventory
from blue_agent.audit.bandit_scanner import scan_with_bandit
from blue_agent.audit.dependency_scanner import scan_dependencies
from blue_agent.audit.semgrep_scanner import scan_with_semgrep

log = get_logger("audit.orchestrator")


def run_full_audit(
    target_path: Optional[str] = None,
    scan_host: str = "127.0.0.1",
) -> AuditReport:
    """
    Execute the complete audit pipeline:

    1. Asset inventory
    2. Dependency scanning  (OWASP DC + pip-audit)
    3. Semgrep SAST
    4. Bandit Python lint

    Returns an ``AuditReport`` with all findings normalized.
    """
    tp = target_path or settings.audit.target_app_path
    log.info("audit_starting", target=tp)
    t0 = time.perf_counter()

    # 1. Asset inventory
    assets = collect_inventory(tp, scan_host=scan_host)

    # 2. Dependency scan
    dep_findings = scan_dependencies(tp)

    # 3. Semgrep
    semgrep_findings = scan_with_semgrep(tp)

    # 4. Bandit
    bandit_findings = scan_with_bandit(tp)

    # Merge all findings
    all_findings: list[VulnerabilityFinding] = []
    all_findings.extend(dep_findings)
    all_findings.extend(semgrep_findings)
    all_findings.extend(bandit_findings)

    # Summary by severity
    severity_counts = Counter(f.severity.value for f in all_findings)
    source_counts = Counter(f.source for f in all_findings)
    summary = {
        "total": len(all_findings),
        **{sev: severity_counts.get(sev, 0) for sev in ("critical", "high", "medium", "low", "unknown")},
        **{f"source_{src}": cnt for src, cnt in source_counts.items()},
    }

    elapsed_ms = (time.perf_counter() - t0) * 1000

    report = AuditReport(
        target_path=str(tp),
        target_url=settings.audit.target_app_url,
        assets=assets,
        dependencies=assets.get("dependencies", []),
        findings=all_findings,
        summary=summary,
    )

    log.info(
        "audit_complete",
        total_findings=len(all_findings),
        critical=severity_counts.get("critical", 0),
        high=severity_counts.get("high", 0),
        elapsed_ms=round(elapsed_ms, 2),
    )
    return report


def run_quick_audit(
    target_path: Optional[str] = None,
) -> AuditReport:
    """
    Lightweight audit — only Bandit + Semgrep, no dependency scan.

    Useful for re-auditing after a patch.
    """
    tp = target_path or settings.audit.target_app_path
    log.info("quick_audit_starting", target=tp)
    t0 = time.perf_counter()

    semgrep_findings = scan_with_semgrep(tp)
    bandit_findings = scan_with_bandit(tp)

    all_findings = semgrep_findings + bandit_findings
    severity_counts = Counter(f.severity.value for f in all_findings)

    report = AuditReport(
        target_path=str(tp),
        target_url=settings.audit.target_app_url,
        findings=all_findings,
        summary={
            "total": len(all_findings),
            **{sev: severity_counts.get(sev, 0) for sev in ("critical", "high", "medium", "low", "unknown")},
        },
    )

    elapsed_ms = (time.perf_counter() - t0) * 1000
    log.info("quick_audit_complete", total_findings=len(all_findings), elapsed_ms=round(elapsed_ms, 2))
    return report
