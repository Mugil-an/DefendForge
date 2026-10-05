"""
Tests for blue_agent.audit — asset inventory, scanners, orchestrator.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from blue_agent.schemas import Severity, VulnerabilityFinding


# ---------------------------------------------------------------------------
# Asset Inventory
# ---------------------------------------------------------------------------
class TestAssetInventory:
    def test_discover_source_files(self, tmp_path: Path):
        from blue_agent.audit.asset_inventory import discover_source_files

        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "style.css").write_text("body{}")
        (tmp_path / "readme.md").write_text("# Readme")  # not a source ext we track (no .md)
        # Files inside .venv should be skipped
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir(parents=True, exist_ok=True)
        (venv_dir / "lib.py").write_text("import os")

        files = discover_source_files(tmp_path)
        names = [f["path"] for f in files]
        assert "app.py" in names
        assert "style.css" in names

    def test_discover_config_files(self, tmp_path: Path):
        from blue_agent.audit.asset_inventory import discover_config_files

        (tmp_path / "Dockerfile").write_text("FROM python:3.11")
        (tmp_path / "config.py").write_text("DEBUG = True")
        (tmp_path / "random.txt").write_text("nope")

        configs = discover_config_files(tmp_path)
        names = [c["name"] for c in configs]
        assert "Dockerfile" in names
        assert "config.py" in names
        assert "random.txt" not in names

    def test_discover_dependency_manifests(self, tmp_path: Path):
        from blue_agent.audit.asset_inventory import discover_dependency_manifests

        (tmp_path / "requirements.txt").write_text("flask>=3.0")
        manifests = discover_dependency_manifests(tmp_path)
        assert len(manifests) >= 1

    def test_parse_requirements_txt(self, tmp_path: Path):
        from blue_agent.audit.asset_inventory import parse_requirements_txt

        req = tmp_path / "requirements.txt"
        req.write_text("flask>=3.0,<4.0\nrequests==2.31\n# comment\nnumpy\n")
        deps = parse_requirements_txt(req)
        assert len(deps) == 3
        assert deps[0]["name"] == "flask"
        assert deps[1]["version_spec"] == "==2.31"
        assert deps[2]["name"] == "numpy"
        assert deps[2]["version_spec"] == ""

    def test_parse_package_json(self, tmp_path: Path):
        from blue_agent.audit.asset_inventory import parse_package_json

        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        }))
        deps = parse_package_json(pkg)
        assert len(deps) == 2

    def test_collect_inventory(self, tmp_path: Path):
        from blue_agent.audit.asset_inventory import collect_inventory

        (tmp_path / "app.py").write_text("print(1)")
        (tmp_path / "requirements.txt").write_text("flask>=3.0")

        inventory = collect_inventory(str(tmp_path))
        assert "source_files" in inventory
        assert "dependencies" in inventory
        assert len(inventory["dependencies"]) >= 1

    def test_collect_inventory_missing_path(self):
        from blue_agent.audit.asset_inventory import collect_inventory

        result = collect_inventory("/nonexistent/path/12345")
        assert "error" in result


# ---------------------------------------------------------------------------
# Semgrep Scanner
# ---------------------------------------------------------------------------
class TestSemgrepScanner:
    SEMGREP_SAMPLE_OUTPUT = json.dumps({
        "results": [
            {
                "check_id": "python.lang.security.audit.sqli",
                "path": "/target/app.py",
                "start": {"line": 42, "col": 1},
                "end": {"line": 42, "col": 80},
                "extra": {
                    "severity": "ERROR",
                    "message": "SQL injection risk",
                    "lines": "query = f\"SELECT * FROM users WHERE id='{uid}'\"",
                    "metadata": {
                        "cwe": ["CWE-89"],
                    },
                },
            }
        ],
        "errors": [],
    })

    @patch("blue_agent.audit.semgrep_scanner.subprocess.run")
    def test_parse_semgrep_output(self, mock_run):
        from blue_agent.audit.semgrep_scanner import run_semgrep

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=self.SEMGREP_SAMPLE_OUTPUT,
            stderr="",
        )
        findings = run_semgrep("/target")
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "semgrep"
        assert f.cwe == "CWE-89"
        assert f.severity == Severity.HIGH
        assert f.line == 42

    @patch("blue_agent.audit.semgrep_scanner.subprocess.run")
    def test_semgrep_not_installed(self, mock_run):
        from blue_agent.audit.semgrep_scanner import run_semgrep

        mock_run.side_effect = FileNotFoundError("semgrep not found")
        findings = run_semgrep("/target")
        assert findings == []


# ---------------------------------------------------------------------------
# Bandit Scanner
# ---------------------------------------------------------------------------
class TestBanditScanner:
    BANDIT_SAMPLE_OUTPUT = json.dumps({
        "results": [
            {
                "test_id": "B608",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "Possible SQL injection via string formatting",
                "filename": "/target/app.py",
                "line_number": 42,
                "code": "query = f\"SELECT ...\"",
                "issue_cwe": {"id": 89, "link": "https://cwe.mitre.org/data/definitions/89.html"},
            },
            {
                "test_id": "B105",
                "issue_severity": "LOW",
                "issue_confidence": "MEDIUM",
                "issue_text": "Possible hardcoded password",
                "filename": "/target/app.py",
                "line_number": 10,
                "code": "password = 'admin123'",
                "issue_cwe": {"id": 259, "link": ""},
            },
        ],
        "errors": [],
    })

    @patch("blue_agent.audit.bandit_scanner.subprocess.run")
    def test_parse_bandit_output(self, mock_run):
        from blue_agent.audit.bandit_scanner import run_bandit

        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=self.BANDIT_SAMPLE_OUTPUT,
            stderr="",
        )
        findings = run_bandit("/target")
        assert len(findings) == 2

        sqli = findings[0]
        assert sqli.source == "bandit"
        assert sqli.cwe == "CWE-89"
        # MEDIUM severity + HIGH confidence → promoted to HIGH
        assert sqli.severity == Severity.HIGH
        assert sqli.component == "B608"

        hardcoded = findings[1]
        assert hardcoded.cwe == "CWE-259"
        assert hardcoded.severity == Severity.LOW

    @patch("blue_agent.audit.bandit_scanner.subprocess.run")
    def test_bandit_not_installed(self, mock_run):
        from blue_agent.audit.bandit_scanner import run_bandit

        mock_run.side_effect = FileNotFoundError
        findings = run_bandit("/target")
        assert findings == []


# ---------------------------------------------------------------------------
# Dependency Scanner
# ---------------------------------------------------------------------------
class TestDependencyScanner:
    @patch("blue_agent.audit.dependency_scanner.subprocess.run")
    def test_dependency_check_not_installed(self, mock_run):
        from blue_agent.audit.dependency_scanner import run_dependency_check

        mock_run.side_effect = FileNotFoundError
        findings = run_dependency_check("/target")
        assert findings == []

    @patch("blue_agent.audit.dependency_scanner.subprocess.run")
    def test_pip_audit_not_installed(self, mock_run):
        from blue_agent.audit.dependency_scanner import pip_audit_check

        mock_run.side_effect = FileNotFoundError
        findings = pip_audit_check()
        assert findings == []

    @patch("blue_agent.audit.dependency_scanner.subprocess.run")
    def test_pip_audit_parse(self, mock_run):
        from blue_agent.audit.dependency_scanner import pip_audit_check

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "dependencies": [
                    {
                        "name": "flask",
                        "version": "2.0.0",
                        "vulns": [
                            {"id": "PYSEC-2023-001", "description": "XSS in flask"}
                        ],
                    }
                ]
            }),
            stderr="",
        )
        findings = pip_audit_check()
        assert len(findings) == 1
        assert findings[0].component == "flask"


# ---------------------------------------------------------------------------
# Audit Orchestrator
# ---------------------------------------------------------------------------
class TestAuditOrchestrator:
    @patch("blue_agent.audit.orchestrator.scan_dependencies", return_value=[])
    @patch("blue_agent.audit.orchestrator.scan_with_semgrep", return_value=[])
    @patch("blue_agent.audit.orchestrator.scan_with_bandit", return_value=[
        VulnerabilityFinding(
            source="bandit", cwe="CWE-89", severity=Severity.HIGH,
            file="app.py", line=42, description="SQL injection",
        ),
    ])
    def test_run_full_audit(self, mock_bandit, mock_semgrep, mock_deps, tmp_path):
        from blue_agent.audit.orchestrator import run_full_audit

        (tmp_path / "app.py").write_text("print(1)")
        report = run_full_audit(str(tmp_path))
        assert len(report.findings) == 1
        assert report.summary["total"] == 1
        assert report.summary["high"] == 1

    @patch("blue_agent.audit.orchestrator.scan_with_semgrep", return_value=[])
    @patch("blue_agent.audit.orchestrator.scan_with_bandit", return_value=[])
    def test_run_quick_audit(self, mock_bandit, mock_semgrep, tmp_path):
        from blue_agent.audit.orchestrator import run_quick_audit

        report = run_quick_audit(str(tmp_path))
        assert report.summary["total"] == 0
