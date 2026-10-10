import json

import pytest

from red_agent.audit_runner import run_audits
from target_platform.registry import AuditProfile


def test_audit_runner_uses_manifest_tools_and_structured_output(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0", encoding="utf-8")
    calls = []

    class Completed:
        returncode = 1
        stdout = json.dumps({"dependencies": []})
        stderr = ""

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Completed()

    monkeypatch.setattr("red_agent.audit_runner.subprocess.run", fake_run)

    report = run_audits(
        tmp_path,
        AuditProfile(tools=("pip-audit",), timeout_seconds=10),
    )

    assert report["tools"]["pip-audit"]["status"] == "completed"
    assert calls[0][0][:3] == ["pip-audit", "--format", "json"]
    assert calls[0][1]["cwd"] == tmp_path.resolve()


def test_audit_runner_rejects_unapproved_tool(tmp_path):
    with pytest.raises(ValueError, match="unsupported audit tools"):
        run_audits(tmp_path, AuditProfile(tools=("shell",)))
