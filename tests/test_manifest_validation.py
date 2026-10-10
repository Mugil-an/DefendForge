from unittest.mock import patch

from blue_agent.remediation.validator import PatchValidator
from target_platform.registry import RegisteredTarget, ValidationProfile


def test_manifest_validation_uses_workspace_and_argv(tmp_path):
    (tmp_path / "checks").mkdir()
    target = RegisteredTarget(
        "demo",
        "http://127.0.0.1:8000",
        validation=ValidationProfile(("pytest", "checks"), "checks", 9),
    )

    with patch("blue_agent.remediation.validator.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "ok"
        run.return_value.stderr = ""
        passed, output = PatchValidator(str(tmp_path), target)._run_tests()

    assert passed is True
    assert output == "ok\n"
    kwargs = run.call_args.kwargs
    assert kwargs["cwd"] == str((tmp_path / "checks").resolve())
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 9
    assert run.call_args.args[0] == ["pytest", "checks"]


def test_manifest_validation_rejects_workspace_escape(tmp_path):
    target = RegisteredTarget(
        "demo",
        "http://127.0.0.1:8000",
        validation=ValidationProfile(("pytest",), "..", 9),
    )

    passed, output = PatchValidator(str(tmp_path), target)._run_tests()

    assert passed is False
    assert "inside the target workspace" in output


def test_manifest_validation_timeout_fails(tmp_path):
    target = RegisteredTarget(
        "demo",
        "http://127.0.0.1:8000",
        validation=ValidationProfile(("pytest",), ".", 2),
    )

    with patch(
        "blue_agent.remediation.validator.subprocess.run",
        side_effect=__import__("subprocess").TimeoutExpired(["pytest"], 2),
    ):
        passed, output = PatchValidator(str(tmp_path), target)._run_tests()

    assert passed is False
    assert "timed out after 2 seconds" in output
