"""Safe, manifest-driven source audit execution for Red reconnaissance."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from target_platform.registry import AuditProfile

ALLOWED_TOOLS = frozenset({"pip-audit", "npm-audit", "semgrep"})


def run_audits(
    source_path: str | Path,
    profile: AuditProfile,
) -> dict[str, Any]:
    """Run only tools explicitly enabled by the target manifest.

    The runner accepts a source directory, never an arbitrary shell command,
    and returns structured output for Blue to correlate with the campaign.
    """
    root = Path(source_path).resolve()
    if not root.is_dir():
        raise ValueError(f"audit source directory does not exist: {root}")
    unknown_tools = set(profile.tools) - ALLOWED_TOOLS
    if unknown_tools:
        raise ValueError(f"unsupported audit tools: {sorted(unknown_tools)}")

    results: dict[str, Any] = {}
    for tool in profile.tools:
        if tool == "pip-audit":
            requirements = next(iter(sorted(root.rglob("requirements*.txt"))), None)
            command = ["pip-audit", "--format", "json"]
            if requirements:
                command.extend(["--requirement", str(requirements)])
        elif tool == "npm-audit":
            package_lock = root / "package-lock.json"
            if not package_lock.is_file():
                results[tool] = {"status": "skipped", "reason": "package-lock.json not found"}
                continue
            command = ["npm", "audit", "--json"]
        else:
            command = ["semgrep", "--config", "p/owasp-top-ten", "--json", "--quiet", str(root)]

        try:
            completed = subprocess.run(
                command,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=profile.timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            results[tool] = {"status": "unavailable"}
            continue
        except subprocess.TimeoutExpired:
            results[tool] = {"status": "timeout"}
            continue

        try:
            output: Any = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            output = {"raw": completed.stdout[-10000:]}
        results[tool] = {
            "status": "completed" if completed.returncode in (0, 1) else "failed",
            "returncode": completed.returncode,
            "result": output,
            "stderr": completed.stderr[-2000:],
        }
    return {"source_path": str(root), "tools": results}
