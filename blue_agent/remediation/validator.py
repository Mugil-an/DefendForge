"""
Patch Validator — Applies a patch, runs tests, and rolls back if validation fails.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from blue_agent.config import PROJECT_ROOT
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import Patch, ValidationDecision, ValidationResult
from target_platform.registry import RegisteredTarget, TargetRegistry

log = get_logger("remediation.validator")


class PatchValidator:
    """
    Applies generated patches to the target application and validates them
    using the application's test suite. Automatically rolls back on failure.
    """
    
    def __init__(
        self,
        target_dir: Optional[str] = None,
        target: Optional[RegisteredTarget] = None,
    ):
        self._target_dir = Path(target_dir or (PROJECT_ROOT / "target_app"))
        self._target = target
        
    def validate_and_apply(self, patch: Patch) -> ValidationResult:
        """
        Apply the patch, run validation, and rollback if it fails.
        """
        log.info("validation_started", patch_id=patch.patch_id, strategy=patch.strategy)
        t0 = time.perf_counter()
        
        # 1. Apply the patch
        apply_success, apply_error = self._apply_patch(patch.diff)
        
        if not apply_success:
            log.error("patch_apply_failed", patch_id=patch.patch_id, error=apply_error)
            return ValidationResult(
                patch_id=patch.patch_id,
                tests_passed=False,
                decision=ValidationDecision.ROLLBACK,
                failure_reason=f"Failed to apply patch: {apply_error}",
                validation_time_ms=(time.perf_counter() - t0) * 1000
            )
            
        # 2. Run the test suite
        test_success, test_output = self._run_tests()
        
        validation_time = (time.perf_counter() - t0) * 1000
        
        if test_success:
            log.info("validation_passed", patch_id=patch.patch_id, time_ms=validation_time)
            return ValidationResult(
                patch_id=patch.patch_id,
                tests_passed=True,
                security_checks_passed=True,
                decision=ValidationDecision.ACCEPT,
                validation_time_ms=validation_time
            )
        else:
            log.warning("validation_failed_rolling_back", patch_id=patch.patch_id)
            self._rollback_patch(patch.diff)
            
            return ValidationResult(
                patch_id=patch.patch_id,
                tests_passed=False,
                regression_detected=True,
                decision=ValidationDecision.ROLLBACK,
                failure_reason=test_output[-2000:] or "Target validation failed.",
                failed_tests=["target_validation"],
                validation_time_ms=validation_time
            )

    def _apply_patch(self, diff_content: str) -> tuple[bool, str]:
        """Apply a unified diff patch."""
        try:
            # We use git apply if available, otherwise patch
            process = subprocess.run(
                ["git", "apply", "--ignore-space-change", "--ignore-whitespace"],
                input=diff_content.encode("utf-8"),
                cwd=str(PROJECT_ROOT),
                capture_output=True
            )
            
            if process.returncode != 0:
                # Try standard patch command
                process2 = subprocess.run(
                    ["patch", "-p0"],
                    input=diff_content.encode("utf-8"),
                    cwd=str(PROJECT_ROOT),
                    capture_output=True
                )
                if process2.returncode != 0:
                    return False, process2.stderr.decode("utf-8")
            
            return True, ""
        except Exception as e:
            return False, str(e)
            
    def _rollback_patch(self, diff_content: str) -> tuple[bool, str]:
        """Reverse a unified diff patch."""
        try:
            process = subprocess.run(
                ["git", "apply", "--reverse", "--ignore-space-change", "--ignore-whitespace"],
                input=diff_content.encode("utf-8"),
                cwd=str(PROJECT_ROOT),
                capture_output=True
            )
            
            if process.returncode != 0:
                process2 = subprocess.run(
                    ["patch", "-p0", "-R"],
                    input=diff_content.encode("utf-8"),
                    cwd=str(PROJECT_ROOT),
                    capture_output=True
                )
                if process2.returncode != 0:
                    return False, process2.stderr.decode("utf-8")
                    
            return True, ""
        except Exception as e:
            return False, str(e)
            
    def _run_tests(self) -> tuple[bool, str]:
        """Run the manifest command directly inside the target workspace.

        Commands are argv arrays and never go through a shell.  The working
        directory is constrained to the target workspace so a target manifest
        cannot make validation execute from an arbitrary host directory.
        """
        target = self._target
        timeout = 300
        try:
            if target is None:
                # Preserve the original local-target behavior when callers do
                # not opt into a manifest yet.
                target = TargetRegistry().load()

            command = target.validation_command
            timeout = target.validation_timeout
            if not command:
                test_dir = self._target_dir / "tests"
                if not test_dir.exists():
                    log.info("no_target_app_tests_found", dir=str(test_dir))
                    return True, "No tests found."
                command = ("pytest", "tests")

            root = self._target_dir.resolve()
            configured_dir = Path(target.validation_working_dir)
            working_dir = (
                configured_dir if configured_dir.is_absolute() else root / configured_dir
            ).resolve()
            if working_dir != root and root not in working_dir.parents:
                return False, "Validation working_dir must remain inside the target workspace."
            if not working_dir.is_dir():
                return False, f"Validation working_dir does not exist: {working_dir}"

            process = subprocess.run(
                list(command),
                cwd=str(working_dir),
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
            )

            return process.returncode == 0, process.stdout + "\n" + process.stderr
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            output = stdout + "\n" + stderr
            return False, f"Validation timed out after {timeout} seconds.\n{output}"
        except Exception as e:
            return False, str(e)
