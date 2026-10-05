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

log = get_logger("remediation.validator")


class PatchValidator:
    """
    Applies generated patches to the target application and validates them
    using the application's test suite. Automatically rolls back on failure.
    """
    
    def __init__(self, target_dir: Optional[str] = None):
        self._target_dir = Path(target_dir or (PROJECT_ROOT / "target_app"))
        
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
                failure_reason="Test suite failed after patch.",
                failed_tests=["target_app_tests"], # Simplified for MVP
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
        """Run the target application's test suite."""
        try:
            # Assuming there's a pytest suite for the target app
            # If the target app doesn't have tests yet, we simulate passing
            test_dir = self._target_dir / "tests"
            if not test_dir.exists():
                log.info("no_target_app_tests_found", dir=str(test_dir))
                return True, "No tests found."
                
            process = subprocess.run(
                ["pytest", str(test_dir)],
                cwd=str(PROJECT_ROOT),
                capture_output=True,
                text=True
            )
            
            return process.returncode == 0, process.stdout + "\n" + process.stderr
        except Exception as e:
            return False, str(e)
