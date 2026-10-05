"""Hard safety boundaries for local red-agent simulation."""
from __future__ import annotations

from urllib.parse import urlparse


class SafetyViolation(ValueError):
    pass


class TargetGuard:
    def __init__(self, allowed_targets: set[str] | None = None):
        self.allowed_targets = frozenset(allowed_targets or {"target-app", "localhost", "127.0.0.1"})

    def validate(self, target: str) -> str:
        parsed = urlparse(target if "://" in target else f"sim://{target}")
        host = parsed.hostname or parsed.path
        if host not in self.allowed_targets:
            raise SafetyViolation("target is not in the local allowlist")
        if parsed.scheme not in {"sim", "http", "https"}:
            raise SafetyViolation("unsupported target scheme")
        if parsed.scheme in {"http", "https"} and host not in {
            "localhost", "127.0.0.1", "::1", "target_app", "target-app"
        }:
            raise SafetyViolation("network targets are restricted to loopback")
        return target

    def validate_plan(self, plan: object) -> None:
        endpoint = getattr(plan, "endpoint", "")
        if not endpoint.startswith("/") or "://" in endpoint:
            raise SafetyViolation("attack plans may only use local path endpoints")
