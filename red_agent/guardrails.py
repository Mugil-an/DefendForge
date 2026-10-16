"""Hard safety boundaries for local red-agent simulation."""
from __future__ import annotations

from urllib.parse import urlparse


class SafetyViolation(ValueError):
    pass


class TargetGuard:
    _custom_targets: set[str] = set()

    @classmethod
    def allow_target(cls, target_or_host: str) -> None:
        """Allow a user-specified container host or URL."""
        parsed = urlparse(target_or_host if "://" in target_or_host else f"http://{target_or_host}")
        host = parsed.hostname or parsed.path.split(":")[0]
        if host:
            cls._custom_targets.add(host)

    def __init__(self, allowed_targets: set[str] | None = None):
        base = {
            "target_app", "target-app", "target_gateway", "target-gateway",
            "localhost", "127.0.0.1", "::1", "host.docker.internal",
        }
        if allowed_targets:
            base.update(allowed_targets)
        base.update(self._custom_targets)
        try:
            from red_agent.config import red_settings
            if red_settings.target_url:
                p = urlparse(red_settings.target_url)
                if p.hostname:
                    base.add(p.hostname)
        except Exception:
            pass
        self.allowed_targets = frozenset(base)

    def validate(self, target: str) -> str:
        parsed = urlparse(target if "://" in target else f"sim://{target}")
        host = parsed.hostname or parsed.path.split(":")[0]
        if host not in self.allowed_targets and host not in self._custom_targets:
            raise SafetyViolation(f"target '{host}' is not in the allowlist")
        if parsed.scheme not in {"sim", "http", "https"}:
            raise SafetyViolation("unsupported target scheme")
        return target

    def validate_plan(self, plan: object) -> None:
        endpoint = getattr(plan, "endpoint", "")
        if not endpoint.startswith("/") or "://" in endpoint:
            raise SafetyViolation("attack plans may only use local path endpoints")
