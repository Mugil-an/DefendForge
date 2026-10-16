"""Configuration for the Green Agent (Legitimate User Simulator)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List


def _env(key: str, default: str) -> str:
    return os.getenv(key, default)


def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes")


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default


@dataclass
class GreenAgentSettings:
    """Settings controlling legitimate background user simulation."""
    target_url: str = _env("GREEN_TARGET_URL", "http://127.0.0.1:8080")
    enabled: bool = _env_bool("GREEN_AGENT_ENABLED", True)
    request_interval_seconds: float = _env_float("GREEN_AGENT_INTERVAL", 1.0)
    concurrency: int = _env_int("GREEN_AGENT_CONCURRENCY", 3)
    timeout_seconds: float = _env_float("GREEN_AGENT_TIMEOUT", 4.0)
    allowed_hosts: List[str] = field(default_factory=lambda: [
        "127.0.0.1", "localhost", "target_app", "target_gateway", "target-app"
    ])


green_settings = GreenAgentSettings()
