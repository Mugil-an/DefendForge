from __future__ import annotations

from typing import Any

from blue_agent.logging_cfg import get_logger

log = get_logger("blue.events")


def classify_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize gateway provenance without treating unknown traffic as benign."""
    source = event.get("source_kind")
    if source not in {"red", "user"}:
        source = "unknown"
    normalized = dict(event)
    normalized["source_kind"] = source
    normalized["is_attack"] = source == "red"
    normalized["attack_type"] = normalized.get("attack_type") or ("red_campaign" if source == "red" else None)
    return normalized
