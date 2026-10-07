"""
Red Agent — Adaptive Memory System.

Stores attack results across rounds so the Red Agent can:
- Avoid techniques that were already detected
- Double down on successful attack vectors
- Track which endpoints have been patched
- Remember reconnaissance findings
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from blue_agent.logging_cfg import get_logger

log = get_logger("red.memory")


@dataclass
class AttackRecord:
    """Record of a single attack attempt."""
    round_number: int
    attack_type: str
    endpoint: str
    method: str
    payload_summary: str
    response_code: int
    detected: bool
    success: bool  # Did the exploit work (e.g., SQLi bypass succeeded)?
    blocked: bool  # Was it blocked by the Blue Agent?
    timestamp: float = field(default_factory=time.time)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "round": self.round_number,
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "method": self.method,
            "payload_summary": self.payload_summary,
            "response_code": self.response_code,
            "detected": self.detected,
            "success": self.success,
            "blocked": self.blocked,
            "timestamp": self.timestamp,
            "notes": self.notes,
        }


@dataclass
class RoundSummary:
    """Summary of a complete attack round."""
    round_number: int
    total_attacks: int = 0
    successful_attacks: int = 0
    detected_attacks: int = 0
    blocked_attacks: int = 0
    attack_types_used: list[str] = field(default_factory=list)
    patched_endpoints: list[str] = field(default_factory=list)
    unpatched_vulnerabilities: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class RedMemory:
    """
    Persistent in-memory store for Red Agent attack history.

    Provides adaptive strategy based on past results:
    - Tracks detection rates per attack type
    - Identifies patched vs unpatched endpoints
    - Suggests next attack based on past success/failure
    """

    def __init__(self, persist_path: str | Path | None = None):
        self._records: list[AttackRecord] = []
        self._round_summaries: list[RoundSummary] = []
        self._current_round: int = 0
        self._patched_endpoints: set[str] = set()
        self._detected_techniques: dict[str, int] = {}  # attack_type -> detect count
        self._successful_techniques: dict[str, int] = {}  # attack_type -> success count
        self._persist_path = Path(persist_path) if persist_path else None

        if self._persist_path and self._persist_path.exists():
            self._load()

    @property
    def current_round(self) -> int:
        return self._current_round

    def start_new_round(self) -> int:
        """Start a new attack round."""
        self._current_round += 1
        log.info("red_memory_new_round", round=self._current_round)
        return self._current_round

    def record_attack(self, record: AttackRecord) -> None:
        """Store an attack result."""
        self._records.append(record)

        # Track detection and success rates
        at = record.attack_type
        if record.detected:
            self._detected_techniques[at] = self._detected_techniques.get(at, 0) + 1
        if record.success:
            self._successful_techniques[at] = self._successful_techniques.get(at, 0) + 1
        if record.blocked:
            self._patched_endpoints.add(f"{record.endpoint}:{record.attack_type}")

        log.info("red_memory_attack_recorded",
                 attack_type=at,
                 endpoint=record.endpoint,
                 detected=record.detected,
                 success=record.success)

    def record_round_summary(self, summary: RoundSummary) -> None:
        """Store a round summary."""
        self._round_summaries.append(summary)
        self._persist()

    def get_detection_rate(self, attack_type: str) -> float:
        """Get the fraction of times this attack type was detected."""
        total = sum(1 for r in self._records if r.attack_type == attack_type)
        if total == 0:
            return 0.0
        detected = sum(1 for r in self._records if r.attack_type == attack_type and r.detected)
        return detected / total

    def get_success_rate(self, attack_type: str) -> float:
        """Get the fraction of times this attack type succeeded."""
        total = sum(1 for r in self._records if r.attack_type == attack_type)
        if total == 0:
            return 0.0
        success = sum(1 for r in self._records if r.attack_type == attack_type and r.success)
        return success / total

    def is_endpoint_patched(self, endpoint: str, attack_type: str) -> bool:
        """Check if an endpoint was recently patched for a given attack type."""
        key = f"{endpoint}:{attack_type}"
        return key in self._patched_endpoints

    def get_best_attack_types(self, top_k: int = 3) -> list[str]:
        """Return attack types sorted by success rate (prefer undetected)."""
        from red_agent.payloads import get_all_categories
        categories = get_all_categories()

        scored = []
        for cat in categories:
            success_rate = self.get_success_rate(cat)
            detection_rate = self.get_detection_rate(cat)
            # Score = high success, low detection
            # Untried attacks get a neutral score to encourage exploration
            total_attempts = sum(1 for r in self._records if r.attack_type == cat)
            if total_attempts == 0:
                score = 0.5  # Encourage exploration of untried attacks
            else:
                score = success_rate * (1.0 - detection_rate * 0.5)
            scored.append((cat, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [cat for cat, _ in scored[:top_k]]

    def get_unpatched_vulnerabilities(self) -> list[dict[str, str]]:
        """Return attack surfaces that haven't been patched yet."""
        unpatched = []
        # Group by endpoint+attack_type, check if ever blocked
        from collections import defaultdict
        groups: dict[str, list[AttackRecord]] = defaultdict(list)
        for r in self._records:
            groups[f"{r.endpoint}:{r.attack_type}"].append(r)

        for key, records in groups.items():
            endpoint, attack_type = key.rsplit(":", 1)
            latest = max(records, key=lambda r: r.timestamp)
            if latest.success and not latest.blocked:
                unpatched.append({
                    "endpoint": endpoint,
                    "attack_type": attack_type,
                    "last_success_round": latest.round_number,
                })
        return unpatched

    def get_strategy_context(self) -> str:
        """Build a context string for LLM-based attack planning."""
        lines = [f"=== Red Agent Memory (Round {self._current_round}) ==="]
        lines.append(f"Total attacks recorded: {len(self._records)}")
        lines.append("")

        # Detection rates
        lines.append("Detection rates by attack type:")
        from red_agent.payloads import get_all_categories
        for cat in get_all_categories():
            total = sum(1 for r in self._records if r.attack_type == cat)
            if total > 0:
                dr = self.get_detection_rate(cat)
                sr = self.get_success_rate(cat)
                lines.append(f"  {cat}: detected={dr:.0%}, success={sr:.0%} ({total} attempts)")
            else:
                lines.append(f"  {cat}: untried")

        # Patched endpoints
        lines.append("")
        lines.append(f"Patched endpoints: {', '.join(self._patched_endpoints) or 'none'}")

        # Best strategies
        best = self.get_best_attack_types(3)
        lines.append(f"Recommended attack types: {', '.join(best)}")

        return "\n".join(lines)

    def get_history_for_llm(self, last_n: int = 10) -> list[dict[str, Any]]:
        """Get recent attack history formatted for LLM context."""
        recent = self._records[-last_n:]
        return [r.to_dict() for r in recent]

    def _persist(self) -> None:
        """Save memory to disk."""
        if not self._persist_path:
            return
        try:
            data = {
                "current_round": self._current_round,
                "records": [r.to_dict() for r in self._records],
                "patched_endpoints": list(self._patched_endpoints),
                "detected_techniques": self._detected_techniques,
                "successful_techniques": self._successful_techniques,
            }
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            self._persist_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            log.error("red_memory_persist_failed", error=str(e))

    def _load(self) -> None:
        """Load memory from disk."""
        try:
            data = json.loads(self._persist_path.read_text(encoding="utf-8"))
            self._current_round = data.get("current_round", 0)
            self._patched_endpoints = set(data.get("patched_endpoints", []))
            self._detected_techniques = data.get("detected_techniques", {})
            self._successful_techniques = data.get("successful_techniques", {})
            for rec in data.get("records", []):
                self._records.append(AttackRecord(**rec))
            log.info("red_memory_loaded", records=len(self._records), round=self._current_round)
        except Exception as e:
            log.warning("red_memory_load_failed", error=str(e))

    def reset(self) -> None:
        """Clear all memory."""
        self._records.clear()
        self._round_summaries.clear()
        self._current_round = 0
        self._patched_endpoints.clear()
        self._detected_techniques.clear()
        self._successful_techniques.clear()
