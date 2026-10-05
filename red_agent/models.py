"""Validated models used by the autonomous campaign."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from red_agent.payloads import get_all_categories


@dataclass(frozen=True)
class AttackPlan:
    attack_type: str
    endpoint: str = "/"
    method: str = "GET"
    max_events: int = 1
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.attack_type not in get_all_categories():
            raise ValueError(f"unsupported attack type: {self.attack_type}")
        if not self.endpoint.startswith("/") or "://" in self.endpoint:
            raise ValueError("endpoint must be a local path")
        if self.method.upper() not in {"GET", "POST", "PUT", "PATCH"}:
            raise ValueError("unsupported HTTP method")
        if not 1 <= self.max_events <= 100:
            raise ValueError("max_events must be between 1 and 100")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackPlan":
        if not isinstance(data, dict):
            raise ValueError("attack plan must be an object")
        return cls(
            attack_type=str(data.get("attack_type", "")),
            endpoint=str(data.get("endpoint", "/")),
            method=str(data.get("method", "GET")),
            max_events=int(data.get("max_events", 1)),
            rationale=str(data.get("rationale", "")),
        )


@dataclass
class CampaignState:
    max_rounds: int = 5
    max_events: int = 25
    rounds: int = 0
    events: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    def can_continue(self) -> bool:
        return self.rounds < self.max_rounds and self.events < self.max_events

    def record(self, result: dict[str, Any]) -> None:
        if not self.can_continue():
            raise RuntimeError("campaign limit reached")
        self.rounds += 1
        self.events += int(result.get("events", 1))
        self.history.append(dict(result))

