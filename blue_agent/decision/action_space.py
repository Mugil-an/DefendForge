"""
Defensive Action Space — defines the discrete actions available
to the Blue Agent's PPO policy.

Actions are configurable but ship with a sensible default set.
Each action maps to a handler that the decision engine can dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Dict, List, Optional

from blue_agent.logging_cfg import get_logger

log = get_logger("decision.action_space")


class DefensiveAction(IntEnum):
    """Default defensive action enumeration."""
    NO_ACTION = 0
    BLOCK_SOURCE_IP = 1
    RATE_LIMIT_SOURCE = 2
    BLOCK_ENDPOINT = 3
    TERMINATE_SESSION = 4
    DISABLE_ENDPOINT = 5
    APPLY_KNOWN_PATCH = 6
    UPDATE_SECURITY_RULE = 7
    ESCALATE_TO_LLM = 8
    ROLLBACK_PREVIOUS = 9


# Human-readable labels
ACTION_LABELS: Dict[int, str] = {
    DefensiveAction.NO_ACTION:            "No action / continue monitoring",
    DefensiveAction.BLOCK_SOURCE_IP:      "Block source IP",
    DefensiveAction.RATE_LIMIT_SOURCE:    "Rate-limit source",
    DefensiveAction.BLOCK_ENDPOINT:       "Block endpoint temporarily",
    DefensiveAction.TERMINATE_SESSION:    "Terminate suspicious session",
    DefensiveAction.DISABLE_ENDPOINT:     "Disable vulnerable endpoint",
    DefensiveAction.APPLY_KNOWN_PATCH:    "Apply known patch template",
    DefensiveAction.UPDATE_SECURITY_RULE: "Update security rule",
    DefensiveAction.ESCALATE_TO_LLM:      "Escalate to LLM reasoning",
    DefensiveAction.ROLLBACK_PREVIOUS:    "Rollback previous change",
}


@dataclass
class ActionMetadata:
    """Metadata for a single defensive action."""
    action_id: int
    name: str
    label: str
    reversible: bool = True
    requires_validation: bool = False
    latency_class: str = "fast"     # fast | medium | slow


# Default action registry
DEFAULT_ACTIONS: List[ActionMetadata] = [
    ActionMetadata(0,  "no_action",            ACTION_LABELS[0],  reversible=False, latency_class="fast"),
    ActionMetadata(1,  "block_source_ip",      ACTION_LABELS[1],  reversible=True,  latency_class="fast"),
    ActionMetadata(2,  "rate_limit_source",     ACTION_LABELS[2],  reversible=True,  latency_class="fast"),
    ActionMetadata(3,  "block_endpoint",        ACTION_LABELS[3],  reversible=True,  latency_class="fast"),
    ActionMetadata(4,  "terminate_session",     ACTION_LABELS[4],  reversible=False, latency_class="fast"),
    ActionMetadata(5,  "disable_endpoint",      ACTION_LABELS[5],  reversible=True,  latency_class="medium"),
    ActionMetadata(6,  "apply_known_patch",     ACTION_LABELS[6],  reversible=True,  requires_validation=True, latency_class="medium"),
    ActionMetadata(7,  "update_security_rule",  ACTION_LABELS[7],  reversible=True,  latency_class="fast"),
    ActionMetadata(8,  "escalate_to_llm",       ACTION_LABELS[8],  reversible=False, latency_class="slow"),
    ActionMetadata(9,  "rollback_previous",     ACTION_LABELS[9],  reversible=False, latency_class="fast"),
]


class ActionSpace:
    """
    Manages the set of available defensive actions.

    Provides lookup by ID or name, and the total action count
    needed by the PPO policy's output head.
    """

    def __init__(self, actions: Optional[List[ActionMetadata]] = None):
        self._actions = {a.action_id: a for a in (actions or DEFAULT_ACTIONS)}

    @property
    def n_actions(self) -> int:
        return len(self._actions)

    def get(self, action_id: int) -> ActionMetadata:
        if action_id not in self._actions:
            raise ValueError(f"Unknown action ID {action_id}. Valid: {list(self._actions.keys())}")
        return self._actions[action_id]

    def get_by_name(self, name: str) -> ActionMetadata:
        for a in self._actions.values():
            if a.name == name:
                return a
        raise ValueError(f"Unknown action name '{name}'")

    def all_actions(self) -> List[ActionMetadata]:
        return sorted(self._actions.values(), key=lambda a: a.action_id)

    def action_names(self) -> List[str]:
        return [a.name for a in self.all_actions()]

    def is_escalation(self, action_id: int) -> bool:
        return action_id == DefensiveAction.ESCALATE_TO_LLM

    def requires_validation(self, action_id: int) -> bool:
        return self._actions[action_id].requires_validation

    def __len__(self) -> int:
        return self.n_actions

    def __repr__(self) -> str:
        return f"ActionSpace(n={self.n_actions}, actions={self.action_names()})"
