from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

@dataclass
class RedAgentConfig:
    target_url: str = field(
        default_factory=lambda: os.getenv("RED_TARGET_URL", "http://target-app:5000")
    )
    attack_intensity: str = field(
        default_factory=lambda: os.getenv("RED_ATTACK_INTENSITY", "medium")
    )
    benign_ratio: float = field(
        default_factory=lambda: float(os.getenv("RED_BENIGN_RATIO", "0.3"))
    )
    scenario_duration: int = field(
        default_factory=lambda: int(os.getenv("RED_SCENARIO_DURATION", "60"))
    )
    enabled_attacks: List[str] = field(
        default_factory=lambda: os.getenv(
            "RED_ENABLED_ATTACKS",
            "sql_injection,xss,path_traversal,command_injection,ssrf,reconnaissance,brute_force"
        ).split(",")
    )
    simulation_only: bool = field(
        default_factory=lambda: os.getenv("RED_SIMULATION_ONLY", "false").lower() == "true"
    )
    request_timeout: float = field(
        default_factory=lambda: float(os.getenv("RED_REQUEST_TIMEOUT", "5"))
    )
    max_campaign_rounds: int = field(
        default_factory=lambda: int(os.getenv("RED_MAX_CAMPAIGN_ROUNDS", "5"))
    )
    max_campaign_events: int = field(
        default_factory=lambda: int(os.getenv("RED_MAX_CAMPAIGN_EVENTS", "25"))
    )

# Singleton configuration instance
red_settings = RedAgentConfig()
