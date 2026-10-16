"""
Green Agent — Legitimate User Activity Simulation.

Generates realistic background user traffic against the target application to
force detection and defense layers to separate real attacks from legitimate noise,
and monitors for False Positive service disruptions.
"""
from __future__ import annotations

from green_agent.config import green_settings
from green_agent.traffic_generator import GreenTrafficGenerator
from green_agent.user_personas import (
    AnonymousVisitor,
    AuthenticatedUser,
    SearchingCustomer,
    UserPersona,
    create_random_persona,
)

__all__ = [
    "GreenTrafficGenerator",
    "green_settings",
    "UserPersona",
    "AnonymousVisitor",
    "SearchingCustomer",
    "AuthenticatedUser",
    "create_random_persona",
]
