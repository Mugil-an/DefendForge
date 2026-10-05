"""Bounded live HTTP campaign against the bundled local target."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from red_agent.campaign import AdaptiveEvaluator
from red_agent.guardrails import TargetGuard
from red_agent.knowledge import AttackKnowledge
from red_agent.models import AttackPlan, CampaignState
from red_agent.payloads import get_payloads


@dataclass(frozen=True)
class LiveAttackResult:
    event: dict[str, Any]
    truth: dict[str, Any]


class LiveCampaign:
    """Send real requests, but only to an explicitly local allowlisted target."""

    def __init__(
        self,
        target_url: str,
        *,
        knowledge: AttackKnowledge | None = None,
        max_rounds: int = 5,
        max_events: int = 25,
        timeout: float = 5.0,
        evaluator: AdaptiveEvaluator | None = None,
    ) -> None:
        parsed = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
            "target_app",
            "target-app",
        }:
            raise ValueError("live campaigns are restricted to the bundled local target")
        self.target_url = target_url.rstrip("/") + "/"
        self.guard = TargetGuard()
        self.guard.validate(target_url)
        self.knowledge = knowledge or AttackKnowledge()
        self.state = CampaignState(
            max_rounds=max(0, min(max_rounds, 100)),
            max_events=max(1, min(max_events, 500)),
        )
        self.timeout = timeout
        self.evaluator = evaluator or AdaptiveEvaluator()

    def _request(self, plan: AttackPlan, payload: str, param_name: str) -> httpx.Response:
        url = urljoin(self.target_url, plan.endpoint.lstrip("/"))
        if plan.method.upper() == "POST":
            return httpx.post(url, data={param_name: payload}, timeout=self.timeout)
        return httpx.get(url, params={param_name: payload}, timeout=self.timeout)

    def run(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        traffic: list[dict[str, Any]] = []
        truth: list[dict[str, Any]] = []
        with httpx.Client(base_url=self.target_url, timeout=self.timeout) as client:
            while self.state.can_continue():
                plan = self.evaluator.choose(self.state.history, self.knowledge)
                self.guard.validate_plan(plan)
                payloads = get_payloads(plan.attack_type)
                if not payloads:
                    break
                payload = payloads[self.state.events % len(payloads)]
                params = {payload.param_name: payload.payload} if payload.param_name else {}
                try:
                    if plan.method.upper() == "POST":
                        response = client.post(plan.endpoint, data=params)
                    else:
                        response = client.get(plan.endpoint, params=params)
                    response_code = response.status_code
                    response_size = len(response.content)
                except httpx.HTTPError as exc:
                    response_code = 599
                    response_size = 0
                    error = str(exc)
                else:
                    error = ""

                event = {
                    "source": "127.0.0.1",
                    "endpoint": plan.endpoint,
                    "method": plan.method.upper(),
                    "params": params,
                    "response_code": response_code,
                    "response_time_ms": 0,
                    "body_size": response_size,
                    "user_agent": "DefendForge-RedAgent/1.0",
                    "destination": urlparse(self.target_url).hostname,
                }
                if error:
                    event["error"] = error
                item = {
                    "index": len(truth),
                    "is_attack": True,
                    "attack_type": plan.attack_type,
                    "severity": payload.severity,
                    "rationale": plan.rationale,
                    "response_code": response_code,
                }
                traffic.append(event)
                truth.append(item)
                self.evaluator.record(self.state, plan, detected=True, events=1)
        return traffic, truth
