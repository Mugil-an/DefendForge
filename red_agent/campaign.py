"""Bounded autonomous campaign loop; simulation is the only default executor."""
from __future__ import annotations

from typing import Callable

from red_agent.guardrails import TargetGuard
from red_agent.knowledge import AttackKnowledge
from red_agent.models import AttackPlan, CampaignState
from red_agent.payloads import get_all_categories


class AdaptiveEvaluator:
    def choose(self, history: list[dict], knowledge: AttackKnowledge) -> AttackPlan:
        if history:
            last = history[-1]
            if last.get("detected") is False:
                attack_type = last.get("attack_type", "reconnaissance")
            else:
                attack_type = "reconnaissance" if last.get("attack_type") != "reconnaissance" else "sql_injection"
        else:
            attack_type = "reconnaissance"
        if attack_type not in get_all_categories():
            attack_type = "reconnaissance"
        entry = knowledge.get(attack_type)
        return AttackPlan(attack_type=attack_type, rationale=entry.description if entry else "")

    def record(self, state: CampaignState, plan: AttackPlan, *, detected: bool, events: int = 1) -> None:
        state.record({"attack_type": plan.attack_type, "detected": detected, "events": events})


class SimulatedCampaign:
    def __init__(self, generator, *, target: str = "target-app", knowledge: AttackKnowledge | None = None,
                 max_rounds: int = 5, max_events: int = 25, evaluator: AdaptiveEvaluator | None = None):
        self.generator = generator
        self.guard = TargetGuard()
        self.guard.validate(target)
        self.knowledge = knowledge or AttackKnowledge()
        self.state = CampaignState(max_rounds=max_rounds, max_events=max_events)
        self.evaluator = evaluator or AdaptiveEvaluator()

    def run(self, *, detected: Callable[[dict], bool] | None = None) -> tuple[list[dict], list[dict]]:
        traffic, truth = [], []
        while self.state.can_continue():
            plan = self.evaluator.choose(self.state.history, self.knowledge)
            self.guard.validate_plan(plan)
            count = min(plan.max_events, self.state.max_events - self.state.events)
            events = self.generator.generate_attack(plan.attack_type, count)
            if not events:
                break
            for event in events:
                meta = event.pop("_attack_meta", {})
                traffic.append(event)
                truth.append({"index": len(truth), "is_attack": True,
                              "attack_type": meta.get("attack_type", plan.attack_type),
                              "severity": meta.get("severity", "low"),
                              "rationale": plan.rationale})
            is_detected = detected(truth[-1]) if detected else True
            self.evaluator.record(self.state, plan, detected=is_detected, events=len(events))
        return traffic, truth

