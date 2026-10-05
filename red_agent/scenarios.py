from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict
from abc import ABC, abstractmethod

from red_agent.traffic_generator import TrafficGenerator

@dataclass
class ScenarioResult:
    name: str
    traffic: List[Dict]
    ground_truth: List[Dict]  # {"index": i, "is_attack": bool, "attack_type": str, "severity": str}
    description: str

class AttackScenario(ABC):
    def __init__(self, generator: TrafficGenerator):
        self.generator = generator

    @abstractmethod
    def generate(self) -> ScenarioResult:
        ...

    def _format_result(self, name: str, events: List[Dict], description: str) -> ScenarioResult:
        traffic = []
        ground_truth = []
        for i, evt in enumerate(events):
            is_attack = "_attack_meta" in evt
            meta = evt.pop("_attack_meta", {})
            traffic.append(evt)
            ground_truth.append({
                "index": i,
                "is_attack": is_attack,
                "attack_type": meta.get("attack_type"),
                "severity": meta.get("severity")
            })
        return ScenarioResult(name, traffic, ground_truth, description)

class ReconThenExploit(AttackScenario):
    """5 benign -> 3 scanner recon -> 2 targeted SQLi"""
    def generate(self) -> ScenarioResult:
        events = []
        events.extend(self.generator.generate_benign(5))
        events.extend(self.generator.generate_attack("reconnaissance", 3))
        events.extend(self.generator.generate_attack("sql_injection", 2))
        return self._format_result("ReconThenExploit", events, "Recon followed by SQLi")

class BruteForceLogin(AttackScenario):
    """2 benign -> 8 rapid login attempts with different passwords"""
    def generate(self) -> ScenarioResult:
        events = []
        events.extend(self.generator.generate_benign(2))
        events.extend(self.generator.generate_attack("brute_force", 8))
        return self._format_result("BruteForceLogin", events, "Rapid brute-force login attempts")

class MultiVectorAttack(AttackScenario):
    """Simultaneous SQLi + XSS + path traversal from different IPs"""
    def generate(self) -> ScenarioResult:
        events = []
        attacks = (
            self.generator.generate_attack("sql_injection", 3) +
            self.generator.generate_attack("xss", 4) +
            self.generator.generate_attack("path_traversal", 3)
        )
        self.generator.rng.shuffle(attacks)
        events.extend(attacks)
        return self._format_result("MultiVectorAttack", events, "Simultaneous attacks of various types")

class SlowAndLow(AttackScenario):
    """20 events total, attacks spread every 3-4 events mixed with benign"""
    def generate(self) -> ScenarioResult:
        events = []
        for i in range(20):
            if i > 0 and i % 4 == 0:
                events.extend(self.generator.generate_attack("sql_injection", 1))
            else:
                events.extend(self.generator.generate_benign(1))
        return self._format_result("SlowAndLow", events, "Slow and low attack pattern mixed with benign traffic")

class EscalationChain(AttackScenario):
    """recon (3) -> SQLi (2) -> path traversal (2) -> command injection (2) -> 1 benign"""
    def generate(self) -> ScenarioResult:
        events = []
        events.extend(self.generator.generate_attack("reconnaissance", 3))
        events.extend(self.generator.generate_attack("sql_injection", 2))
        events.extend(self.generator.generate_attack("path_traversal", 2))
        events.extend(self.generator.generate_attack("command_injection", 2))
        events.extend(self.generator.generate_benign(1))
        return self._format_result("EscalationChain", events, "Sequential escalation chain of attacks")

class FullSpectrum(AttackScenario):
    """At least 2 of every attack type mixed with benign traffic"""
    def generate(self) -> ScenarioResult:
        events = []
        categories = [
            "sql_injection", "xss", "path_traversal", 
            "command_injection", "ssrf", "reconnaissance", "brute_force"
        ]
        for cat in categories:
            events.extend(self.generator.generate_attack(cat, 2))
            
        events.extend(self.generator.generate_benign(16))
        self.generator.rng.shuffle(events)
        
        return self._format_result("FullSpectrum", events, "All attack types interleaved with benign traffic")

_SCENARIOS = {
    "ReconThenExploit": ReconThenExploit,
    "BruteForceLogin": BruteForceLogin,
    "MultiVectorAttack": MultiVectorAttack,
    "SlowAndLow": SlowAndLow,
    "EscalationChain": EscalationChain,
    "FullSpectrum": FullSpectrum,
}

def get_scenario(name: str, generator: TrafficGenerator) -> AttackScenario:
    """Get an instantiated scenario by name."""
    cls = _SCENARIOS.get(name)
    if not cls:
        raise ValueError(f"Unknown scenario: {name}")
    return cls(generator)

def list_scenarios() -> List[str]:
    """List all available scenario names."""
    return list(_SCENARIOS.keys())
