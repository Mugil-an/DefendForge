from __future__ import annotations

from typing import List, Dict

from red_agent.traffic_generator import TrafficGenerator
from red_agent.scenarios import get_scenario, ScenarioResult
from red_agent.campaign import SimulatedCampaign
from red_agent.live_campaign import LiveCampaign
from red_agent.autonomous_campaign import AutonomousCampaign, AutonomousCampaignResult
from red_agent.memory import RedMemory
from red_agent.config import red_settings
from blue_agent.logging_cfg import get_logger

log = get_logger("red.orchestrator")

class RedAgent:
    """Orchestrator for managing Red Agent attack operations."""
    
    def __init__(self, seed: int = 42):
        self._generator = TrafficGenerator(seed=seed)
        self._attack_log: List[Dict] = []
        self._campaign = None
        self._autonomous_campaign: AutonomousCampaign | None = None
        self._autonomous_result: AutonomousCampaignResult | None = None
        self._memory = RedMemory()
    
    @property
    def memory(self) -> RedMemory:
        return self._memory

    def run_scenario(self, scenario_name: str) -> ScenarioResult:
        """Run a named attack scenario."""
        scenario = get_scenario(scenario_name, self._generator)
        result = scenario.generate()
        self._attack_log.extend(result.ground_truth)
        return result
    
    def run_continuous(self, total_events: int, benign_ratio: float = 0.3) -> ScenarioResult:
        """Generate continuous mixed traffic."""
        events = self._generator.generate_mixed_stream(total_events, benign_ratio)
        
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
            
        result = ScenarioResult(
            name="ContinuousStream", 
            traffic=traffic, 
            ground_truth=ground_truth, 
            description="Randomly mixed continuous traffic stream"
        )
        self._attack_log.extend(result.ground_truth)
        return result
        
    def run_autonomous_attack(self, rounds: int = 5, *, max_events: int | None = None) -> ScenarioResult:
        """Run a bounded local campaign using real HTTP by default."""
        log.info("starting_autonomous_red_campaign")
        event_limit = max_events if max_events is not None else max(1, rounds)
        if not red_settings.simulation_only:
            campaign = LiveCampaign(
                red_settings.target_url,
                max_rounds=rounds,
                max_events=event_limit,
                timeout=red_settings.request_timeout,
            )
            self._campaign = campaign
            traffic, ground_truth = campaign.run()
            result = ScenarioResult(
                name="LiveAutonomousCampaign",
                traffic=traffic,
                ground_truth=ground_truth,
                description="Bounded live HTTP campaign against the local target",
            )
            self._attack_log.extend(result.ground_truth)
            return result
        campaign = SimulatedCampaign(
            self._generator,
            max_rounds=max(0, min(rounds, 100)),
            max_events=event_limit,
        )
        self._campaign = campaign
        traffic, ground_truth = campaign.run()
        result = ScenarioResult(
            name="AutonomousCampaign",
            traffic=traffic,
            ground_truth=ground_truth,
            description="Bounded local autonomous campaign using simulated traffic",
        )
        self._attack_log.extend(result.ground_truth)
        return result

    def run_full_autonomous_campaign(
        self,
        rounds: int = 5,
        max_events_per_round: int = 10,
        use_llm: bool = True,
    ) -> AutonomousCampaignResult:
        """
        Run the full autonomous multi-round campaign with:
        - Real reconnaissance
        - LLM-guided attack planning (if available)
        - Adaptive memory
        - Multi-round evolution
        """
        log.info("starting_full_autonomous_campaign",
                 rounds=rounds,
                 events_per_round=max_events_per_round,
                 use_llm=use_llm)

        self._autonomous_campaign = AutonomousCampaign(
            red_settings.target_url,
            max_rounds=rounds,
            max_events_per_round=max_events_per_round,
            timeout=red_settings.request_timeout,
            use_llm=use_llm,
            memory=self._memory,
        )

        self._autonomous_result = self._autonomous_campaign.run()

        # Also extend the attack log for backward compatibility
        self._attack_log.extend(self._autonomous_result.ground_truth)

        return self._autonomous_result

    def get_campaign_status(self) -> Dict:
        """Return a serializable snapshot of the latest autonomous campaign."""
        # Check autonomous campaign first
        if self._autonomous_result:
            return {
                "status": "completed",
                "mode": "full_autonomous",
                "rounds": self._autonomous_result.rounds_completed,
                "events": self._autonomous_result.total_attacks,
                "max_rounds": self._autonomous_campaign.max_rounds if self._autonomous_campaign else 0,
                "max_events": (self._autonomous_campaign.max_rounds * self._autonomous_campaign.max_events_per_round) if self._autonomous_campaign else 0,
                "successful_exploits": self._autonomous_result.successful_exploits,
                "detected_attacks": self._autonomous_result.detected_attacks,
                "round_summaries": self._autonomous_result.round_summaries,
                "strategy_evolution": self._autonomous_result.strategy_evolution,
                "recon_report": self._autonomous_result.recon_report,
                "history": [],
                "simulation_only": False,
                "execution_mode": "full_autonomous",
            }

        if self._campaign is None:
            return {
                "status": "idle",
                "rounds": 0,
                "events": 0,
                "max_rounds": red_settings.max_campaign_rounds,
                "max_events": red_settings.max_campaign_events,
                "history": [],
                "simulation_only": red_settings.simulation_only,
                "execution_mode": "simulation" if red_settings.simulation_only else "live_http",
            }
        state = self._campaign.state
        return {
            "status": "completed" if not state.can_continue() else "idle",
            "rounds": state.rounds,
            "events": state.events,
            "max_rounds": state.max_rounds,
            "max_events": state.max_events,
            "history": list(state.history),
            "simulation_only": red_settings.simulation_only,
            "execution_mode": "simulation" if red_settings.simulation_only else "live_http",
        }
    
    def get_attack_log(self) -> List[Dict]:
        """Get ground truth of all generated attacks for metrics."""
        return self._attack_log.copy()
    
    def reset(self):
        """Reset the internal attack log."""
        self._attack_log.clear()
        self._campaign = None
        self._autonomous_campaign = None
        self._autonomous_result = None
        self._memory.reset()
