from __future__ import annotations

import time
import uuid
import httpx
import random

from typing import List, Dict

from red_agent.traffic_generator import TrafficGenerator
from red_agent.scenarios import get_scenario, ScenarioResult
from red_agent.campaign import SimulatedCampaign
from red_agent.live_campaign import LiveCampaign
from red_agent.autonomous_campaign import AutonomousCampaign, AutonomousCampaignResult
from red_agent.memory import RedMemory
from red_agent.audit_runner import run_audits
from red_agent.config import red_settings
from red_agent.provenance import signed_provenance_headers
from target_platform.registry import TargetRegistry
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
        self._autonomous_in_progress = False
        self._autonomous_progress: Dict = {}
        self._memory = RedMemory()
        self._target_surface: Any = None
    
    @property
    def memory(self) -> RedMemory:
        return self._memory

    def set_target_surface(self, surface: Any) -> None:
        """Register the active target surface discovered for the campaign."""
        self._target_surface = surface
        log.info("red_agent_target_surface_registered", total_routes=getattr(surface, "total_routes", 0))

    def _execute_live_scenario(self, result: ScenarioResult) -> ScenarioResult:
        """Transmit scenario events as real, cryptographically signed HTTP requests to the target."""
        target_url = red_settings.target_url.rstrip("/")
        timeout = red_settings.request_timeout
        campaign_id = f"scenario-{uuid.uuid4().hex[:8]}"

        live_traffic = []
        live_truth = []

        try:
            with httpx.Client(base_url=target_url, timeout=timeout) as client:
                for idx, evt in enumerate(result.traffic):
                    endpoint = evt.get("endpoint", "/")
                    method = evt.get("method", "GET").upper()
                    params = evt.get("params", {})
                    req_id = str(uuid.uuid4())
                    headers = signed_provenance_headers(campaign_id, req_id)

                    t0 = time.perf_counter()
                    resp_code = 599
                    resp_size = 0
                    try:
                        if method == "POST":
                            resp = client.post(endpoint, data=params, headers=headers)
                        else:
                            resp = client.get(endpoint, params=params, headers=headers)
                        resp_code = resp.status_code
                        resp_size = len(resp.content)
                    except Exception as req_err:
                        log.debug("scenario_http_request_error", endpoint=endpoint, error=str(req_err))

                    duration_ms = round((time.perf_counter() - t0) * 1000, 2)
                    updated_evt = {
                        **evt,
                        "request_id": req_id,
                        "campaign_id": campaign_id,
                        "response_code": resp_code,
                        "response_time_ms": duration_ms,
                        "body_size": resp_size,
                    }
                    live_traffic.append(updated_evt)

                    gt = dict(result.ground_truth[idx]) if idx < len(result.ground_truth) else {}
                    gt["response_code"] = resp_code
                    live_truth.append(gt)

            return ScenarioResult(
                name=result.name,
                traffic=live_traffic,
                ground_truth=live_truth,
                description=f"Live HTTP execution of {result.name} against {target_url}",
            )
        except Exception as exc:
            log.warning("scenario_live_execution_failed_falling_back", error=str(exc))
            return result

    def run_scenario(self, scenario_name: str) -> ScenarioResult:
        """Run a named attack scenario using real live HTTP by default."""
        scenario = get_scenario(scenario_name, self._generator)
        result = scenario.generate()

        if not red_settings.simulation_only:
            result = self._execute_live_scenario(result)

        self._attack_log.extend(result.ground_truth)
        return result

    def execute_single_attack(
        self,
        attack_type: str = "sql_injection",
        endpoint: str | None = None,
        method: str | None = None,
        param_name: str | None = None,
        payload_str: str | None = None,
        target_url: str | None = None,
        evasion: str | None = None,
        target_surface: Any | None = None,
    ) -> Dict[str, Any]:
        """Execute a single real HTTP attack against the target container."""
        from red_agent.payloads import get_payloads
        from red_agent.guardrails import TargetGuard
        from red_agent.evasion import EvasionEngine
        import re

        target_url = (target_url or red_settings.target_url).rstrip("/")
        TargetGuard.allow_target(target_url)

        # Look up category payload if parameters not provided
        category_payloads = get_payloads(attack_type)
        default_payload = category_payloads[0] if category_payloads else None

        active_surface = target_surface or getattr(self, "_target_surface", None)

        req_endpoint = endpoint
        req_method = method
        req_param = param_name

        # If endpoint not provided, check dynamic target surface
        if not req_endpoint and active_surface and hasattr(active_surface, "get_endpoints_for_attack"):
            candidates = active_surface.get_endpoints_for_attack(attack_type)
            if candidates:
                cand = random.choice(candidates)
                req_endpoint = cand.path
                req_method = cand.method
                req_param = cand.parameters[0] if cand.parameters else None

        # Fallback to default payload endpoint if still unresolved
        req_endpoint = req_endpoint or (default_payload.target_endpoint if default_payload else "/login")
        req_method = (req_method or (default_payload.method if default_payload else "POST")).upper()
        req_param = req_param or (default_payload.param_name if default_payload else "username")
        actual_payload = payload_str if payload_str is not None else (default_payload.payload if default_payload else "' OR 1=1--")

        # Apply evasion mutation if requested
        if evasion and evasion != "none":
            try:
                evasion_engine = EvasionEngine()
                actual_payload = evasion_engine.apply(evasion, actual_payload)
            except Exception:
                pass

        # Handle path template substitution (e.g. /users/{user_id})
        if "{" in req_endpoint and "}" in req_endpoint:
            req_endpoint = re.sub(r"\{[a-zA-Z0-9_]+\}", str(actual_payload), req_endpoint)

        # Format parameters
        params: Dict[str, Any] = {}
        if req_param and "{" not in req_endpoint:
            params[req_param] = actual_payload
        elif actual_payload and "{" not in req_endpoint:
            params["q"] = actual_payload

        # Endpoint-specific parameter conveniences
        if req_endpoint == "/login" and "password" not in params:
            if attack_type == "brute_force" and ":" in str(actual_payload):
                u, p = actual_payload.split(":", 1)
                params["username"] = u
                params["password"] = p
            else:
                params["password"] = "password123"

        campaign_id = f"single-{uuid.uuid4().hex[:8]}"
        req_id = str(uuid.uuid4())
        headers = signed_provenance_headers(campaign_id, req_id)

        if attack_type == "reconnaissance" and actual_payload:
            headers["User-Agent"] = str(actual_payload)

        resp_code = 500
        resp_size = 0
        resp_snippet = ""
        duration_ms = 0.0

        t0 = time.perf_counter()
        try:
            with httpx.Client(base_url=target_url, timeout=red_settings.request_timeout) as client:
                if req_method == "POST":
                    resp = client.post(req_endpoint, data=params, headers=headers)
                elif req_method == "PUT":
                    resp = client.put(req_endpoint, data=params, headers=headers)
                elif req_method == "DELETE":
                    resp = client.delete(req_endpoint, params=params, headers=headers)
                else:
                    resp = client.get(req_endpoint, params=params, headers=headers)

                resp_code = resp.status_code
                resp_size = len(resp.content)
                resp_snippet = resp.text[:300]
        except Exception as exc:
            log.warning("single_attack_live_http_failed", endpoint=req_endpoint, error=str(exc))
            resp_code = 502
            resp_snippet = f"Connection error: {str(exc)}"

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        traffic_event = {
            "source": "10.0.0.66",
            "endpoint": req_endpoint,
            "method": req_method,
            "params": params,
            "payload": actual_payload,
            "response_code": resp_code,
            "response_time_ms": duration_ms,
            "body_size": resp_size,
            "timestamp": time.time(),
            "request_id": req_id,
            "campaign_id": campaign_id,
            "user_agent": headers.get("User-Agent", "DefendForge-RedAgent/1.0"),
            "is_attack": True,
            "attack_type": attack_type,
            "severity": default_payload.severity if default_payload else "high",
            "evasion": evasion or "none",
            "response_snippet": resp_snippet,
        }

        self._attack_log.append({
            "request_id": req_id,
            "is_attack": True,
            "attack_type": attack_type,
            "severity": traffic_event["severity"],
            "response_code": resp_code,
            "exploit_success": resp_code in (200, 500),
        })

        return traffic_event

    def run_target_audit(self, target_name: str = "default") -> Dict:
        """Run the registered target's allowlisted read-only audits."""
        target = TargetRegistry().load(target_name)
        return run_audits(target.audit.source_path, target.audit)
    
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
        round_callback=None,
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

        self._autonomous_in_progress = True
        self._autonomous_progress = {
            "status": "running",
            "mode": "full_autonomous",
            "rounds": 0,
            "events": 0,
            "max_rounds": rounds,
            "max_events": rounds * max_events_per_round,
            "execution_mode": "full_autonomous",
        }

        def on_round(traffic, ground_truth, summary):
            self._autonomous_progress.update({
                "rounds": summary.get("round", 0),
                "events": self._autonomous_progress["events"] + len(traffic),
            })
            if round_callback:
                round_callback(traffic, ground_truth, summary)

        self._autonomous_campaign = AutonomousCampaign(
            red_settings.target_url,
            max_rounds=rounds,
            max_events_per_round=max_events_per_round,
            timeout=red_settings.request_timeout,
            use_llm=use_llm,
            memory=self._memory,
            round_callback=on_round,
        )

        try:
            self._autonomous_result = self._autonomous_campaign.run()
        finally:
            self._autonomous_in_progress = False

        # Also extend the attack log for backward compatibility
        if self._autonomous_result:
            self._attack_log.extend(self._autonomous_result.ground_truth)

        return self._autonomous_result

    def stop_autonomous_campaign(self) -> None:
        """Signal the running autonomous campaign to halt."""
        if self._autonomous_campaign:
            self._autonomous_campaign._stop_requested = True
        self._autonomous_in_progress = False

    def get_campaign_status(self) -> Dict:
        """Return a serializable snapshot of the latest autonomous campaign."""
        if self._autonomous_in_progress:
            return dict(self._autonomous_progress)
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
