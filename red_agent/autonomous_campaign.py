"""
Red Agent — Autonomous Multi-Round Campaign.

This is the core autonomous attack loop that:
1. Performs real reconnaissance against the target
2. Uses LLM reasoning (via Ollama/OpenAI) to decide attack strategy
3. Executes attacks using the payload library
4. Records results in adaptive memory
5. Adapts strategy based on what was detected/blocked
6. Runs multiple rounds, evolving against Blue Agent defenses
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from blue_agent.logging_cfg import get_logger
from red_agent.config import red_settings
from red_agent.guardrails import TargetGuard
from red_agent.knowledge import AttackKnowledge
from red_agent.memory import AttackRecord, RedMemory, RoundSummary
from red_agent.models import CampaignState
from red_agent.payloads import get_payloads, get_all_categories
from red_agent.recon.scanner import LiveScanner, ReconReport

log = get_logger("red.autonomous")


@dataclass
class AutonomousCampaignResult:
    """Result of a full autonomous campaign."""
    rounds_completed: int = 0
    total_attacks: int = 0
    successful_exploits: int = 0
    detected_attacks: int = 0
    traffic: list[dict[str, Any]] = field(default_factory=list)
    ground_truth: list[dict[str, Any]] = field(default_factory=list)
    round_summaries: list[dict[str, Any]] = field(default_factory=list)
    recon_report: dict[str, Any] = field(default_factory=dict)
    strategy_evolution: list[str] = field(default_factory=list)


class AutonomousCampaign:
    """
    Full autonomous Red Agent campaign with real reconnaissance,
    LLM-guided attack planning, and adaptive memory.

    Safety: Restricted to allowlisted local targets only.
    """

    def __init__(
        self,
        target_url: str,
        *,
        max_rounds: int = 5,
        max_events_per_round: int = 10,
        timeout: float = 5.0,
        use_llm: bool = True,
        knowledge: AttackKnowledge | None = None,
        memory: RedMemory | None = None,
    ):
        self.guard = TargetGuard()
        self.guard.validate(target_url)
        self.target_url = target_url.rstrip("/")
        self.max_rounds = min(max_rounds, 100)
        self.max_events_per_round = min(max_events_per_round, 50)
        self.timeout = timeout
        self.use_llm = use_llm
        self.knowledge = knowledge or AttackKnowledge()
        self.memory = memory or RedMemory()
        self.state = CampaignState(
            max_rounds=self.max_rounds,
            max_events=self.max_rounds * self.max_events_per_round,
        )
        self._recon_report: ReconReport | None = None
        self._llm_available = False

    def run(self) -> AutonomousCampaignResult:
        """Execute the full autonomous campaign."""
        result = AutonomousCampaignResult()
        log.info("autonomous_campaign_starting",
                 target=self.target_url,
                 max_rounds=self.max_rounds,
                 max_events_per_round=self.max_events_per_round)

        # Phase 1: Reconnaissance
        log.info("autonomous_campaign_phase_1_recon")
        self._recon_report = self._perform_recon()
        result.recon_report = self._recon_report.to_dict()

        # Check LLM availability
        self._llm_available = self._check_llm_available()
        log.info("autonomous_campaign_llm_status", available=self._llm_available)

        # Phase 2: Multi-round attack loop
        with httpx.Client(base_url=self.target_url, timeout=self.timeout) as client:
            for round_num in range(1, self.max_rounds + 1):
                log.info("autonomous_campaign_round_start", round=round_num)
                self.memory.start_new_round()

                round_t0 = time.perf_counter()

                # Decide attack strategy for this round
                attack_plan = self._plan_round_attacks(round_num)
                result.strategy_evolution.append(
                    f"Round {round_num}: {', '.join(a['type'] for a in attack_plan)}"
                )

                # Execute attacks
                round_traffic, round_truth, round_records = self._execute_round(
                    client, round_num, attack_plan
                )

                result.traffic.extend(round_traffic)
                result.ground_truth.extend(round_truth)
                result.total_attacks += len(round_traffic)

                # Build round summary
                summary = RoundSummary(
                    round_number=round_num,
                    total_attacks=len(round_traffic),
                    successful_attacks=sum(1 for r in round_records if r.success),
                    detected_attacks=sum(1 for r in round_records if r.detected),
                    blocked_attacks=sum(1 for r in round_records if r.blocked),
                    attack_types_used=list({r.attack_type for r in round_records}),
                    duration_ms=(time.perf_counter() - round_t0) * 1000,
                )
                self.memory.record_round_summary(summary)

                result.successful_exploits += summary.successful_attacks
                result.detected_attacks += summary.detected_attacks
                result.round_summaries.append({
                    "round": round_num,
                    "attacks": summary.total_attacks,
                    "successful": summary.successful_attacks,
                    "detected": summary.detected_attacks,
                    "blocked": summary.blocked_attacks,
                    "types": summary.attack_types_used,
                    "duration_ms": round(summary.duration_ms, 1),
                })

                result.rounds_completed = round_num
                self.state.rounds = round_num
                self.state.events = len(result.traffic)

                log.info("autonomous_campaign_round_complete",
                         round=round_num,
                         attacks=summary.total_attacks,
                         successful=summary.successful_attacks,
                         detected=summary.detected_attacks)

        log.info("autonomous_campaign_complete",
                 rounds=result.rounds_completed,
                 total_attacks=result.total_attacks,
                 successful=result.successful_exploits,
                 detected=result.detected_attacks)

        return result

    def _perform_recon(self) -> ReconReport:
        """Run reconnaissance scan against the target."""
        try:
            scanner = LiveScanner(self.target_url, timeout=self.timeout)
            report = scanner.scan()
            scanner.close()
            log.info("recon_complete",
                     endpoints=len(report.discovered_endpoints),
                     vulns=len(report.potential_vulnerabilities),
                     techs=report.technologies)
            return report
        except Exception as e:
            log.error("recon_failed", error=str(e))
            from red_agent.recon.scanner import ReconReport
            return ReconReport(target_url=self.target_url)

    def _check_llm_available(self) -> bool:
        """Check if Ollama or configured LLM is accessible."""
        if not self.use_llm:
            return False
        try:
            resp = httpx.get("http://localhost:11434/api/tags", timeout=3.0)
            return resp.is_success
        except Exception:
            try:
                # Try host.docker.internal for Docker environments
                resp = httpx.get("http://host.docker.internal:11434/api/tags", timeout=3.0)
                return resp.is_success
            except Exception:
                return False

    def _plan_round_attacks(self, round_num: int) -> list[dict[str, Any]]:
        """Decide which attacks to execute this round."""
        plan = []

        if self._llm_available and self.use_llm:
            plan = self._plan_with_llm(round_num)

        if not plan:
            plan = self._plan_heuristic(round_num)

        return plan

    def _plan_with_llm(self, round_num: int) -> list[dict[str, Any]]:
        """Use LLM to plan the next attack round."""
        try:
            from red_agent.llm.attack_planner import AutonomousAttackPlanner
            planner = AutonomousAttackPlanner()

            scan_results = self._recon_report.to_dict() if self._recon_report else {}
            context = [self.memory.get_strategy_context()]

            # Get LLM decision
            decision = planner.plan_next_action(scan_results, context)
            action = decision.get("action", "reconnaissance")
            reasoning = decision.get("reasoning", "")

            log.info("llm_attack_plan",
                     action=action,
                     reasoning=reasoning[:200])

            # Map LLM decision to attack plan
            if action in get_all_categories():
                # Find the best endpoints for this attack type
                endpoints = self._get_endpoints_for_attack(action)
                for ep in endpoints[:self.max_events_per_round]:
                    plan_item = {
                        "type": action,
                        "endpoint": ep["endpoint"],
                        "method": ep.get("method", "GET"),
                        "reasoning": reasoning,
                    }
                    plan.append(plan_item)
            else:
                plan = self._plan_heuristic(round_num)

            return plan
        except Exception as e:
            log.warning("llm_planning_failed", error=str(e))
            return []

    def _plan_heuristic(self, round_num: int) -> list[dict[str, Any]]:
        """Heuristic attack planning without LLM."""
        plan = []

        # Use memory to pick best attack types
        best_types = self.memory.get_best_attack_types(3)

        # On first round, try a broader scan
        if round_num == 1:
            best_types = get_all_categories()

        for attack_type in best_types:
            # Skip if endpoint is known to be patched
            endpoints = self._get_endpoints_for_attack(attack_type)
            for ep in endpoints:
                if self.memory.is_endpoint_patched(ep["endpoint"], attack_type):
                    log.info("skipping_patched_endpoint",
                             endpoint=ep["endpoint"],
                             attack_type=attack_type)
                    continue
                plan.append({
                    "type": attack_type,
                    "endpoint": ep["endpoint"],
                    "method": ep.get("method", "GET"),
                    "reasoning": f"Heuristic: {attack_type} on {ep['endpoint']}",
                })

            if len(plan) >= self.max_events_per_round:
                break

        return plan[:self.max_events_per_round]

    def _get_endpoints_for_attack(self, attack_type: str) -> list[dict[str, str]]:
        """Map attack type to target endpoints using recon data."""
        # Map attack types to known vulnerable endpoints
        attack_endpoint_map = {
            "sql_injection": [
                {"endpoint": "/login", "method": "POST"},
                {"endpoint": "/search", "method": "GET"},
                {"endpoint": "/comments", "method": "POST"},
            ],
            "xss": [
                {"endpoint": "/greet", "method": "GET"},
            ],
            "path_traversal": [
                {"endpoint": "/file", "method": "GET"},
            ],
            "command_injection": [
                {"endpoint": "/ping", "method": "GET"},
            ],
            "ssrf": [
                {"endpoint": "/fetch", "method": "GET"},
            ],
            "brute_force": [
                {"endpoint": "/login", "method": "POST"},
            ],
            "reconnaissance": [
                {"endpoint": "/", "method": "GET"},
                {"endpoint": "/admin/users", "method": "GET"},
            ],
        }

        # If we have recon data, use it to enhance endpoints
        if self._recon_report and self._recon_report.potential_vulnerabilities:
            recon_endpoints = []
            for vuln in self._recon_report.potential_vulnerabilities:
                vuln_type = vuln.get("type", "").lower()
                if attack_type.replace("_", " ") in vuln_type or attack_type in vuln_type:
                    recon_endpoints.append({
                        "endpoint": vuln["endpoint"],
                        "method": vuln.get("method", "GET"),
                    })
            if recon_endpoints:
                return recon_endpoints

        return attack_endpoint_map.get(attack_type, [{"endpoint": "/", "method": "GET"}])

    def _execute_round(
        self,
        client: httpx.Client,
        round_num: int,
        attack_plan: list[dict[str, Any]],
    ) -> tuple[list[dict], list[dict], list[AttackRecord]]:
        """Execute all attacks in a round."""
        traffic = []
        truth = []
        records = []

        for plan_item in attack_plan:
            attack_type = plan_item["type"]
            endpoint = plan_item["endpoint"]
            method = plan_item.get("method", "GET")

            payloads = get_payloads(attack_type)
            if not payloads:
                continue

            # Pick payload based on round (cycle through them)
            payload_idx = (round_num - 1 + len(traffic)) % len(payloads)
            payload = payloads[payload_idx]

            # Build and send the request
            params = {payload.param_name: payload.payload} if payload.param_name else {}

            try:
                if method.upper() == "POST":
                    response = client.post(endpoint, data=params)
                else:
                    response = client.get(endpoint, params=params)

                response_code = response.status_code
                response_size = len(response.content)
                response_body = response.text[:1024]
            except httpx.HTTPError as exc:
                response_code = 599
                response_size = 0
                response_body = str(exc)

            # Determine if exploit was successful
            exploit_success = self._evaluate_exploit_success(
                attack_type, endpoint, response_code, response_body
            )

            # Build traffic event
            event = {
                "source": "127.0.0.1",
                "endpoint": endpoint,
                "method": method.upper(),
                "params": params,
                "response_code": response_code,
                "response_time_ms": 0,
                "body_size": response_size,
                "user_agent": "DefendForge-RedAgent/2.0-Autonomous",
                "destination": "target_app",
            }

            truth_item = {
                "index": len(truth),
                "is_attack": True,
                "attack_type": attack_type,
                "severity": payload.severity,
                "rationale": plan_item.get("reasoning", ""),
                "response_code": response_code,
                "exploit_success": exploit_success,
                "round": round_num,
            }

            traffic.append(event)
            truth.append(truth_item)

            # Record in memory
            record = AttackRecord(
                round_number=round_num,
                attack_type=attack_type,
                endpoint=endpoint,
                method=method,
                payload_summary=payload.description,
                response_code=response_code,
                detected=True,  # Assume detected initially; Blue Agent will update
                success=exploit_success,
                blocked=response_code in (403, 429),
                notes=plan_item.get("reasoning", ""),
            )
            self.memory.record_attack(record)
            records.append(record)

        return traffic, truth, records

    def _evaluate_exploit_success(
        self,
        attack_type: str,
        endpoint: str,
        response_code: int,
        response_body: str,
    ) -> bool:
        """Determine if an exploit actually worked."""
        body_lower = response_body.lower()

        if attack_type == "sql_injection":
            if endpoint == "/login" and response_code == 200:
                if "login successful" in body_lower:
                    return True
            if endpoint == "/search" and response_code == 200:
                # Union injection success might return user data
                if "password" in body_lower or "admin" in body_lower:
                    return True
            return response_code == 200

        if attack_type == "xss":
            # Check if our payload was reflected unescaped
            if "<script" in body_lower or "onerror=" in body_lower or "onload=" in body_lower:
                return True

        if attack_type == "command_injection":
            # If we got back command output (not just "ping failed")
            if response_code == 200:
                if "root:" in response_body or "uid=" in response_body:
                    return True
                # Even getting a response suggests the command ran
                if "output" in body_lower and len(response_body) > 50:
                    return True

        if attack_type == "path_traversal":
            if response_code == 200 and "content" in body_lower:
                if "root:" in response_body or len(response_body) > 20:
                    return True

        if attack_type == "ssrf":
            if response_code == 200 and len(response_body) > 10:
                return True

        if attack_type == "brute_force":
            if response_code == 200 and "login successful" in body_lower:
                return True

        if attack_type == "reconnaissance":
            if response_code == 200:
                return True

        return False
