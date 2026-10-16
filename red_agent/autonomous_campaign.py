"""
Red Agent — Autonomous Multi-Round Campaign.

This is the core autonomous attack loop that:
1. Performs real reconnaissance against the target
2. Selects attack techniques from the MITRE ATT&CK knowledge base
3. Executes attacks using the payload library
4. Records results in adaptive in-round and persistent cross-campaign memory
5. Applies evasion variants for previously blocked techniques
6. Adapts strategy based on what was detected/blocked across rounds & campaigns
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin

import httpx

from blue_agent.logging_cfg import get_logger
from red_agent.config import red_settings
from red_agent.evasion import EvasionEngine
from red_agent.guardrails import TargetGuard
from red_agent.knowledge import AttackKnowledge
from red_agent.memory import AttackRecord, RedMemory, RoundSummary
from red_agent.mitre_knowledge import MitreKnowledge
from red_agent.models import CampaignState
from red_agent.payloads import get_payloads, get_all_categories
from red_agent.persistent_memory import RedPersistentMemory
from red_agent.planner import TargetAwarePlanner
from red_agent.provenance import signed_provenance_headers
from target_platform.registry import Endpoint, RegisteredTarget, TargetRegistry
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
        target: RegisteredTarget | None = None,
        audit_findings: dict[str, Any] | None = None,
        campaign_id: str | None = None,
        round_callback: Callable[[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]], None] | None = None,
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
        self.target = target or RegisteredTarget("runtime", self.target_url)
        self.audit_findings = audit_findings or {}
        self.campaign_id = campaign_id or f"campaign-{int(time.time() * 1000)}"
        self.round_callback = round_callback
        self.state = CampaignState(
            max_rounds=self.max_rounds,
            max_events=self.max_rounds * self.max_events_per_round,
        )
        self._recon_report: ReconReport | None = None
        self._llm_available = False
        self._discovered_endpoints: tuple[Endpoint, ...] = ()

        # ── MITRE + Evasion + Persistent memory ──────────────────────
        self.mitre = MitreKnowledge()
        self.evasion = EvasionEngine()
        self.persistent_memory = RedPersistentMemory()

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
        try:
            self._discovered_endpoints = (
                TargetRegistry().discover(self.target, self.timeout) or self.target.endpoints
            )
        except (OSError, ValueError, httpx.HTTPError):
            self._discovered_endpoints = ()
        result.recon_report = self._recon_report.to_dict()

        # Check LLM availability
        self._llm_available = self._check_llm_available()
        log.info("autonomous_campaign_llm_status", available=self._llm_available)

        # Phase 2: Multi-round attack loop
        self._stop_requested = False
        with httpx.Client(base_url=self.target_url, timeout=self.timeout) as client:
            for round_num in range(1, self.max_rounds + 1):
                if getattr(self, "_stop_requested", False):
                    log.info("autonomous_campaign_stopped_by_user", round=round_num)
                    break
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
                if self.round_callback:
                    self.round_callback(
                        round_traffic,
                        round_truth,
                        result.round_summaries[-1],
                    )

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

            plan = []
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
        """MITRE-guided attack planning — uses knowledge base + persistent memory."""
        plan = []

        # Prefer target registry discovery and audit evidence over the legacy
        # bundled-route catalogue. The hard cap is enforced by the planner.
        if self._discovered_endpoints:
            target_plan = TargetAwarePlanner(
                self.target, max_events=self.max_events_per_round
            ).plan(self._discovered_endpoints, self.audit_findings)
            if target_plan:
                # Annotate with MITRE data before returning
                return self._annotate_with_mitre(target_plan)

        # ── MITRE-driven selection ────────────────────────────────────
        blocked_ids = self.persistent_memory.get_blocked_technique_ids()
        tried_ids = self.persistent_memory.get_tried_technique_ids(self.campaign_id)

        # Pick a diverse set of MITRE techniques
        selected_techniques = []
        for _ in range(min(3, self.max_events_per_round)):
            least_covered_tactic = self.mitre.get_least_covered_tactic(tried_ids)
            tech = self.mitre.get_novel_technique(
                blocked_ids=blocked_ids,
                tried_ids={t.technique_id for t in selected_techniques} | tried_ids,
                preferred_tactic=least_covered_tactic,
            )
            if tech and tech not in selected_techniques:
                selected_techniques.append(tech)

        if not selected_techniques:
            # Fallback: use in-round memory
            best_types = self.memory.get_best_attack_types(3)
            if round_num == 1:
                best_types = get_all_categories()
            for attack_type in best_types:
                endpoints = self._get_endpoints_for_attack(attack_type)
                for ep in endpoints:
                    if not self.memory.is_endpoint_patched(ep["endpoint"], attack_type):
                        plan.append({
                            "type": attack_type,
                            "endpoint": ep["endpoint"],
                            "method": ep.get("method", "GET"),
                            "reasoning": f"Fallback heuristic: {attack_type} on {ep['endpoint']}",
                            "technique_id": "unknown",
                            "technique_name": attack_type,
                            "evasion_variant": "none",
                        })
                if len(plan) >= self.max_events_per_round:
                    break
            return plan[:self.max_events_per_round]

        # Build plan from selected MITRE techniques
        for tech in selected_techniques:
            if not tech.payload_categories:
                continue
            attack_type = tech.payload_categories[0]
            endpoints = self._get_endpoints_for_attack(attack_type)

            # Determine if evasion is needed
            already_tried_variants = self.persistent_memory.get_tried_evasion_variants(
                tech.technique_id
            )
            was_blocked_before = tech.technique_id in blocked_ids
            evasion_variant = "none"
            if was_blocked_before and tech.evasion_variants:
                evasion_variant = self.mitre.get_evasion_variant(
                    tech.technique_id, already_tried_variants
                ) or "none"

            for ep in endpoints[:max(1, self.max_events_per_round // len(selected_techniques))]:
                if self.memory.is_endpoint_patched(ep["endpoint"], attack_type):
                    continue
                plan.append({
                    "type": attack_type,
                    "endpoint": ep["endpoint"],
                    "method": ep.get("method", "GET"),
                    "reasoning": (
                        f"MITRE {tech.technique_id} {tech.name} "
                        f"({'evasion:' + evasion_variant if was_blocked_before else 'novel'})"
                    ),
                    "technique_id": tech.technique_id,
                    "technique_name": tech.name,
                    "tactic": tech.tactic,
                    "evasion_variant": evasion_variant,
                })

        return plan[:self.max_events_per_round]

    def _annotate_with_mitre(self, plan: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Annotate a plan from TargetAwarePlanner with MITRE technique metadata."""
        blocked_ids = self.persistent_memory.get_blocked_technique_ids()
        for item in plan:
            attack_type = item.get("type", "")
            techniques = self.mitre.get_by_payload_category(attack_type)
            if techniques:
                # Pick the best unblocked technique
                tech = next(
                    (t for t in techniques if t.technique_id not in blocked_ids),
                    techniques[0]
                )
                item.setdefault("technique_id", tech.technique_id)
                item.setdefault("technique_name", tech.name)
                item.setdefault("tactic", tech.tactic)
                # Add evasion if this technique was blocked before
                if tech.technique_id in blocked_ids:
                    tried = self.persistent_memory.get_tried_evasion_variants(tech.technique_id)
                    item.setdefault(
                        "evasion_variant",
                        self.mitre.get_evasion_variant(tech.technique_id, tried) or "none"
                    )
                else:
                    item.setdefault("evasion_variant", "none")
            else:
                item.setdefault("technique_id", "unknown")
                item.setdefault("technique_name", attack_type)
                item.setdefault("tactic", "unknown")
                item.setdefault("evasion_variant", "none")
        return plan

    def _get_endpoints_for_attack(self, attack_type: str) -> list[dict[str, str]]:
        """Map attack type to target endpoints using recon data."""
        if self._discovered_endpoints:
            discovered = []
            for endpoint in self._discovered_endpoints:
                candidate = TargetAwarePlanner(self.target, max_events=50).plan(
                    (endpoint,), self.audit_findings
                )
                if any(item["type"] == attack_type for item in candidate):
                    discovered.append({"endpoint": endpoint.path, "method": endpoint.method})
            if discovered:
                return discovered
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
        """Execute all attacks in a round, applying evasion where needed."""
        traffic = []
        truth = []
        records = []

        for plan_item in attack_plan:
            attack_type = plan_item["type"]
            endpoint = plan_item["endpoint"]
            method = plan_item.get("method", "GET")
            technique_id = plan_item.get("technique_id", "unknown")
            technique_name = plan_item.get("technique_name", attack_type)
            tactic = plan_item.get("tactic", "unknown")
            evasion_variant = plan_item.get("evasion_variant", "none")

            payloads = get_payloads(attack_type)
            if not payloads:
                continue

            # Pick payload based on round (cycle through them)
            payload_idx = (round_num - 1 + len(traffic)) % len(payloads)
            payload = payloads[payload_idx]
            raw_payload_value = payload.payload

            # ── Apply evasion transform if requested ──────────────────
            mutated_value = raw_payload_value
            if evasion_variant and evasion_variant != "none":
                mutated_value = self.evasion.apply(evasion_variant, raw_payload_value)
                log.info("evasion_transform_applied",
                         technique=technique_id,
                         variant=evasion_variant,
                         endpoint=endpoint)

            # Build request params
            params = {payload.param_name: mutated_value} if payload.param_name else {}
            request_id = f"{self.campaign_id}-{round_num}-{len(traffic)}"
            provenance = signed_provenance_headers(self.campaign_id, request_id)

            # Apply meta-level evasion headers
            extra_headers = self.evasion.meta_headers(evasion_variant)
            all_headers = {**provenance, **extra_headers}

            try:
                if method.upper() == "POST":
                    response = client.post(endpoint, data=params, headers=all_headers)
                else:
                    response = client.get(endpoint, params=params, headers=all_headers)

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
            was_blocked = response_code in (403, 429)
            was_detected = response_code in (403, 429, 200)  # conservative assumption

            # Build traffic event
            event = {
                "source": "127.0.0.1",
                "endpoint": endpoint,
                "method": method.upper(),
                "params": params,
                "response_code": response_code,
                "response_time_ms": 0,
                "body_size": response_size,
                "user_agent": all_headers.get("User-Agent",
                                              "DefendForge-RedAgent/2.0-Autonomous"),
                "destination": "target_app",
                "request_id": request_id,
                "campaign_id": self.campaign_id,
                "source_kind": "red",
                "technique_id": technique_id,
                "evasion_variant": evasion_variant,
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
                "technique_id": technique_id,
                "evasion_variant": evasion_variant,
            }

            traffic.append(event)
            truth.append(truth_item)

            # ── Record in in-round memory ─────────────────────────────
            record = AttackRecord(
                round_number=round_num,
                attack_type=attack_type,
                endpoint=endpoint,
                method=method,
                payload_summary=payload.description,
                response_code=response_code,
                detected=was_detected,
                success=exploit_success,
                blocked=was_blocked,
                notes=plan_item.get("reasoning", ""),
            )
            self.memory.record_attack(record)
            records.append(record)

            # ── Record in cross-campaign persistent memory ────────────
            try:
                self.persistent_memory.record_attack(
                    campaign_id=self.campaign_id,
                    round_number=round_num,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                    attack_type=attack_type,
                    endpoint=endpoint,
                    method=method,
                    payload_value=mutated_value,
                    evasion_variant=evasion_variant,
                    response_code=response_code,
                    was_blocked=was_blocked,
                    was_detected=was_detected,
                    exploit_success=exploit_success,
                    notes=plan_item.get("reasoning", ""),
                )
            except Exception as exc:
                log.warning("persistent_memory_record_failed", error=str(exc))

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
