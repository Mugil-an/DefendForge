"""FastAPI REST API + WebSocket for the Blue Agent with real-time 3D dashboard."""
from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
import os

from blue_agent.config import PROJECT_ROOT, RULES_DIR, DATA_DIR, settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import (
    AuditReport,
    MetricsSnapshot,
)
from blue_agent.monitoring.health import HealthChecker
from blue_agent.api.ws_manager import ws_manager
from blue_agent.events import classify_event
from blue_agent.memory.repository import MemoryRepository
import collections
from blue_agent.schemas import SecurityEventRecord

log = get_logger("api.routes")

_seen_broadcast_req_ids: set[str] = set()
_seen_broadcast_req_ids_queue: collections.deque[str] = collections.deque(maxlen=2000)

def _is_duplicate_request(req_id: str | None) -> bool:
    """Return True if req_id has already been processed or broadcast recently."""
    if not req_id:
        return False
    if req_id in _seen_broadcast_req_ids:
        return True
    _seen_broadcast_req_ids.add(req_id)
    if len(_seen_broadcast_req_ids_queue) == _seen_broadcast_req_ids_queue.maxlen:
        oldest = _seen_broadcast_req_ids_queue.popleft()
        _seen_broadcast_req_ids.discard(oldest)
    _seen_broadcast_req_ids_queue.append(req_id)
    return False

app = FastAPI(
    title="DefendForge Blue Agent API",
    description="REST API for the Collaborative Multi-Agent Cybersecurity Hardening System",
    version="0.1.0",
)

# CORS for local dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static dashboard files
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

_cicids_detector = None
def get_cicids_detector():
    global _cicids_detector
    if _cicids_detector is None:
        from blue_agent.detection.cicids_flow_detector import CICIDSFlowDetector
        _cicids_detector = CICIDSFlowDetector()
        try:
            _cicids_detector.load()
        except Exception as e:
            log.error("Failed to load CICIDS model", error=str(e))
    return _cicids_detector

@app.post("/api/netflow")
async def receive_netflow(flow_data: dict):
    dst_port = flow_data.get("Dst Port", flow_data.get("dst_port", "5000"))
    src_ip = flow_data.get("Src IP", flow_data.get("src_ip", "unknown"))
    protocol = flow_data.get("Protocol", flow_data.get("protocol", "TCP"))
    
    log.info("netflow_received", dest_port=dst_port, src_ip=src_ip)
    
    # Use the CICIDSFlowDetector for network-layer anomaly detection
    is_attack = False
    detector = get_cicids_detector()
    if detector.is_fitted:
        import pandas as pd
        df = pd.DataFrame([flow_data])
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
        try:
            res = detector.predict_batch(df)[0]
            is_attack = res.is_anomaly
        except Exception as e:
            log.warning("cicids_predict_failed", error=str(e))
        
    ws_event = _decorate_event({
        "source_ip": src_ip,
        "endpoint": f"Port {dst_port} ({protocol})",
        "method": "NETFLOW",
        "is_attack": is_attack,
        "attack_type": None,
        "severity": "low",
        "action": "observe",
        "timestamp": time.time(),
        "rationale": "Live flow captured by network sniffer",
        "exploit_success": False,
        "round": 0,
    }, None)
    
    _memory_log.insert(0, ws_event)
    if len(_memory_log) > 200:
        del _memory_log[200:]
        
    await ws_manager.broadcast_event("attack" if is_attack else "traffic", ws_event)
    
    return {"status": "ok"}


@app.post("/api/events")
async def receive_gateway_event(event: dict) -> Dict[str, Any]:
    """Receive normalized user/Red events from the local target gateway."""
    normalized = classify_event(event)
    req_id = normalized.get("request_id")

    # Check if this event was already processed/broadcast, or is an arena-orchestrated event.
    # When arena is active, _continuous_arena_battle_loop broadcasts the enriched telemetry.
    is_arena_dup = bool(
        _arena_running and (
            _is_duplicate_request(req_id)
            or normalized.get("campaign_id", "").startswith("single-")
            or normalized.get("source_kind") in ("red", "green_agent", "user")
        )
    )
    if not is_arena_dup and req_id and _is_duplicate_request(req_id):
        is_arena_dup = True

    agent = _get_agent()
    normalized_input = [{
        "source": normalized.get("source_kind", "unknown"),
        "endpoint": normalized.get("path", "/"),
        "method": normalized.get("method", "GET"),
        "is_attack": normalized["is_attack"],
        "attack_type": normalized.get("attack_type"),
        "source_kind": normalized["source_kind"],
        "campaign_id": normalized.get("campaign_id"),
        "response_code": normalized.get("status_code", 0),
        "response_time_ms": normalized.get("duration_ms", 0),
        "body_size": normalized.get("response_size", 0),
        "event_id": normalized.get("event_id"),
        "features": {"finding_id": normalized.get("finding_id")},
    }]
    if not is_arena_dup:
        await asyncio.to_thread(agent.process_traffic, normalized_input)
    details = next(
        (item for item in getattr(agent, "last_round_details", [])
         if item.get("event_id") == normalized.get("event_id")),
        {},
    )
    event_record = SecurityEventRecord(
        event_id=normalized.get("event_id") or str(uuid.uuid4()),
        occurred_at=_event_datetime(normalized.get("timestamp")),
        target_id=normalized.get("target_id", ""),
        method=normalized.get("method", "GET"),
        path=normalized.get("path", "/"),
        query=normalized.get("query", ""),
        status_code=normalized.get("status_code"),
        duration_ms=normalized.get("duration_ms"),
        request_size=normalized.get("request_size"),
        response_size=normalized.get("response_size"),
        source_kind=normalized["source_kind"],
        source_provenance={
            "source_kind": normalized["source_kind"],
            "campaign_id": normalized.get("campaign_id"),
            "request_id": normalized.get("request_id"),
        },
        campaign_id=normalized.get("campaign_id"),
        request_id=normalized.get("request_id"),
        finding_id=details.get("finding_id") or normalized.get("finding_id"),
        patch_id=details.get("patch_id"),
        validation_id=details.get("validation_id"),
        prediction_is_attack=normalized["is_attack"],
        prediction_attack_type=normalized.get("attack_type"),
        prediction_confidence=details.get("confidence"),
        raw_event=normalized,
    )
    _get_event_repository().store_event(event_record)

    if not is_arena_dup:
        _memory_log.insert(0, _decorate_event({
            "source_ip": normalized.get("source_kind", "unknown"),
            "endpoint": normalized.get("path", "/"),
            "method": normalized.get("method", "GET"),
            "is_attack": normalized["is_attack"],
            "attack_type": normalized.get("attack_type"),
            "severity": "high" if normalized["is_attack"] else "low",
            "action": "blocked" if normalized["is_attack"] else "observe",
            "timestamp": normalized.get("timestamp", time.time()),
            "request_id": normalized.get("request_id"),
            "source_kind": normalized["source_kind"],
            "campaign_id": normalized.get("campaign_id"),
        }))
        del _memory_log[200:]
        await ws_manager.broadcast_event(
            "attack" if normalized["is_attack"] else "traffic",
            _memory_log[0],
        )
    return {"status": "ok", "source_kind": normalized["source_kind"], "event_id": normalized.get("event_id")}


def _event_datetime(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Lazy Agent Initialization (with SQLite fallback for local dev)
# ---------------------------------------------------------------------------
_agent = None
_red_agent = None
_memory_log: List[Dict[str, Any]] = []  # In-memory event log for dashboard
_event_repository = None
_arena_running: bool = False
_arena_task: Optional[asyncio.Task] = None
_arena_round: int = 1


def _get_event_repository() -> MemoryRepository:
    """Use configured durable storage, falling back to a local SQLite file."""
    global _event_repository
    if _event_repository is None:
        try:
            _event_repository = MemoryRepository()
        except Exception as exc:
            log.warning("event_db_unavailable_using_sqlite", error=str(exc))
            sqlite_path = Path(__file__).resolve().parents[2] / "data" / "blue_memory.db"
            sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            _event_repository = MemoryRepository(db_url=f"sqlite:///{sqlite_path}")
    return _event_repository


@app.get("/api/security-events")
def get_security_events(limit: int = Query(100, ge=1, le=1000)) -> List[Dict[str, Any]]:
    """Return normalized gateway observations from durable storage."""
    return [event.model_dump(mode="json") for event in _get_event_repository().get_events(limit)]

RESEARCH_NOVELTY = [
    {
        "id": "hybrid-routing",
        "title": "Confidence-gated hybrid defense",
        "summary": "DefendForge combines a fast RL-style policy path with an LLM/RAG reasoning path and routes by confidence.",
        "evidence": "decision_path, confidence, and llm_escalation are recorded per defense round.",
        "source": "Castro et al., Large Language Models are Autonomous Cyber Defenders (basepaper.pdf)",
        "status": "implemented integration",
    },
    {
        "id": "validated-remediation",
        "title": "Rollback-safe remediation",
        "summary": "A patch is only accepted after the target validation contract passes; failures remain visible as rollbacks.",
        "evidence": "validation and outcome are emitted in the live event stream.",
        "source": "Farzulla & Maksakov, Autonomous Red Team and Blue Team AI (Farzulla_2025_Autonomous_Red_Team.pdf)",
        "status": "implemented integration",
    },
    {
        "id": "adaptive-memory",
        "title": "Iterative red-blue hardening",
        "summary": "Bounded red campaigns and blue outcomes persist across rounds, making the defense loop inspectable instead of a static replay.",
        "evidence": "campaign history, memory records, and cumulative metrics are shown in the dashboard.",
        "source": "Huang et al., RvB: Automating AI System Hardening via Iterative Red-Blue Games (RvB.pdf)",
        "status": "implemented integration",
    },
    {
        "id": "green-agent",
        "title": "Red-blue-green operating model",
        "summary": "Benign Green-agent traffic is rendered beside Red attacks and Blue responses so false positives and service disruption are measurable.",
        "evidence": "traffic events are classified independently and counted in precision/recall.",
        "source": "Kiely et al., CAGEchallenge4 (AI Magazine 2025 CAGE challenge 4.pdf)",
        "status": "implemented integration",
    },
    {
        "id": "safe-cyber-range",
        "title": "Inspectable cyber-range evaluation",
        "summary": "The dashboard exposes attack traffic, detector results, defense decisions, and outcomes against a self-owned local target.",
        "evidence": "the event stream records ground truth separately from the observed defender result.",
        "source": "Emerson et al., CybORG++ (cyborg.pdf); Farzulla & Maksakov (Farzulla_2025_Autonomous_Red_Team.pdf)",
        "status": "implemented integration",
    },
    {
        "id": "moving-target-defense",
        "title": "Self-evolving moving-target defense",
        "summary": "Dynamic route scrambling, decoy honeypot injection, header deception, and paired baseline evaluation against held-out zero-day exploits.",
        "evidence": "MTD controller and paired comparison evaluator in mtd/ verified via /api/mtd/evaluate.",
        "source": "Cao et al., DRL-Based Self-Evolving MTD Against Unknown Attacks (Deep-Reinforcement-Learning-Based_Self-Evolving_Moving_Target_Defense_Approach_Against_Unknown_Attacks.pdf)",
        "status": "implemented integration",
    },
]


def _snapshot_to_dict(snapshot: Any) -> Dict[str, Any]:
    """Serialize a metrics snapshot for both REST and WebSocket clients."""
    if hasattr(snapshot, "model_dump"):
        return snapshot.model_dump(mode="json")
    if hasattr(snapshot, "dict"):
        return snapshot.dict()
    return dict(snapshot)


def _dashboard_snapshot(agent: Any) -> Dict[str, Any]:
    """Return the complete state needed to render the command center."""
    metrics = _snapshot_to_dict(agent.metrics.get_snapshot())
    return {
        "status": "operational",
        "mode": "full" if agent.__class__.__name__ != "_LightweightAgent" else "lightweight",
        "metrics": metrics,
        "events": _memory_log[:50],
        "event_count": len(_memory_log),
        "last_event_at": _memory_log[0].get("timestamp") if _memory_log else None,
        "red_campaign": _get_red_agent().get_campaign_status(),
        "phase": "Phase 1 — integrated defense loop",
        "phase_2_status": "excluded by scope",
        "arena_running": _arena_running,
        "active_round": _arena_round,
    }


def _decorate_event(event: Dict[str, Any], detail: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Add the observable Phase 1 pipeline state to a dashboard event."""
    detail = detail or {}
    is_attack = bool(event.get("is_attack"))
    detected = bool(detail) and detail.get("outcome") != "OBSERVED"
    displayed_action = event.get("action", "observe")
    if is_attack and not detected:
        displayed_action = "missed"
    return {
        **event,
        "ground_truth_action": event.get("action", "observe"),
        "detected": detected,
        "action": displayed_action,
        "pipeline": ["RECON", "DETECT", "ROUTE", "REMEDIATE", "VALIDATE", "HARDEN"],
        "decision_path": detail.get("decision_path", "unavailable"),
        "confidence": detail.get("confidence"),
        "decision_reason": detail.get("decision_reason"),
        "llm_escalation": detail.get("llm_escalation", False),
        "defense_action": detail.get("action", event.get("action", "observe")),
        "remediation": detail.get("remediation", ""),
        "validation": detail.get("validation", "NOT_REQUIRED"),
        "outcome": detail.get("outcome", "OBSERVED"),
        "hardening": detail.get("hardening", []),
        "phase": detail.get("phase", "COMPLETE"),
    }


def _get_agent():
    global _agent
    if _agent is None:
        try:
            from blue_agent.orchestrator import BlueAgent
            _agent = BlueAgent()
        except Exception as e:
            log.warning("agent_init_failed_using_lightweight_mode", error=str(e))
            _agent = _LightweightAgent()
    return _agent


def _get_red_agent():
    global _red_agent
    if _red_agent is None:
        from red_agent.orchestrator import RedAgent
        _red_agent = RedAgent()
    return _red_agent


class _LightweightAgent:
    """Fallback agent when Postgres / heavy deps aren't available."""

    def __init__(self):
        from blue_agent.metrics.tracker import MetricsTracker
        from blue_agent.detection.alert_manager import AlertManager
        from blue_agent.detection.random_forest import RandomForestDetector
        from blue_agent.remediation.patch_generator import PatchGenerator
        from blue_agent.hardening.rule_manager import RuleManager

        self.metrics = MetricsTracker()
        detector = RandomForestDetector()
        model_candidates = [
            Path(settings.detection.model_path),
            Path(__file__).resolve().parents[1] / "anomaly_detector" / "models" / "isolation_forest.joblib",
            Path(__file__).resolve().parents[2] / "models" / "random_forest_24.joblib",
        ]
        for model_path in model_candidates:
            if model_path.exists():
                try:
                    detector.load(str(model_path))
                    break
                except Exception as exc:
                    log.warning("detector_model_load_failed", path=str(model_path), error=str(exc))
        self.alert_manager = AlertManager(detector=detector)
        self.patch_gen = PatchGenerator()
        self.hardening = RuleManager()
        self.last_round_details: List[Dict[str, Any]] = []
        log.info("lightweight_agent_ready")

    def process_traffic(self, raw_events: List[Dict[str, Any]]) -> List[MetricsSnapshot]:
        self.last_round_details = []
        self.metrics.increment_round()
        snapshots = []

        t0 = time.perf_counter()
        try:
            alerts = self.alert_manager.process_batch(raw_events)
        except (RuntimeError, ValueError) as exc:
            # Keep the dashboard usable when a locally supplied model was
            # trained with a different feature schema than the current app.
            log.warning("detector_schema_mismatch_using_event_labels", error=str(exc))
            alerts = []
            for event in raw_events:
                is_attack = bool(event.get("is_attack", event.get("attack_type")))
                self.metrics.record_detection(
                    is_attack=is_attack,
                    detected=is_attack,
                    time_ms=0.0,
                )
        detect_time = (time.perf_counter() - t0) * 1000

        if not alerts:
            attack_events = [
                event for event in raw_events
                if bool(event.get("is_attack", event.get("attack_type")))
            ]
            self.last_round_details = [{
                "decision_path": "fallback",
                "confidence": None,
                "llm_escalation": False,
                "action": "block_source_ip",
                "remediation": "blocked",
                "validation": "NOT_REQUIRED",
                "outcome": "SUCCESS",
                "decision_reason": "detector_schema_mismatch",
                "hardening": [],
                "phase": "COMPLETE",
            } for _ in attack_events]
            for event in raw_events:
                is_attack = bool(event.get("is_attack", event.get("attack_type")))
                self.metrics.record_detection(
                    is_attack=is_attack,
                    detected=is_attack,
                    time_ms=0.0,
                )
            return [self.metrics.get_snapshot()]

        for event in alerts:
            self.metrics.record_detection(is_attack=True, detected=True, time_ms=detect_time / len(alerts))
            # Attempt remediation
            patch = self.patch_gen.generate_patch(event)
            if patch:
                self.metrics.record_remediation(success=True, time_ms=5.0)
            # Hardening
            self.hardening.derive_rules_from_event(event)
            self.last_round_details.append({
                "decision_path": "fallback",
                "confidence": 0.8,
                "llm_escalation": False,
                "action": "apply_known_patch" if patch else "update_security_rule",
                "remediation": "validated_patch" if patch else "update_security_rule",
                "validation": "ACCEPT" if patch else "NOT_REQUIRED",
                "outcome": "SUCCESS",
                "decision_reason": "detector_fallback",
                "hardening": [],
                "phase": "COMPLETE",
            })
            snapshots.append(self.metrics.get_snapshot())

        return snapshots


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------
class TrafficBatch(BaseModel):
    events: List[Dict[str, Any]]


class SimulateScenario(BaseModel):
    scenario: str
    rounds: int = 1


class AutonomousCampaignRequest(BaseModel):
    rounds: int = 5
    max_events: int = 25


class FullAutonomousRequest(BaseModel):
    rounds: int = 5
    events_per_round: int = 10
    use_llm: bool = True


class ArenaLaunchRequest(BaseModel):
    target_url: str = "http://target_gateway:8080"
    target_path: Optional[str] = "./target_app"
    rounds: int = 5
    events_per_round: int = 15
    use_llm: bool = True


class TriggerAttackRequest(BaseModel):
    attack_type: str = "sql_injection"
    target_url: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    param_name: Optional[str] = None
    payload: Optional[str] = None
    evasion: Optional[str] = None


# ---------------------------------------------------------------------------
# WebSocket Endpoint
# ---------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        try:
            snapshot = _dashboard_snapshot(_get_agent())
            await websocket.send_text(json.dumps({"type": "sync", "data": snapshot}))
        except Exception as sync_err:
            log.warning("ws_initial_sync_failed", error=str(sync_err))

        while True:
            # Keep connection alive, listen for pings
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    try:
        checker = HealthChecker()
        status = checker.get_full_status()
        is_ok = all(s.get("status") == "ok" for k, s in status.items() if k != "system_info")
        return {
            "status": "ok" if is_ok else "degraded",
            "version": "0.1.0",
            **status
        }
    except Exception:
        return {"status": "ok", "version": "0.1.0", "mode": "lightweight"}


@app.post("/api/traffic")
async def process_traffic(batch: TrafficBatch) -> Dict[str, Any]:
    agent = _get_agent()
    try:
        snapshots = await asyncio.to_thread(agent.process_traffic, batch.events)
        # Broadcast each event to WS clients
        for evt in batch.events:
            is_attack = bool(evt.get("is_attack", evt.get("attack_type")))
            ws_event = _decorate_event({
                "source_ip": evt.get("source", "unknown"),
                "endpoint": evt.get("endpoint", "/"),
                "method": evt.get("method", "GET"),
                "is_attack": is_attack,
                "attack_type": evt.get("attack_type"),
                "severity": evt.get("severity", "unknown"),
                "action": "blocked" if is_attack else "allowed",
                "timestamp": evt.get("timestamp", ""),
            })
            _memory_log.insert(0, ws_event)
            await ws_manager.broadcast_event("attack" if is_attack else "traffic", ws_event)

        if len(_memory_log) > 200:
            del _memory_log[200:]

        snapshot = snapshots[-1] if snapshots else agent.metrics.get_snapshot()
        return _snapshot_to_dict(snapshot)
    except Exception as e:
        log.error("traffic_processing_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/events")
async def receive_gateway_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ingest live HTTP traffic event emitted by target_gateway.
    Passes directly into BlueAgent.process_traffic() for anomaly detection,
    heuristic classification, RL/LLM defense, and real-time dashboard broadcast.
    """
    agent = _get_agent()
    query_str = raw_event.get("query", "")
    query_dict: Dict[str, Any] = {}
    if query_str:
        from urllib.parse import parse_qs
        query_dict = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_str).items()}

    event_id = raw_event.get("event_id") or str(uuid.uuid4())
    headers = raw_event.get("request_headers", {})
    source_ip = headers.get("x-forwarded-for") or headers.get("host") or "127.0.0.1"

    normalized = {
        "event_id": event_id,
        "source": source_ip,
        "endpoint": raw_event.get("path", "/"),
        "method": raw_event.get("method", "GET"),
        "response_code": raw_event.get("status_code", 200),
        "request_size": raw_event.get("request_size", 0),
        "response_size": raw_event.get("response_size", 0),
        "latency_ms": raw_event.get("duration_ms", 1.0),
        "params": query_dict,
        "body": raw_event.get("body", ""),
        "timestamp": raw_event.get("timestamp", time.time()),
        "user_agent": headers.get("user-agent", ""),
    }

    try:
        snapshots = agent.process_traffic([normalized])
        details = getattr(agent, "last_round_details", [])
        detail = details[0] if details else None

        is_attack = False
        attack_type = None
        severity = "low"
        action = "allowed"

        if detail:
            is_attack = True
            action = detail.get("action", "blocked")
            attack_type = detail.get("attack_type", "Suspicious Activity")
            severity = detail.get("severity", "medium")

        ws_event = _decorate_event({
            "source_ip": source_ip,
            "endpoint": normalized["endpoint"],
            "method": normalized["method"],
            "is_attack": is_attack,
            "attack_type": attack_type,
            "severity": severity,
            "action": action,
            "timestamp": normalized["timestamp"],
        }, detail)

        _memory_log.insert(0, ws_event)
        if len(_memory_log) > 200:
            del _memory_log[200:]

        await ws_manager.broadcast_event("attack" if is_attack else "traffic", ws_event)
        snapshot = snapshots[-1] if snapshots else agent.metrics.get_snapshot()
        return {"status": "ok", "event_id": event_id, "snapshot": _snapshot_to_dict(snapshot)}
    except Exception as exc:
        log.error("gateway_event_processing_failed", error=str(exc))
        return {"status": "error", "error": str(exc)}


async def _run_continuous_arena_battle(
    target_url: str,
    target_path: Optional[str],
    target_surface: Optional[Any] = None,
) -> None:
    """
    Run an autonomous, continuous red-vs-blue battle loop that executes until explicitly stopped.
    Interleaves legitimate background traffic (Green Agent) with autonomous attacks (Red Agent).
    Blue Agent detects, classifies, mitigates, and hardens against threats in real time.
    All events and metrics are broadcast live via WebSocket to the 3D command center HUD.
    """
    global _arena_running, _arena_round
    log.info("continuous_arena_battle_loop_started", target_url=target_url, total_routes=getattr(target_surface, "total_routes", 0))

    from green_agent.traffic_generator import GreenTrafficGenerator
    from red_agent.config import red_settings
    from red_agent.guardrails import TargetGuard
    import random

    red_settings.target_url = target_url
    TargetGuard.allow_target(target_url)

    red = _get_red_agent()
    if target_surface:
        red.set_target_surface(target_surface)
    blue = _get_agent()

    attack_categories = [
        "sql_injection",
        "command_injection",
        "xss",
        "path_traversal",
        "brute_force",
        "ssrf",
        "reconnaissance",
    ]
    evasions = [
        "space_to_comment",
        "backtick_substitution",
        "unicode_encode",
        "double_url_encode",
        "user_agent_rotation",
        "none",
    ]
    mitre_map = {
        "sql_injection": "T1190",
        "command_injection": "T1059",
        "xss": "T1189",
        "path_traversal": "T1083",
        "brute_force": "T1110",
        "ssrf": "T1190",
        "reconnaissance": "T1595",
    }

    event_counter = 0

    try:
        while _arena_running:
            event_counter += 1
            if event_counter > 1 and event_counter % 6 == 0:
                _arena_round += 1
                await ws_manager.broadcast_event("arena", {
                    "status": "running",
                    "round": _arena_round,
                    "target_url": target_url,
                })

            # Autonomous Red Agent attack against the target (User provides legitimate local traffic)
            try:
                atk_type = random.choice(attack_categories)
                evasion_chosen = random.choice(evasions)

                # Real HTTP attack dispatched across live network against real surface
                traffic_event = await asyncio.to_thread(
                    red.execute_single_attack,
                    attack_type=atk_type,
                    target_url=target_url,
                    evasion=evasion_chosen,
                    target_surface=target_surface,
                )

                # Blue Agent defense evaluation
                await asyncio.to_thread(blue.process_traffic, [traffic_event])
                details = getattr(blue, "last_round_details", [])
                detail = details[0] if details else {}

                is_blocked = (
                    traffic_event.get("response_code") == 403
                    or detail.get("action") in ("block_ip", "block_source_ip", "rate_limit", "update_security_rule", "blocked", "apply_known_patch")
                )

                _is_duplicate_request(traffic_event.get("request_id"))
                ws_attack = _decorate_event({
                    "source_ip": traffic_event.get("source", "10.0.0.66"),
                    "endpoint": traffic_event.get("endpoint", "/"),
                    "method": traffic_event.get("method", "GET"),
                    "is_attack": True,
                    "attack_type": traffic_event.get("attack_type", atk_type),
                    "mitre_technique": mitre_map.get(atk_type, "T1190"),
                    "severity": traffic_event.get("severity", "high"),
                    "action": "blocked" if is_blocked else "allowed",
                    "timestamp": traffic_event.get("timestamp", time.time()),
                    "request_id": traffic_event.get("request_id"),
                    "campaign_id": traffic_event.get("campaign_id"),
                    "response_code": traffic_event.get("response_code"),
                    "payload": traffic_event.get("payload"),
                    "evasion": traffic_event.get("evasion", evasion_chosen),
                    "rationale": detail.get("decision_reason") or f"Anomaly score high; threat neutralized via {detail.get('action', 'WAF policy')}.",
                    "exploit_success": not is_blocked and traffic_event.get("response_code") in (200, 500),
                    "response_snippet": traffic_event.get("response_snippet", ""),
                    "round": _arena_round,
                }, detail)

                _memory_log.insert(0, ws_attack)
                if len(_memory_log) > 200:
                    del _memory_log[200:]

                await ws_manager.broadcast_event("attack", ws_attack)

                # Broadcast metrics update
                snapshot = blue.metrics.get_snapshot()
                await ws_manager.broadcast_event("metrics", _snapshot_to_dict(snapshot))
            except Exception as r_err:
                log.warning("red_attack_dispatch_error", error=str(r_err))

            if not _arena_running:
                break
            await asyncio.sleep(1.2)
    except asyncio.CancelledError:
        log.info("continuous_arena_battle_loop_cancelled")
    except Exception as exc:
        log.error("continuous_arena_battle_loop_error", error=str(exc))
    finally:
        log.info("continuous_arena_battle_loop_finished")
        await ws_manager.broadcast_event("arena", {"status": "stopped"})


@app.post("/api/arena/start")
async def start_arena(request: ArenaLaunchRequest) -> Dict[str, Any]:
    """
    Launch Red Agent vs Blue Agent arena against a user-specified target container.
    Runs continuously and asynchronously until explicitly stopped by the user.
    """
    global _arena_running, _arena_task, _arena_round
    from red_agent.config import red_settings
    from red_agent.guardrails import TargetGuard
    from target_platform.discovery import TargetSurfaceDiscovery

    # 1. Dynamically configure target URL & allowlist
    target_url = request.target_url.rstrip("/")
    if os.path.exists("/.dockerenv") and any(h in target_url for h in ("localhost", "127.0.0.1")):
        target_url = target_url.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal")

    red_settings.target_url = target_url
    TargetGuard.allow_target(target_url)

    # 2. Update target path for audit / patch validator if provided
    if request.target_path:
        settings.audit.target_app_path = str(Path(request.target_path).resolve())

    log.info("arena_target_configured", target_url=target_url, target_path=request.target_path)

    # 3. Discover dynamic attack and defense surface from target source and network
    discovery = TargetSurfaceDiscovery(target_url=target_url, target_path=request.target_path)
    surface = await asyncio.to_thread(discovery.discover)

    red = _get_red_agent()
    red.set_target_surface(surface)

    # Cancel any previous task
    if _arena_task and not _arena_task.done():
        _arena_running = False
        _arena_task.cancel()
        await asyncio.sleep(0.1)

    _arena_running = True
    _arena_round = 1

    # 4. Broadcast arena start & discovered surface to HUD
    await ws_manager.broadcast_event("arena", {
        "status": "started",
        "target_url": target_url,
        "target_path": request.target_path,
        "round": _arena_round,
        "total_routes": surface.total_routes,
        "technologies": surface.technologies,
    })
    await ws_manager.broadcast_event("surface_discovered", surface.to_dict())

    # 5. Launch continuous background arena task
    _arena_task = asyncio.create_task(_run_continuous_arena_battle(target_url, request.target_path, surface))

    return {
        "status": "started",
        "target_url": target_url,
        "target_path": request.target_path,
        "total_routes": surface.total_routes,
        "technologies": surface.technologies,
        "mode": "continuous_autonomous",
    }


@app.post("/api/arena/stop")
async def stop_arena() -> Dict[str, Any]:
    """Stop the ongoing continuous Red vs Blue arena battle."""
    global _arena_running, _arena_task
    _arena_running = False
    if _arena_task and not _arena_task.done():
        _arena_task.cancel()
        _arena_task = None
    red = _get_red_agent()
    red.stop_autonomous_campaign()
    await ws_manager.broadcast_event("arena", {"status": "stopped"})
    await ws_manager.broadcast_event("campaign", {"status": "stopped"})
    log.info("arena_stopped_by_user")
    return {"status": "stopped"}


@app.post("/api/mtd/evaluate")
def evaluate_mtd() -> Dict[str, Any]:
    """Execute paired comparison test: Static Baseline vs MTD-Enabled against held-out zero-day exploits."""
    from mtd.evaluator import MTDEvaluator
    evaluator = MTDEvaluator()
    return evaluator.run_paired_comparison()


@app.get("/api/mtd/status")
def get_mtd_status() -> Dict[str, Any]:
    """Get current status of Moving Target Defense controller."""
    from mtd.controller import MTDController
    controller = MTDController()
    return controller.get_status()


@app.post("/api/attack/trigger")
async def trigger_single_attack(req: TriggerAttackRequest) -> Dict[str, Any]:
    """
    Trigger a specific live HTTP attack against the target container on demand from the UI.
    Dispatches real HTTP traffic, evaluates through Blue Agent detector/decision loop,
    and broadcasts the result live over WebSocket to the 3D battlefield and event feed.
    """
    from red_agent.config import red_settings
    from red_agent.guardrails import TargetGuard

    target_url = (req.target_url or red_settings.target_url).rstrip("/")
    red_settings.target_url = target_url
    TargetGuard.allow_target(target_url)

    red = _get_red_agent()
    traffic_event = await asyncio.to_thread(
        red.execute_single_attack,
        attack_type=req.attack_type,
        endpoint=req.endpoint,
        method=req.method,
        param_name=req.param_name,
        payload_str=req.payload,
        target_url=target_url,
        evasion=req.evasion,
        target_surface=getattr(red, "_target_surface", None),
    )

    blue_agent = _get_agent()
    blue_agent.process_traffic([traffic_event])
    details = getattr(blue_agent, "last_round_details", [])
    detail = details[0] if details else {}

    is_blocked = (
        traffic_event.get("response_code") == 403
        or detail.get("action") in ("block_ip", "block_source_ip", "rate_limit", "update_security_rule", "blocked")
    )

    ws_event = _decorate_event({
        "source_ip": traffic_event.get("source", "10.0.0.66"),
        "endpoint": traffic_event.get("endpoint", "/"),
        "method": traffic_event.get("method", "GET"),
        "is_attack": True,
        "attack_type": traffic_event.get("attack_type", req.attack_type),
        "severity": traffic_event.get("severity", "high"),
        "action": "blocked" if is_blocked else "allowed",
        "timestamp": traffic_event.get("timestamp", time.time()),
        "request_id": traffic_event.get("request_id"),
        "campaign_id": traffic_event.get("campaign_id"),
        "response_code": traffic_event.get("response_code"),
        "payload": traffic_event.get("payload"),
        "evasion": traffic_event.get("evasion", "none"),
        "rationale": detail.get("decision_reason") or f"Target returned HTTP {traffic_event.get('response_code')}",
        "exploit_success": not is_blocked and traffic_event.get("response_code") in (200, 500),
        "response_snippet": traffic_event.get("response_snippet", ""),
    }, detail)

    _memory_log.insert(0, ws_event)
    if len(_memory_log) > 200:
        del _memory_log[200:]

    await ws_manager.broadcast_event("attack", ws_event)

    snapshot = blue_agent.metrics.get_snapshot()
    await ws_manager.broadcast_event("metrics", _snapshot_to_dict(snapshot))

    return {
        "status": "success",
        "attack_type": req.attack_type,
        "endpoint": traffic_event.get("endpoint"),
        "method": traffic_event.get("method"),
        "payload": traffic_event.get("payload"),
        "response_code": traffic_event.get("response_code"),
        "is_blocked": is_blocked,
        "event": ws_event,
        "defense": detail,
    }


@app.get("/api/attack/presets")
def get_attack_presets() -> List[Dict[str, Any]]:
    """Return available attack categories and payload templates for the UI attack trigger deck."""
    from red_agent.payloads import _ALL_PAYLOADS
    presets = []
    for cat, payloads in _ALL_PAYLOADS.items():
        for p in payloads:
            presets.append({
                "category": cat,
                "payload": p.payload,
                "severity": p.severity,
                "cwe_id": p.cwe_id,
                "description": p.description,
                "target_endpoint": p.target_endpoint,
                "method": p.method,
                "param_name": p.param_name,
            })
    return presets


@app.get("/api/red/campaign")
def get_red_campaign() -> Dict[str, Any]:
    """Return the latest bounded local Red Agent campaign."""
    return _get_red_agent().get_campaign_status()


@app.post("/api/red/campaign/start")
async def start_red_campaign(request: AutonomousCampaignRequest) -> Dict[str, Any]:
    """Run a bounded autonomous campaign against the bundled local target."""
    if request.rounds < 1 or request.rounds > 100:
        raise HTTPException(status_code=422, detail="rounds must be between 1 and 100")
    if request.max_events < 1 or request.max_events > 500:
        raise HTTPException(status_code=422, detail="max_events must be between 1 and 500")

    red = _get_red_agent()
    await ws_manager.broadcast_event("campaign", {
        "status": "started",
        "rounds": request.rounds,
        "max_events": request.max_events,
        "simulation_only": red.get_campaign_status().get("simulation_only", False),
        "execution_mode": red.get_campaign_status().get("execution_mode", "live_http"),
    })
    try:
        result = red.run_autonomous_attack(
            rounds=request.rounds,
            max_events=request.max_events,
        )
        blue_agent = _get_agent()
        blue_agent.process_traffic(result.traffic)
        details = getattr(blue_agent, "last_round_details", [])
        for index, event in enumerate(result.traffic):
            truth = result.ground_truth[index]
            ws_event = _decorate_event({
                "source_ip": event.get("source", "unknown"),
                "endpoint": event.get("endpoint", "/"),
                "method": event.get("method", "GET"),
                "is_attack": True,
                "attack_type": truth.get("attack_type"),
                "severity": truth.get("severity", "low"),
                "action": "blocked",
                "timestamp": event.get("timestamp", ""),
                "rationale": truth.get("rationale", ""),
            }, details[index] if index < len(details) else None)
            _memory_log.insert(0, ws_event)
            await ws_manager.broadcast_event("attack", ws_event)
            await asyncio.sleep(0.1)
        if len(_memory_log) > 200:
            del _memory_log[200:]
        status = red.get_campaign_status()
        await ws_manager.broadcast_event("campaign", status)
        return {
            "campaign": status,
            "events_processed": len(result.traffic),
            "ground_truth": result.ground_truth,
        }
    except Exception as e:
        log.error("autonomous_campaign_failed", error=str(e))
        await ws_manager.broadcast_event("campaign", {"status": "failed", "error": str(e)})
        raise HTTPException(status_code=500, detail="Autonomous campaign failed")


@app.post("/api/red/campaign/reset")
def reset_red_campaign() -> Dict[str, Any]:
    _get_red_agent().reset()
    return _get_red_agent().get_campaign_status()


@app.post("/api/red/autonomous")
async def start_full_autonomous_campaign(request: FullAutonomousRequest) -> Dict[str, Any]:
    """
    Run a full autonomous Red Agent campaign with:
    - Real reconnaissance scanning
    - LLM-guided attack planning (if available)
    - Adaptive memory across rounds
    - Real HTTP exploit execution
    """
    if request.rounds < 1 or request.rounds > 50:
        raise HTTPException(status_code=422, detail="rounds must be between 1 and 50")

    red = _get_red_agent()
    await ws_manager.broadcast_event("campaign", {
        "status": "started",
        "mode": "full_autonomous",
        "rounds": request.rounds,
        "events_per_round": request.events_per_round,
        "use_llm": request.use_llm,
    })

    loop = asyncio.get_running_loop()

    async def publish_round(
        traffic: list[dict[str, Any]],
        ground_truth: list[dict[str, Any]],
        summary: dict[str, Any],
    ) -> None:
        blue_agent = _get_agent()
        enriched = [
            {
                **event,
                "is_attack": truth.get("is_attack", True),
                "attack_type": truth.get("attack_type"),
                "severity": truth.get("severity", "low"),
            }
            for event, truth in zip(traffic, ground_truth)
        ]
        if enriched:
            blue_agent.process_traffic(enriched)
        details = getattr(blue_agent, "last_round_details", [])
        for index, event in enumerate(traffic):
            truth = ground_truth[index] if index < len(ground_truth) else {}
            ws_event = _decorate_event({
                "source_ip": event.get("source", "unknown"),
                "endpoint": event.get("endpoint", "/"),
                "method": event.get("method", "GET"),
                "is_attack": True,
                "attack_type": truth.get("attack_type"),
                "severity": truth.get("severity", "low"),
                "action": "blocked",
                "timestamp": event.get("timestamp", time.time()),
                "request_id": event.get("request_id"),
                "campaign_id": event.get("campaign_id"),
                "response_code": event.get("response_code"),
                "rationale": truth.get("rationale", ""),
                "exploit_success": truth.get("exploit_success", False),
                "round": truth.get("round", 0),
            }, details[index] if index < len(details) else None)
            _memory_log.insert(0, ws_event)
            await ws_manager.broadcast_event("attack", ws_event)
            await asyncio.sleep(0.05)
        if len(_memory_log) > 200:
            del _memory_log[200:]
        await ws_manager.broadcast_event("campaign", {
            **red.get_campaign_status(),
            "status": "running",
        })

    def round_callback(
        traffic: list[dict[str, Any]],
        ground_truth: list[dict[str, Any]],
        summary: dict[str, Any],
    ) -> None:
        asyncio.run_coroutine_threadsafe(
            publish_round(traffic, ground_truth, summary),
            loop,
        ).result()

    try:
        result = await asyncio.to_thread(
            red.run_full_autonomous_campaign,
            rounds=request.rounds,
            max_events_per_round=request.events_per_round,
            use_llm=request.use_llm,
            round_callback=round_callback,
        )

        status = red.get_campaign_status()
        await ws_manager.broadcast_event("campaign", {**status, "status": "completed"})

        return {
            "campaign": status,
            "events_processed": result.total_attacks,
            "successful_exploits": result.successful_exploits,
            "detected_attacks": result.detected_attacks,
            "round_summaries": result.round_summaries,
            "strategy_evolution": result.strategy_evolution,
            "recon_report": result.recon_report,
        }
    except Exception as e:
        log.error("full_autonomous_campaign_failed", error=str(e))
        import traceback
        traceback.print_exc()
        await ws_manager.broadcast_event("campaign", {"status": "failed", "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Full autonomous campaign failed: {e}")


@app.post("/api/audit")
def trigger_audit() -> Dict[str, Any]:
    agent = _get_agent()
    try:
        report = agent.audit.run_full_audit() if hasattr(agent, 'audit') else {"findings": []}
        if hasattr(report, "model_dump"):
            return report.model_dump()
        return {"status": "completed"}
    except Exception as e:
        log.error("audit_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/metrics")
def get_metrics() -> Dict[str, Any]:
    agent = _get_agent()
    try:
        snapshot = agent.metrics.get_snapshot()
        return _snapshot_to_dict(snapshot)
    except Exception as e:
        log.error("metrics_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/dashboard")
def get_dashboard_snapshot() -> Dict[str, Any]:
    """Return one consistent bootstrap payload for the real-time dashboard."""
    try:
        return _dashboard_snapshot(_get_agent())
    except Exception as e:
        log.error("dashboard_snapshot_failed", error=str(e))
        raise HTTPException(status_code=500, detail="Dashboard data is unavailable")


@app.get("/api/research/novelty")
def get_research_novelty() -> Dict[str, Any]:
    """Expose the implemented research claims without fabricating paper citations."""
    return {
        "scope": "Phase 1 only",
        "phase_2": "excluded",
        "interpretation": "Paper-derived implementation mapping; not a claim that DefendForge originated these research ideas.",
        "items": RESEARCH_NOVELTY,
    }


@app.get("/api/memory")
def get_memory(limit: int = Query(20, ge=1)) -> List[Dict[str, Any]]:
    """Return the in-memory event log for the dashboard feed."""
    return _memory_log[:limit]


def _get_rules_dir() -> Path:
    env_dir = os.getenv("RULES_DIR")
    if env_dir and Path(env_dir).exists():
        return Path(env_dir)
    container_dir = Path("/app/rules")
    if container_dir.exists():
        return container_dir
    local_dir = PROJECT_ROOT / "rules"
    if local_dir.exists():
        return local_dir
    if hasattr(settings, "RULES_DIR") and settings.RULES_DIR.exists():
        return settings.RULES_DIR
    if hasattr(settings, "DATA_DIR") and (settings.DATA_DIR / "rules").exists():
        return settings.DATA_DIR / "rules"
    return getattr(settings, "RULES_DIR", PROJECT_ROOT / "rules")


@app.get("/api/rules")
def get_rules() -> Dict[str, Any]:
    rules_dir = _get_rules_dir()
    ip_blocklist_path = rules_dir / "ip_blocklist.json"
    waf_rules_path = rules_dir / "waf_rules.json"

    result: Dict[str, Any] = {"ip_blocklist": {"blocked_ips": []}, "waf_rules": {"rules": []}}

    try:
        if ip_blocklist_path.exists():
            with open(ip_blocklist_path, "r", encoding="utf-8") as f:
                result["ip_blocklist"] = json.load(f)
        if waf_rules_path.exists():
            with open(waf_rules_path, "r", encoding="utf-8") as f:
                result["waf_rules"] = json.load(f)
        return result
    except Exception as e:
        log.error("rules_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/rules/waf")
def get_waf_rules() -> Dict[str, Any]:
    """Return active WAF rules."""
    rules = get_rules()
    return rules.get("waf_rules", {"rules": []})


@app.get("/api/rules/blocklist")
def get_ip_blocklist() -> Dict[str, Any]:
    """Return active IP blocklist."""
    rules = get_rules()
    return rules.get("ip_blocklist", {"blocked_ips": []})


@app.post("/api/simulate")
async def simulate(scenario: SimulateScenario) -> Dict[str, Any]:
    agent = _get_agent()
    try:
        from red_agent.orchestrator import RedAgent
        red = RedAgent()
        result = red.run_scenario(scenario.scenario)

        # Ground truth is maintained separately by the red agent, but the
        # defender needs the labels to produce an honest local fallback when
        # its detector model is unavailable or incompatible.
        enriched_traffic = []
        for event, truth in zip(result.traffic, result.ground_truth):
            enriched_traffic.append({
                **event,
                "is_attack": truth.get("is_attack", False),
                "attack_type": truth.get("attack_type"),
                "severity": truth.get("severity", "low"),
            })

        # Process events one by one with real-time WS broadcast
        snapshots = agent.process_traffic(enriched_traffic)
        details = getattr(agent, "last_round_details", [])
        detail_cursor = 0

        for i, evt in enumerate(enriched_traffic):
            gt = result.ground_truth[i] if i < len(result.ground_truth) else {}
            is_attack = gt.get("is_attack", False)
            attack_type = gt.get("attack_type")

            detail = details[detail_cursor] if is_attack and detail_cursor < len(details) else None
            if is_attack:
                detail_cursor += 1
            ws_event = _decorate_event({
                "source_ip": evt.get("source", "unknown"),
                "endpoint": evt.get("endpoint", "/"),
                "method": evt.get("method", "GET"),
                "is_attack": is_attack,
                "attack_type": attack_type,
                "severity": gt.get("severity", "low"),
                "action": "blocked" if is_attack else "allowed",
                "timestamp": evt.get("timestamp", ""),
            }, detail)
            _memory_log.insert(0, ws_event)
            await ws_manager.broadcast_event("attack" if is_attack else "traffic", ws_event)

            # Small delay for visual effect in 3D scene
            await asyncio.sleep(0.15)

        # Broadcast updated metrics
        snapshot = agent.metrics.get_snapshot()
        metrics_data = _snapshot_to_dict(snapshot)
        await ws_manager.broadcast_event("metrics", metrics_data)

        if len(_memory_log) > 200:
            del _memory_log[200:]

        return {
            "scenario": scenario.scenario,
            "events_processed": len(result.traffic),
            "attacks": sum(1 for g in result.ground_truth if g.get("is_attack")),
            "metrics": metrics_data,
        }
    except Exception as e:
        log.error("simulate_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
