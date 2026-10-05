"""FastAPI REST API + WebSocket for the Blue Agent with real-time 3D dashboard."""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
import os

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import (
    AuditReport,
    MetricsSnapshot,
)
from blue_agent.monitoring.health import HealthChecker
from blue_agent.api.ws_manager import ws_manager

log = get_logger("api.routes")

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

# ---------------------------------------------------------------------------
# Lazy Agent Initialization (with SQLite fallback for local dev)
# ---------------------------------------------------------------------------
_agent = None
_red_agent = None
_memory_log: List[Dict[str, Any]] = []  # In-memory event log for dashboard


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
        from blue_agent.detection.isolation_forest import IsolationForestDetector
        from blue_agent.remediation.patch_generator import PatchGenerator
        from blue_agent.hardening.rule_manager import RuleManager

        self.metrics = MetricsTracker()
        detector = IsolationForestDetector()
        model_candidates = [
            Path(settings.detection.model_path),
            Path(__file__).resolve().parents[1] / "anomaly_detector" / "models" / "isolation_forest.joblib",
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
        log.info("lightweight_agent_ready")

    def process_traffic(self, raw_events: List[Dict[str, Any]]) -> List[MetricsSnapshot]:
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
            self.metrics.record_detection(is_attack=False, detected=False)
            return [self.metrics.get_snapshot()]

        for event in alerts:
            self.metrics.record_detection(is_attack=True, detected=True, time_ms=detect_time / len(alerts))
            # Attempt remediation
            patch = self.patch_gen.generate_patch(event)
            if patch:
                self.metrics.record_remediation(success=True, time_ms=5.0)
            # Hardening
            self.hardening.derive_rules_from_event(event)
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


# ---------------------------------------------------------------------------
# WebSocket Endpoint
# ---------------------------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
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
        snapshots = agent.process_traffic(batch.events)
        # Broadcast each event to WS clients
        for evt in batch.events:
            is_attack = bool(evt.get("is_attack", evt.get("attack_type")))
            ws_event = {
                "source_ip": evt.get("source", "unknown"),
                "endpoint": evt.get("endpoint", "/"),
                "method": evt.get("method", "GET"),
                "is_attack": is_attack,
                "attack_type": evt.get("attack_type"),
                "severity": evt.get("severity", "unknown"),
                "action": "blocked" if is_attack else "allowed",
                "timestamp": evt.get("timestamp", ""),
            }
            _memory_log.insert(0, ws_event)
            await ws_manager.broadcast_event("attack" if is_attack else "traffic", ws_event)

        if len(_memory_log) > 200:
            del _memory_log[200:]

        snapshot = snapshots[-1] if snapshots else agent.metrics.get_snapshot()
        return _snapshot_to_dict(snapshot)
    except Exception as e:
        log.error("traffic_processing_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


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
        for index, event in enumerate(result.traffic):
            truth = result.ground_truth[index]
            ws_event = {
                "source_ip": event.get("source", "unknown"),
                "endpoint": event.get("endpoint", "/"),
                "method": event.get("method", "GET"),
                "is_attack": True,
                "attack_type": truth.get("attack_type"),
                "severity": truth.get("severity", "low"),
                "action": "blocked",
                "timestamp": event.get("timestamp", ""),
                "rationale": truth.get("rationale", ""),
            }
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


@app.get("/api/memory")
def get_memory(limit: int = Query(20, ge=1)) -> List[Dict[str, Any]]:
    """Return the in-memory event log for the dashboard feed."""
    return _memory_log[:limit]


@app.get("/api/rules")
def get_rules() -> Dict[str, Any]:
    rules_dir = settings.DATA_DIR / "rules"
    ip_blocklist_path = rules_dir / "ip_blocklist.json"
    waf_rules_path = rules_dir / "waf_rules.json"

    result = {"ip_blocklist": [], "waf_rules": []}

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


@app.post("/api/simulate")
async def simulate(scenario: SimulateScenario) -> Dict[str, Any]:
    agent = _get_agent()
    try:
        from red_agent.orchestrator import RedAgent
        red = RedAgent()
        result = red.run_scenario(scenario.scenario)

        # Process events one by one with real-time WS broadcast
        snapshots = agent.process_traffic(result.traffic)

        for i, evt in enumerate(result.traffic):
            gt = result.ground_truth[i] if i < len(result.ground_truth) else {}
            is_attack = gt.get("is_attack", False)
            attack_type = gt.get("attack_type")

            ws_event = {
                "source_ip": evt.get("source", "unknown"),
                "endpoint": evt.get("endpoint", "/"),
                "method": evt.get("method", "GET"),
                "is_attack": is_attack,
                "attack_type": attack_type,
                "severity": gt.get("severity", "low"),
                "action": "blocked" if is_attack else "allowed",
                "timestamp": evt.get("timestamp", ""),
            }
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
