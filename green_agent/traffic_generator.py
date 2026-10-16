"""
Green Agent — Background Legitimate Traffic Generator.

Dispatches realistic legitimate background user traffic to the target application,
providing the background signal against which the Blue Agent's detection must
distinguish adversarial Red Agent activity from normal operations.
"""
from __future__ import annotations

import asyncio
import os
import random
import time
import uuid
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import httpx

from blue_agent.logging_cfg import get_logger
from green_agent.config import green_settings
from green_agent.user_personas import UserPersona, create_random_persona

log = get_logger("green_agent.traffic")


class GreenTrafficGenerator:
    """
    Simulates ongoing legitimate user activity against the target application.
    """

    def __init__(
        self,
        target_url: Optional[str] = None,
        timeout: float = 4.0,
        concurrency: int = 2,
        target_surface: Optional[Any] = None,
    ):
        self.target_url = (target_url or green_settings.target_url).rstrip("/")
        self.timeout = timeout
        self.concurrency = concurrency
        self.target_surface = target_surface
        self._personas: List[UserPersona] = [create_random_persona() for _ in range(concurrency * 2)]
        self._is_running = False
        self._task: Optional[asyncio.Task] = None
        self._event_callback: Optional[Callable[[Dict[str, Any]], None]] = None

        # Statistics
        self.total_requests: int = 0
        self.successful_requests: int = 0
        self.blocked_requests: int = 0       # HTTP 403 (False Positive block!)
        self.errored_requests: int = 0        # HTTP 500
        self.latencies_ms: List[float] = []

    def set_target_surface(self, surface: Any) -> None:
        """Register the dynamic target surface for benign user traffic."""
        self.target_surface = surface
        log.info("green_agent_target_surface_registered", total_routes=getattr(surface, "total_routes", 0))

    def set_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback for each generated traffic event."""
        self._event_callback = callback

    def _resolve_benign_endpoint(self) -> tuple[str, str, dict]:
        """Select a benign endpoint from the active target surface or fallback to persona action."""
        if self.target_surface and hasattr(self.target_surface, "get_benign_endpoints"):
            benign_eps = self.target_surface.get_benign_endpoints()
            if benign_eps:
                chosen = random.choice(benign_eps)
                path = chosen.path
                params = {}
                # Populate common harmless parameters if required
                for p in chosen.parameters:
                    if "user" in p.lower() or "id" in p.lower():
                        params[p] = f"user_{random.randint(100, 999)}"
                    elif "page" in p.lower():
                        params[p] = "1"
                    elif "limit" in p.lower():
                        params[p] = "20"
                return chosen.method, path, params

        persona = random.choice(self._personas)
        action = persona.next_action()
        return action.method, action.endpoint, action.params or {}

    def generate_single_event(self) -> Dict[str, Any]:
        """
        Generate a single normalized benign event dict, executing real HTTP if reachable.
        """
        persona = random.choice(self._personas)
        method, endpoint, params = self._resolve_benign_endpoint()
        self.total_requests += 1

        status_code = 200
        latency_ms = random.uniform(8.0, 35.0)
        body_size = random.randint(120, 2048)
        req_id = str(uuid.uuid4())

        req_headers = dict(persona.headers)
        req_headers["x-request-id"] = req_id
        req_headers["x-defendforge-agent"] = "user"

        # Attempt quick real HTTP request to verify live target behavior if not in simulation mode
        if os.getenv("RED_SIMULATION_ONLY") != "true":
            try:
                full_url = urljoin(self.target_url + "/", endpoint.lstrip("/"))
                t0 = time.perf_counter()
                with httpx.Client(timeout=1.0, verify=False) as client:
                    if method == "POST":
                        resp = client.post(full_url, json=params or None, headers=req_headers)
                    else:
                        resp = client.get(full_url, params=params or None, headers=req_headers)
                    status_code = resp.status_code
                    body_size = len(resp.content)
                latency_ms = (time.perf_counter() - t0) * 1000
            except Exception:
                # If target offline or unreachable, fall back to simulated latency
                pass

        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > 500:
            self.latencies_ms.pop(0)

        is_blocked = status_code == 403
        if is_blocked:
            self.blocked_requests += 1
        elif status_code in (200, 201, 204, 301, 302):
            self.successful_requests += 1
        else:
            self.errored_requests += 1

        event = {
            "source": persona.source_ip,
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "data": {},
            "headers": req_headers,
            "is_attack": False,
            "attack_type": None,
            "source_kind": "green_agent",
            "user_agent": persona.user_agent,
            "timestamp": time.time(),
            "request_id": req_id,
            "event_id": req_id,
            "response_code": status_code,
            "response_time_ms": round(latency_ms, 2),
            "body_size": body_size,
        }
        return event

    def generate_batch(self, count: int) -> List[Dict[str, Any]]:
        """Generate a batch of normalized benign user events."""
        return [self.generate_single_event() for _ in range(count)]

    async def send_live_request(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """
        Execute a real HTTP request against the target container.
        """
        persona = random.choice(self._personas)
        method, endpoint, params = self._resolve_benign_endpoint()
        full_url = urljoin(self.target_url + "/", endpoint.lstrip("/"))

        self.total_requests += 1
        t0 = time.perf_counter()
        status_code = 0
        response_size = 0
        error_msg = ""

        try:
            if method == "POST":
                resp = await client.post(
                    full_url,
                    json=params or None,
                    headers=persona.headers,
                    timeout=self.timeout,
                )
            else:
                resp = await client.get(
                    full_url,
                    params=params or None,
                    headers=persona.headers,
                    timeout=self.timeout,
                )
            status_code = resp.status_code
            response_size = len(resp.content)
        except Exception as exc:
            error_msg = str(exc)
            status_code = 0

        latency_ms = (time.perf_counter() - t0) * 1000
        self.latencies_ms.append(latency_ms)
        if len(self.latencies_ms) > 500:
            self.latencies_ms.pop(0)

        # Classify result
        is_blocked = status_code == 403
        if is_blocked:
            self.blocked_requests += 1
            log.warning("green_user_blocked_false_positive",
                        endpoint=action.endpoint,
                        source_ip=persona.source_ip,
                        action=action.description)
        elif status_code in (200, 302, 404):
            self.successful_requests += 1
        else:
            self.errored_requests += 1

        event_data = {
            "source": persona.source_ip,
            "endpoint": action.endpoint,
            "method": action.method,
            "params": action.params,
            "data": action.data,
            "headers": action.headers,
            "is_attack": False,
            "attack_type": None,
            "source_kind": "green_agent",
            "user_agent": persona.user_agent,
            "timestamp": time.time(),
            "response_code": status_code,
            "response_time_ms": round(latency_ms, 2),
            "body_size": response_size,
            "is_blocked": is_blocked,
            "error": error_msg,
        }

        if self._event_callback:
            try:
                self._event_callback(event_data)
            except Exception as e:
                log.error("green_callback_failed", error=str(e))

        return event_data

    async def start_background_loop(self, interval: float = 1.0) -> None:
        """Start continuous asynchronous background traffic dispatch."""
        if self._is_running:
            return
        self._is_running = True

        async def _loop():
            log.info("green_agent_background_loop_started", target=self.target_url)
            async with httpx.AsyncClient(follow_redirects=True) as client:
                while self._is_running:
                    try:
                        await self.send_live_request(client)
                    except Exception as e:
                        log.debug("green_traffic_dispatch_exception", error=str(e))
                    await asyncio.sleep(interval + random.uniform(-0.2, 0.4))
            log.info("green_agent_background_loop_stopped")

        self._task = asyncio.create_task(_loop())

    def stop_background_loop(self) -> None:
        """Stop background traffic dispatch."""
        self._is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None

    def get_service_disruption_metrics(self) -> Dict[str, Any]:
        """
        Calculate metrics assessing whether the Blue Agent's defenses
        disrupted legitimate service operations.
        """
        total = self.total_requests or 1
        false_positive_block_rate = self.blocked_requests / total
        availability_rate = self.successful_requests / total
        avg_latency = (sum(self.latencies_ms) / len(self.latencies_ms)) if self.latencies_ms else 0.0

        return {
            "total_legitimate_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "blocked_requests": self.blocked_requests,
            "errored_requests": self.errored_requests,
            "false_positive_block_rate": round(false_positive_block_rate, 4),
            "availability_rate": round(availability_rate, 4),
            "avg_latency_ms": round(avg_latency, 2),
            "service_disrupted": self.blocked_requests > 0,
        }

    def reset(self) -> None:
        """Reset counters."""
        self.total_requests = 0
        self.successful_requests = 0
        self.blocked_requests = 0
        self.errored_requests = 0
        self.latencies_ms.clear()
