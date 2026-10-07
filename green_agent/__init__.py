"""
Green Agent — Legitimate Traffic Generator.

Generates realistic normal user activity so that the Blue Agent's
anomaly detection must distinguish between:
  - Red Agent attack traffic
  - Green Agent legitimate traffic

This prevents the detector from trivially flagging all traffic as attacks
and forces it to learn real attack signatures vs normal behavior.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from blue_agent.logging_cfg import get_logger

log = get_logger("green.agent")


@dataclass
class GreenTrafficConfig:
    """Configuration for green traffic generation."""
    target_url: str = "http://target_app:5000"
    requests_per_second: float = 2.0
    session_duration_seconds: float = 30.0
    num_simulated_users: int = 3
    seed: int = 42


class GreenAgent:
    """
    Simulates legitimate user behavior against the target application.

    Performs normal operations like:
    - Browsing pages
    - Searching for content
    - Logging in with valid credentials
    - Creating posts and comments
    - Viewing admin pages (as admin)
    """

    NORMAL_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    ]

    BENIGN_SEARCH_TERMS = [
        "hello", "world", "python", "flask", "web",
        "security", "news", "article", "tutorial", "update",
    ]

    BENIGN_NAMES = [
        "Alice", "Bob", "Charlie", "Diana", "Eve",
        "Frank", "Grace", "Henry", "Ivy", "Jack",
    ]

    def __init__(self, config: GreenTrafficConfig | None = None):
        self.config = config or GreenTrafficConfig()
        self.rng = random.Random(self.config.seed)
        self._traffic_log: list[dict[str, Any]] = []

    def generate_traffic_batch(self, count: int = 10) -> list[dict[str, Any]]:
        """Generate a batch of normal traffic events (simulation mode)."""
        events = []
        for _ in range(count):
            event = self._generate_single_event()
            events.append(event)
            self._traffic_log.append(event)
        return events

    def run_live_traffic(
        self,
        duration_seconds: float = 30.0,
        target_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Send real legitimate HTTP requests to the target application.
        Returns the traffic events generated.
        """
        url = target_url or self.config.target_url
        events: list[dict[str, Any]] = []
        end_time = time.time() + duration_seconds
        delay = 1.0 / max(0.1, self.config.requests_per_second)

        log.info("green_agent_live_traffic_start",
                 target=url,
                 duration=duration_seconds,
                 rps=self.config.requests_per_second)

        try:
            with httpx.Client(base_url=url, timeout=5.0) as client:
                while time.time() < end_time:
                    event = self._send_live_request(client)
                    if event:
                        events.append(event)
                        self._traffic_log.append(event)
                    time.sleep(delay)
        except Exception as e:
            log.warning("green_agent_live_traffic_error", error=str(e))

        log.info("green_agent_live_traffic_complete", events=len(events))
        return events

    def _send_live_request(self, client: httpx.Client) -> dict[str, Any] | None:
        """Send one legitimate request to the target."""
        action = self.rng.choice([
            "browse", "browse", "browse",  # Most common
            "search",
            "greet",
            "health",
            "list_posts",
        ])

        try:
            if action == "browse":
                path = self.rng.choice(["/", "/health", "/posts"])
                resp = client.get(path)
            elif action == "search":
                term = self.rng.choice(self.BENIGN_SEARCH_TERMS)
                resp = client.get("/search", params={"q": term})
                path = f"/search?q={term}"
            elif action == "greet":
                name = self.rng.choice(self.BENIGN_NAMES)
                resp = client.get("/greet", params={"name": name})
                path = f"/greet?name={name}"
            elif action == "health":
                resp = client.get("/health")
                path = "/health"
            elif action == "list_posts":
                resp = client.get("/posts")
                path = "/posts"
            else:
                return None

            return {
                "source": f"192.168.1.{self.rng.randint(100, 200)}",
                "endpoint": path.split("?")[0],
                "method": "GET",
                "params": {},
                "response_code": resp.status_code,
                "response_time_ms": resp.elapsed.total_seconds() * 1000 if resp.elapsed else 0,
                "body_size": len(resp.content),
                "user_agent": self.rng.choice(self.NORMAL_USER_AGENTS),
                "destination": "target_app",
                "is_attack": False,
                "attack_type": None,
                "timestamp": time.time(),
            }
        except httpx.HTTPError as e:
            log.debug("green_agent_request_failed", error=str(e))
            return None

    def _generate_single_event(self) -> dict[str, Any]:
        """Generate a single simulated normal traffic event."""
        action = self.rng.choice([
            "browse", "browse", "browse",
            "search", "greet", "health", "list_posts",
        ])

        if action == "browse":
            endpoint = self.rng.choice(["/", "/about", "/health", "/posts", "/contact"])
            method = "GET"
            params = {}
        elif action == "search":
            endpoint = "/search"
            method = "GET"
            params = {"q": self.rng.choice(self.BENIGN_SEARCH_TERMS)}
        elif action == "greet":
            endpoint = "/greet"
            method = "GET"
            params = {"name": self.rng.choice(self.BENIGN_NAMES)}
        elif action == "health":
            endpoint = "/health"
            method = "GET"
            params = {}
        elif action == "list_posts":
            endpoint = "/posts"
            method = "GET"
            params = {}
        else:
            endpoint = "/"
            method = "GET"
            params = {}

        return {
            "source": f"192.168.1.{self.rng.randint(100, 200)}",
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "response_code": 200,
            "response_time_ms": self.rng.randint(10, 80),
            "body_size": self.rng.randint(200, 3000),
            "user_agent": self.rng.choice(self.NORMAL_USER_AGENTS),
            "destination": "target_app",
            "is_attack": False,
            "attack_type": None,
            "timestamp": time.time(),
        }

    def get_traffic_log(self) -> list[dict[str, Any]]:
        return self._traffic_log.copy()

    def reset(self):
        self._traffic_log.clear()
