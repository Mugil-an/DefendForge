"""
Phase 2 — Self-Evolving Moving Target Defense (MTD) Controller.

Applies continuous, proactive surface reconfigurations:
  1. Port Rotation (dynamic exposed service ports)
  2. Route / Endpoint Scrambling (ephemeral routing aliases + honeypot decoys)
  3. Header & Banner Deception (anti-fingerprinting server headers)
  4. Topology & Upstream Shuffling

Seeds its reconfiguration policy from Phase 1 historical telemetry so proactive
defense focuses on the surfaces that saw the highest attacker activity.
"""
from __future__ import annotations

import hashlib
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from blue_agent.logging_cfg import get_logger

log = get_logger("mtd.controller")


@dataclass
class ReconfigurationRecord:
    reconfig_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    action_type: str = ""  # "port_rotation", "route_scramble", "header_deception", "topology_shuffle"
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class MTDController:
    """
    Moving Target Defense engine managing continuous proactive surface reconfigurations.
    """

    def __init__(self, is_enabled: bool = False):
        self.is_enabled: bool = is_enabled
        self.current_port: int = 8080
        self.port_pool: List[int] = [8080, 8081, 8082, 8083, 8084, 8085]
        self.active_route_aliases: Dict[str, str] = {}  # original_path -> scrambled_path
        self.decoy_routes: Set[str] = set()
        self.server_banner: str = "nginx/1.24.0"
        self.server_banners_pool: List[str] = [
            "Apache/2.4.57 (Unix)", "nginx/1.24.0", "Cloudflare", "Microsoft-IIS/10.0", "openresty/1.21.4.1"
        ]
        self.reconfiguration_history: List[ReconfigurationRecord] = []
        self.mined_vulnerable_surfaces: List[str] = []

    def enable(self) -> None:
        """Enable active Moving Target Defense."""
        self.is_enabled = True
        log.info("mtd_controller_enabled")
        self.execute_proactive_reconfiguration()

    def disable(self) -> None:
        """Disable Moving Target Defense (revert to static baseline)."""
        self.is_enabled = False
        self.active_route_aliases.clear()
        self.decoy_routes.clear()
        self.current_port = 8080
        self.server_banner = "Werkzeug/2.2.2 Python/3.11"
        log.info("mtd_controller_disabled_reverted_to_static_baseline")

    def seed_from_phase1_history(self, attack_records: List[Dict[str, Any]]) -> None:
        """
        Mine Phase 1 round history to seed MTD policy.
        Identifies the endpoints and techniques with the highest attack volume
        so proactive scrambling prioritizes actively targeted assets.
        """
        endpoint_counts: Dict[str, int] = {}
        for rec in attack_records:
            ep = rec.get("endpoint") or "/"
            endpoint_counts[ep] = endpoint_counts.get(ep, 0) + 1

        # Sort by attack frequency
        sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
        self.mined_vulnerable_surfaces = [ep for ep, _ in sorted_endpoints]
        log.info("mtd_seeded_from_phase1", prioritized_surfaces=self.mined_vulnerable_surfaces)

    def rotate_port(self) -> int:
        """Rotate the exposed communication port."""
        available = [p for p in self.port_pool if p != self.current_port]
        self.current_port = random.choice(available)
        record = ReconfigurationRecord(
            action_type="port_rotation",
            details={"active_port": self.current_port},
        )
        self.reconfiguration_history.append(record)
        log.info("mtd_port_rotated", new_port=self.current_port)
        return self.current_port

    def scramble_routes(self, surfaces_to_scramble: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Create ephemeral routing aliases for sensitive endpoints and set up honeypot decoys.
        """
        surfaces = surfaces_to_scramble or self.mined_vulnerable_surfaces or [
            "/login", "/file", "/ping", "/search", "/admin", "/fetch"
        ]
        new_aliases: Dict[str, str] = {}
        new_decoys: Set[str] = set()

        for path in surfaces:
            token = hashlib.sha256(f"{path}:{time.time()}:{random.random()}".encode()).hexdigest()[:10]
            base = path.strip("/")
            alias = f"/{base}_{token}"
            new_aliases[path] = alias
            # The original static path becomes an instrumented honeypot decoy
            new_decoys.add(path)

        self.active_route_aliases = new_aliases
        self.decoy_routes = new_decoys

        record = ReconfigurationRecord(
            action_type="route_scramble",
            details={"aliases_count": len(new_aliases), "decoys": list(new_decoys)},
        )
        self.reconfiguration_history.append(record)
        log.info("mtd_routes_scrambled", aliases_count=len(new_aliases))
        return self.active_route_aliases

    def randomize_headers(self) -> str:
        """Rotate server identity banners to defeat OS/framework fingerprinting."""
        self.server_banner = random.choice(self.server_banners_pool)
        record = ReconfigurationRecord(
            action_type="header_deception",
            details={"banner": self.server_banner},
        )
        self.reconfiguration_history.append(record)
        log.info("mtd_headers_randomized", banner=self.server_banner)
        return self.server_banner

    def execute_proactive_reconfiguration(self) -> Dict[str, Any]:
        """Execute full composite proactive reconfiguration."""
        port = self.rotate_port()
        aliases = self.scramble_routes()
        banner = self.randomize_headers()
        return {
            "active_port": port,
            "scrambled_routes": aliases,
            "active_decoys": list(self.decoy_routes),
            "server_banner": banner,
            "timestamp": time.time(),
        }

    def evaluate_request_access(self, path: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Evaluate an inbound HTTP request against the active MTD configuration.
        Returns whether the request hits an active alias, hits a decoy honeypot, or is allowed.
        """
        if not self.is_enabled:
            # Static baseline: all original paths route normally
            return {"status": "normal", "target_path": path, "is_decoy": False}

        # If attacker targets the old static path, it hits a decoy honeypot trap!
        if path in self.decoy_routes:
            return {
                "status": "decoy_intercepted",
                "target_path": path,
                "is_decoy": True,
                "action": "trap_and_block",
                "simulated_code": 404,
                "reason": "Static endpoint intercepted by MTD decoy; real endpoint dynamically relocated.",
            }

        # Legitimate client with alias
        return {"status": "routed", "target_path": path, "is_decoy": False}

    def get_status(self) -> Dict[str, Any]:
        """Return current status of Moving Target Defense controller."""
        return {
            "is_enabled": self.is_enabled,
            "current_port": self.current_port,
            "port_pool": self.port_pool,
            "active_route_aliases_count": len(self.active_route_aliases),
            "decoy_routes_count": len(self.decoy_routes),
            "server_banner": self.server_banner,
            "total_reconfigurations": len(self.reconfiguration_history),
        }
