from __future__ import annotations

import random
from datetime import datetime, timezone
from typing import List, Dict

from red_agent.payloads import get_payloads, get_all_categories

class TrafficGenerator:
    """Converts payloads into raw traffic event dicts."""
    
    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        self.benign_endpoints = ["/", "/about", "/health", "/posts", "/contact"]
        self.benign_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
        ]

    def _random_source_ip(self, is_attack: bool = False) -> str:
        """Generate random IPs from 10.x.x.x range for attacks, 192.168.x.x for benign."""
        if is_attack:
            return f"10.{self.rng.randint(0,255)}.{self.rng.randint(0,255)}.{self.rng.randint(1,254)}"
        return f"192.168.{self.rng.randint(0,255)}.{self.rng.randint(0,255)}.{self.rng.randint(1,254)}"

    def _random_user_agent(self) -> str:
        """Return a random normal user agent for benign traffic."""
        return self.rng.choice(self.benign_user_agents)

    def _generate_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def generate_benign(self, count: int) -> List[Dict]:
        """Generate normal-looking traffic events."""
        events = []
        for _ in range(count):
            events.append({
                "source": self._random_source_ip(is_attack=False),
                "endpoint": self.rng.choice(self.benign_endpoints),
                "method": "GET",
                "params": {},
                "response_code": 200,
                "user_agent": self._random_user_agent(),
                "destination": "target-app",
                "timestamp": self._generate_timestamp(),
                "body_size": self.rng.randint(200, 2500),
                "response_time_ms": self.rng.randint(10, 80),
            })
        return events

    def generate_attack(self, attack_type: str, count: int) -> List[Dict]:
        """Generate attack traffic events from the payload library."""
        events = []
        payloads = get_payloads(attack_type)
        if not payloads:
            return events

        for _ in range(count):
            payload_obj = self.rng.choice(payloads)
            
            # Recon scanners often put their signature in the UA string
            user_agent = payload_obj.payload if attack_type == "reconnaissance" else self._random_user_agent()
            
            # Pack payload into the requested parameter
            params = {payload_obj.param_name: payload_obj.payload} if payload_obj.param_name else {}

            events.append({
                "source": self._random_source_ip(is_attack=True),
                "endpoint": payload_obj.target_endpoint,
                "method": payload_obj.method,
                "params": params,
                "response_code": 500 if self.rng.random() > 0.5 else 200,
                "user_agent": user_agent,
                "destination": "target-app",
                "timestamp": self._generate_timestamp(),
                "body_size": self.rng.randint(200, 1500),
                "response_time_ms": self.rng.randint(10, 120),
                # Hidden meta field used by scenario parser to build ground truth
                "_attack_meta": {
                    "attack_type": attack_type,
                    "severity": payload_obj.severity
                }
            })
        return events

    def generate_mixed_stream(self, total: int, benign_ratio: float) -> List[Dict]:
        """Generate an interleaved mix of benign and attack traffic."""
        events = []
        categories = get_all_categories()
        
        for _ in range(total):
            if self.rng.random() < benign_ratio:
                events.extend(self.generate_benign(1))
            else:
                attack_type = self.rng.choice(categories)
                events.extend(self.generate_attack(attack_type, 1))
                
        return events
