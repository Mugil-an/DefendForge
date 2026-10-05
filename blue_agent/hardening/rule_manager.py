"""
Hardening Manager — Translates attack intelligence into durable defensive rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from blue_agent.config import PROJECT_ROOT, settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import AttackEvent

log = get_logger("hardening.rule_manager")


class RuleManager:
    """
    Manages persistent hardening rules (e.g., WAF rules, IP blocklists,
    or Semgrep custom rules).
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self._rules_dir = Path(rules_dir or (PROJECT_ROOT / "rules"))
        self._blocklist_file = self._rules_dir / "ip_blocklist.json"
        self._waf_rules_file = self._rules_dir / "waf_rules.json"
        
        self._initialize_storage()

    def _initialize_storage(self) -> None:
        self._rules_dir.mkdir(parents=True, exist_ok=True)
        if not self._blocklist_file.exists():
            self._write_json(self._blocklist_file, {"blocked_ips": []})
        if not self._waf_rules_file.exists():
            self._write_json(self._waf_rules_file, {"rules": []})

    def _read_json(self, path: Path) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            log.error("json_read_error", path=str(path), error=str(e))
            return {}

    def _write_json(self, path: Path, data: Dict[str, Any]) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.error("json_write_error", path=str(path), error=str(e))

    def block_ip(self, ip_address: str, reason: str = "") -> None:
        """Add an IP to the persistent blocklist."""
        if not ip_address:
            return
            
        data = self._read_json(self._blocklist_file)
        blocked = data.get("blocked_ips", [])
        
        # Check if already blocked
        if any(b.get("ip") == ip_address for b in blocked):
            log.debug("ip_already_blocked", ip=ip_address)
            return
            
        blocked.append({
            "ip": ip_address,
            "reason": reason,
        })
        data["blocked_ips"] = blocked
        
        self._write_json(self._blocklist_file, data)
        log.info("ip_blocked", ip=ip_address, reason=reason)

    def add_waf_rule(self, pattern: str, attack_type: str) -> None:
        """Add a regex pattern to the WAF ruleset."""
        if not pattern:
            return
            
        data = self._read_json(self._waf_rules_file)
        rules = data.get("rules", [])
        
        if any(r.get("pattern") == pattern for r in rules):
            log.debug("waf_rule_already_exists", pattern=pattern)
            return
            
        rules.append({
            "pattern": pattern,
            "attack_type": attack_type,
        })
        data["rules"] = rules
        
        self._write_json(self._waf_rules_file, data)
        log.info("waf_rule_added", pattern=pattern, attack_type=attack_type)

    def derive_rules_from_event(self, event: AttackEvent) -> List[str]:
        """
        Automatically derive and apply hardening rules based on an attack event.
        Returns a list of actions taken.
        """
        actions_taken = []
        
        # Block source IP for severe attacks
        if event.severity in ("high", "critical") and event.source:
            self.block_ip(event.source, reason=f"Severe {event.attack_type} detected.")
            actions_taken.append(f"Blocked IP: {event.source}")
            
        # Add WAF rule for specific payloads if available in features
        # (For MVP, we use heuristics. In a real system, the LLM might extract the exact payload signature)
        if event.attack_type.lower() == "sql injection":
            # Example signature derived from the event
            signature = r"(?i)(UNION\s+SELECT|OR\s+1=1|--)"
            self.add_waf_rule(signature, "SQL Injection")
            actions_taken.append(f"Added WAF rule: {signature}")
            
        if event.attack_type.lower() == "cross-site scripting" or event.attack_type.lower() == "xss":
            signature = r"(?i)(<script>|javascript:)"
            self.add_waf_rule(signature, "Cross-Site Scripting")
            actions_taken.append(f"Added WAF rule: {signature}")

        return actions_taken
