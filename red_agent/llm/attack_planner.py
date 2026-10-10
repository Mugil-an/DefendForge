from __future__ import annotations

import os
import json
import httpx
from typing import Dict, Any, List

from red_agent.config import red_settings
from blue_agent.logging_cfg import get_logger

log = get_logger("red.llm.planner")

class AutonomousAttackPlanner:
    """
    LLM reasoning engine for the Red Agent.
    Uses a local Ollama model to plan the next attack action based on
    reconnaissance data and MITRE ATT&CK context.
    """
    
    def __init__(self, model_name: str = "llama3", api_url: str = None):
        self.model_name = red_settings.llm_model if hasattr(red_settings, 'llm_model') else model_name
        self.api_url = api_url or os.getenv("LLM_BASE_URL", "http://host.docker.internal:11434")
        self.client = httpx.Client(timeout=30.0)
        self.conversation_history: List[Dict[str, str]] = []

    def _build_system_prompt(self) -> str:
        return (
            "You are an autonomous Red Team AI. Your goal is to identify vulnerabilities in the target "
            "application and select the best exploit technique. You must format your output as a JSON object "
            "with exactly two keys: 'reasoning' (your thought process) and 'action' (the attack type to execute, "
            "chosen from: sql_injection, xss, path_traversal, command_injection, ssrf, reconnaissance, brute_force)."
        )

    def plan_next_action(self, scan_results: Dict[str, Any], context: List[str]) -> Dict[str, Any]:
        """
        Ask the LLM to decide on the next attack type.
        """
        prompt = (
            f"Target Scan Results:\n{json.dumps(scan_results, indent=2)}\n\n"
            f"Knowledge Base Context:\n" + "\n".join(context) + "\n\n"
            "Based on the above, what is your next action?"
        )
        
        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.client.post(
                f"{self.api_url}/api/chat",
                json={
                    "model": self.model_name,
                    "messages": messages,
                    "stream": False,
                    "format": "json"
                }
            )
            response.raise_for_status()
            result = response.json()
            message = result.get("message", {}).get("content", "{}")
            
            try:
                decision = json.loads(message)
                log.info("red_llm_decision", action=decision.get("action"))
                return decision
            except json.JSONDecodeError:
                log.error("red_llm_invalid_json", raw=message)
                return {"reasoning": "Fallback due to parse error", "action": "reconnaissance"}
                
        except Exception as e:
            log.warning("red_llm_api_failed", error=str(e))
            # Fallback if Ollama is not running
            return {"reasoning": "Ollama unreachable, fallback to default", "action": "sql_injection"}
