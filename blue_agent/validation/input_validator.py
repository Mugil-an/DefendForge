"""Input validation utilities."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from blue_agent.logging_cfg import get_logger
from blue_agent.remediation.validator import PatchValidator

log = get_logger("validation.input_validator")

class InputValidator:
    """Utilities for validating and sanitizing inputs."""
    
    REQUIRED_EVENT_FIELDS = {"source", "endpoint", "method"}
    VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    
    @staticmethod
    def validate_traffic_event(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize a raw traffic event dict."""
        missing = InputValidator.REQUIRED_EVENT_FIELDS - set(raw.keys())
        if missing:
            raise ValueError(f"Missing required fields: {missing}")
        
        normalized = dict(raw)
        method = str(normalized.get("method", "")).upper()
        if method not in InputValidator.VALID_METHODS:
            raise ValueError(f"Invalid HTTP method: {method}")
        normalized["method"] = method
        
        # Add some defaults if missing
        normalized.setdefault("headers", {})
        normalized.setdefault("body", "")
        
        return normalized
    
    @staticmethod
    def validate_traffic_batch(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate a batch of events, returning only valid ones with warnings for invalid."""
        valid_events = []
        for i, event in enumerate(events):
            try:
                if not isinstance(event, dict):
                    raise ValueError("Event must be a dictionary")
                valid = InputValidator.validate_traffic_event(event)
                valid_events.append(valid)
            except Exception as e:
                log.warning("invalid_traffic_event", index=i, error=str(e), raw_event=event)
        
        return valid_events
    
    @staticmethod
    def sanitize_log_input(text: str) -> str:
        """Strip control characters for safe structured logging."""
        if not isinstance(text, str):
            return ""
        # Remove ASCII control characters except newline and tab
        return re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', text)


def sanitize_log_input(text: str) -> str:
    """Convenience alias for InputValidator.sanitize_log_input."""
    return InputValidator.sanitize_log_input(text)
