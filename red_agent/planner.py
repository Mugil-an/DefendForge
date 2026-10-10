"""Target-aware, bounded attack planning.

Planning is deliberately data-driven: discovered endpoints and audit evidence
are inputs, while the payload catalogue remains the only source of executable
attack types.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from red_agent.payloads import get_all_categories
from target_platform.registry import Endpoint, RegisteredTarget


_HINTS = {
    "sql_injection": ("sql", "query", "search", "login", "comment", "database"),
    "xss": ("xss", "greet", "render", "html", "comment", "search"),
    "path_traversal": ("file", "path", "download", "document"),
    "command_injection": ("ping", "exec", "command", "shell"),
    "ssrf": ("fetch", "proxy", "url", " webhook"),
    "brute_force": ("login", "auth", "session", "token"),
}


@dataclass(frozen=True)
class TargetAwarePlanner:
    """Build a small plan from target discovery and read-only audit evidence."""

    target: RegisteredTarget
    max_events: int = 10
    discovered_endpoints: tuple[Endpoint, ...] = field(default_factory=tuple)
    audit_findings: dict[str, Any] = field(default_factory=dict)

    def plan(
        self,
        endpoints: Iterable[Endpoint] | None = None,
        audit_findings: dict[str, Any] | None = None,
    ) -> list[dict[str, str]]:
        limit = max(0, min(self.max_events, 50))
        if limit == 0:
            return []
        discovered = tuple(endpoints) if endpoints is not None else (
            self.discovered_endpoints or self.target.endpoints
        )
        if not discovered:
            return []
        evidence = self._evidence(
            self.audit_findings if audit_findings is None else audit_findings
        )
        evidence_types = {
            attack_type for attack_type, hints in _HINTS.items()
            if any(hint in evidence for hint in hints)
            or attack_type.replace("_", " ") in evidence
            or {"sql_injection": "cwe-89", "xss": "cwe-79",
                "path_traversal": "cwe-22", "command_injection": "cwe-78",
                "ssrf": "cwe-918", "brute_force": "cwe-307"}.get(attack_type, "")
                in evidence
        }
        candidates: list[tuple[int, str, Endpoint, str]] = []
        for endpoint in discovered:
            haystack = f"{endpoint.path} {' '.join(endpoint.parameters)} {evidence}".lower()
            for attack_type, hints in _HINTS.items():
                score = sum(2 if hint in endpoint.path.lower() else 1 for hint in hints if hint in haystack)
                if score or attack_type in evidence_types:
                    candidates.append((score, attack_type, endpoint, "discovery/audit evidence"))
        # Always retain a bounded reconnaissance action for newly discovered targets.
        if not candidates:
            candidates = [(1, "reconnaissance", discovered[0], "discovered endpoint")]
        candidates.sort(key=lambda item: (-item[0], item[1], item[2].path))
        plans: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for _, attack_type, endpoint, reason in candidates:
            method = endpoint.method.upper()
            if method not in self.target.allowed_methods or method not in {"GET", "POST", "PUT", "PATCH"}:
                continue
            key = (attack_type, method, endpoint.path)
            if key in seen:
                continue
            seen.add(key)
            plans.append({
                "type": attack_type,
                "endpoint": endpoint.path,
                "method": method,
                "reasoning": f"{reason} for {self.target.name}: {attack_type} on {endpoint.path}",
            })
            if len(plans) >= limit:
                break
        return plans

    @staticmethod
    def _evidence(audits: dict[str, Any]) -> str:
        return str(audits).lower()

    @classmethod
    def from_report(
        cls,
        target: RegisteredTarget,
        report: Any,
        *,
        audit_findings: dict[str, Any] | None = None,
        max_events: int = 10,
    ) -> "TargetAwarePlanner":
        endpoints = tuple(
            Endpoint(ep.method, ep.path, tuple(getattr(ep, "parameters", ())))
            for ep in getattr(report, "discovered_endpoints", ())
        )
        return cls(
            target,
            max_events=max_events,
            discovered_endpoints=endpoints,
            audit_findings=audit_findings or {},
        )
