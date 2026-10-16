"""
Red Agent — Attack Knowledge Base.

This module is the primary interface used by the campaign planner.
It delegates to MitreKnowledge for the full 32-technique ATT&CK
catalogue while keeping the original KnowledgeEntry API intact for
backward compatibility with existing callers (planner, LLM modules).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class KnowledgeEntry:
    attack_type: str
    technique: str
    description: str
    payload_categories: tuple[str, ...]
    tags: tuple[str, ...] = ()


def _build_default_from_mitre() -> tuple[KnowledgeEntry, ...]:
    """Load entries from the embedded MITRE JSON at import time."""
    mitre_path = Path(__file__).parent / "mitre_techniques.json"
    if not mitre_path.exists():
        return (
            KnowledgeEntry("reconnaissance", "T1595", "Identify exposed application paths.", ("reconnaissance",), ("discovery",)),
            KnowledgeEntry("sql_injection", "T1190", "Exercise input validation at query boundaries.", ("sql_injection",), ("injection",)),
            KnowledgeEntry("xss", "T1189", "Exercise output encoding in reflected input.", ("xss",), ("injection",)),
            KnowledgeEntry("path_traversal", "T1083", "Exercise file path normalization controls.", ("path_traversal",), ("file",)),
            KnowledgeEntry("command_injection", "T1059", "Exercise command argument validation.", ("command_injection",), ("injection",)),
            KnowledgeEntry("ssrf", "T1557", "Exercise outbound URL validation.", ("ssrf",), ("network",)),
            KnowledgeEntry("brute_force", "T1110", "Exercise authentication throttling.", ("brute_force",), ("credential",)),
        )
    try:
        raw = json.loads(mitre_path.read_text(encoding="utf-8"))
        entries: list[KnowledgeEntry] = []
        for item in raw:
            categories = tuple(item.get("payload_categories", [item.get("attack_type", "")]))
            tags = tuple(item.get("tags", ()))
            for cat in categories:
                if cat:
                    entries.append(KnowledgeEntry(
                        attack_type=cat,
                        technique=item["technique_id"],
                        description=item.get("description", ""),
                        payload_categories=categories,
                        tags=tags,
                    ))
        # Deduplicate by attack_type (keep first occurrence per category)
        seen: set[str] = set()
        deduped: list[KnowledgeEntry] = []
        for e in entries:
            if e.attack_type not in seen:
                seen.add(e.attack_type)
                deduped.append(e)
        return tuple(deduped)
    except Exception:
        return (
            KnowledgeEntry("sql_injection", "T1190", "SQL Injection", ("sql_injection",), ("injection",)),
            KnowledgeEntry("xss", "T1189", "Cross-Site Scripting", ("xss",), ("injection",)),
            KnowledgeEntry("command_injection", "T1059", "Command Injection", ("command_injection",), ("injection",)),
            KnowledgeEntry("path_traversal", "T1083", "Path Traversal", ("path_traversal",), ("file",)),
            KnowledgeEntry("ssrf", "T1557", "SSRF", ("ssrf",), ("network",)),
            KnowledgeEntry("brute_force", "T1110", "Brute Force", ("brute_force",), ("credential",)),
            KnowledgeEntry("reconnaissance", "T1595", "Reconnaissance", ("reconnaissance",), ("discovery",)),
        )


_DEFAULT = _build_default_from_mitre()


class AttackKnowledge:
    """
    Read-only knowledge base backed by the MITRE ATT&CK JSON.
    Keeps the original retrieve/get API for backward compatibility.
    """

    def __init__(self, entries: Iterable[KnowledgeEntry] = _DEFAULT):
        self._entries = tuple(entries)

    @classmethod
    def from_json(cls, path: str | Path) -> "AttackKnowledge":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("knowledge JSON must contain a list")
        entries = []
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("knowledge entries must be objects")
            entries.append(KnowledgeEntry(
                attack_type=str(item["attack_type"]),
                technique=str(item.get("technique", "")),
                description=str(item.get("description", "")),
                payload_categories=tuple(item.get("payload_categories", (item["attack_type"],))),
                tags=tuple(item.get("tags", ())),
            ))
        return cls(entries)

    def retrieve(self, query: str = "", *, attack_type: str | None = None, limit: int = 5) -> list[KnowledgeEntry]:
        if limit < 1:
            return []
        terms = set(query.lower().split())
        matches = []
        for entry in self._entries:
            haystack = " ".join((entry.attack_type, entry.technique, entry.description, *entry.tags)).lower()
            if attack_type and entry.attack_type != attack_type:
                continue
            if terms and not any(term in haystack for term in terms):
                continue
            matches.append(entry)
        return matches[:limit]

    def get(self, attack_type: str) -> KnowledgeEntry | None:
        return next(iter(self.retrieve(attack_type=attack_type, limit=1)), None)

    def all_attack_types(self) -> list[str]:
        """Return all unique attack types in this knowledge base."""
        return list({e.attack_type for e in self._entries})
