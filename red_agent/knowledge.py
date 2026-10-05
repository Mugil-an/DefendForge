"""Local, deterministic attack knowledge for the safe red-agent simulator."""
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


_DEFAULT = (
    KnowledgeEntry("reconnaissance", "T1595", "Identify exposed application paths.", ("reconnaissance",), ("discovery",)),
    KnowledgeEntry("sql_injection", "T1190", "Exercise input validation at query boundaries.", ("sql_injection",), ("injection",)),
    KnowledgeEntry("xss", "T1189", "Exercise output encoding in reflected input.", ("xss",), ("injection",)),
    KnowledgeEntry("path_traversal", "T1190", "Exercise file path normalization controls.", ("path_traversal",), ("file",)),
    KnowledgeEntry("command_injection", "T1059", "Exercise command argument validation.", ("command_injection",), ("injection",)),
    KnowledgeEntry("ssrf", "T1190", "Exercise outbound URL validation.", ("ssrf",), ("network",)),
    KnowledgeEntry("brute_force", "T1110", "Exercise authentication throttling.", ("brute_force",), ("credential",)),
)


class AttackKnowledge:
    """Read-only knowledge loaded from local JSON or supplied Python data."""

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

