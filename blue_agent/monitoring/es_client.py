"""
Blue Agent — Elasticsearch Event Indexer.

Indexes every security event, decision, and remediation outcome into
Elasticsearch so they appear in the Kibana dashboards.

Index layout:
  - defend-forge-events-{YYYY.MM.DD}  : Raw security events
  - defend-forge-decisions-{YYYY.MM.DD}: Decision + remediation records
  - defend-forge-metrics-{YYYY.MM.DD} : Per-round metric snapshots
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("monitoring.elasticsearch")


def _today_suffix() -> str:
    return datetime.now(timezone.utc).strftime("%Y.%m.%d")


class ElasticsearchClient:
    """
    Thin wrapper around the Elasticsearch Python client.
    Gracefully degrades to a no-op if Elasticsearch is unavailable.
    """

    def __init__(self, url: str | None = None):
        self._url = url or settings.monitoring.log_file  # fallback
        self._es = None
        self._available = False

        es_url = __import__("os").getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
        try:
            from elasticsearch import Elasticsearch, NotFoundError  # type: ignore[import]
            self._es = Elasticsearch(
                es_url,
                request_timeout=5,
                max_retries=2,
                retry_on_timeout=True,
            )
            # Quick health check
            info = self._es.info()
            self._available = True
            log.info("elasticsearch_connected",
                     version=info.get("version", {}).get("number", "?"),
                     url=es_url)
        except ImportError:
            log.warning("elasticsearch_sdk_missing",
                        hint="pip install elasticsearch")
        except Exception as exc:
            log.warning("elasticsearch_unavailable", url=es_url, error=str(exc))

    @property
    def available(self) -> bool:
        return self._available

    # ------------------------------------------------------------------
    # Index methods
    # ------------------------------------------------------------------

    def index_security_event(self, event: dict[str, Any]) -> None:
        """Index a raw gateway security event."""
        if not self._available:
            return
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "security_event",
            **event,
        }
        self._index(f"defend-forge-events-{_today_suffix()}", doc)

    def index_decision(self, record: dict[str, Any]) -> None:
        """Index a decision + remediation record."""
        if not self._available:
            return
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "decision",
            **record,
        }
        self._index(f"defend-forge-decisions-{_today_suffix()}", doc)

    def index_metrics(self, snapshot: dict[str, Any]) -> None:
        """Index a metric snapshot."""
        if not self._available:
            return
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "metrics",
            **snapshot,
        }
        self._index(f"defend-forge-metrics-{_today_suffix()}", doc)

    def index_knowledge_gain(
        self,
        attack_type: str,
        endpoint: str,
        technique_id: str,
        mitigation_summary: str,
        outcome: str,
        confidence: float,
    ) -> None:
        """Index a new knowledge base entry (after successful remediation)."""
        if not self._available:
            return
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "knowledge_gain",
            "attack_type": attack_type,
            "endpoint": endpoint,
            "mitre_technique_id": technique_id,
            "mitigation_summary": mitigation_summary,
            "outcome": outcome,
            "confidence": confidence,
        }
        self._index(f"defend-forge-knowledge-{_today_suffix()}", doc)

    def index_red_campaign(self, campaign_summary: dict[str, Any]) -> None:
        """Index a Red Agent campaign summary."""
        if not self._available:
            return
        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "red_campaign",
            **campaign_summary,
        }
        self._index("defend-forge-campaigns", doc)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _index(self, index: str, doc: dict[str, Any]) -> None:
        try:
            self._es.index(index=index, document=doc)
        except Exception as exc:
            log.debug("elasticsearch_index_failed", index=index, error=str(exc))


# Singleton — import and use directly
_client: ElasticsearchClient | None = None


def get_es_client() -> ElasticsearchClient:
    global _client
    if _client is None:
        _client = ElasticsearchClient()
    return _client
