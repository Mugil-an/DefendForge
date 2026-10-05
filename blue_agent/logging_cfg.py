"""
Structured logging for the Blue Agent.

Uses ``structlog`` with a JSON renderer so every log line is
machine-parseable.  All pipeline-phase events (AUDIT, DETECT, …)
flow through here so monitoring and metrics can consume them
uniformly.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog

from blue_agent.config import settings


def setup_logging() -> None:
    """Configure structured logging once at startup."""
    log_level = getattr(logging, settings.monitoring.log_level.upper(), logging.INFO)

    # Ensure log directory exists
    log_path = Path(settings.monitoring.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # stdlib root
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(log_path), encoding="utf-8"),
        ],
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named, bound logger."""
    return structlog.get_logger(name)
