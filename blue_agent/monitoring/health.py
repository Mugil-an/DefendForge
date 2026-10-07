"""Health check and system monitoring utilities."""
from __future__ import annotations

import os
import platform
import time
from typing import Any, Dict

import httpx
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("monitoring.health")

_START_TIME = time.time()

class HealthChecker:
    """Performs various health and readiness checks for the Blue Agent."""

    def check_database(self) -> Dict[str, Any]:
        """Check PostgreSQL/SQLite connectivity."""
        try:
            engine = create_engine(settings.db.sync_url)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            engine.dispose()
            return {"status": "ok", "message": "Database connected"}
        except SQLAlchemyError as e:
            log.warning("db_health_check_failed", error=str(e))
            return {"status": "error", "message": str(e)}
        except Exception as e:
            log.warning("db_health_check_failed", error=str(e))
            return {"status": "error", "message": str(e)}

    def check_model_loaded(self) -> Dict[str, Any]:
        """Check if detection model file exists."""
        try:
            if os.path.exists(settings.detection.model_path):
                return {"status": "ok", "message": "Model found"}
            else:
                return {"status": "error", "message": f"Model not found at {settings.detection.model_path}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def check_target_app(self) -> Dict[str, Any]:
        """Check target app reachability."""
        url = f"{settings.audit.target_app_url.rstrip('/')}/health"
        try:
            with httpx.Client(timeout=3.0) as client:
                response = client.get(url)
                response.raise_for_status()
            return {"status": "ok", "message": "Target app reachable"}
        except Exception as e:
            log.warning("target_app_health_check_failed", error=str(e))
            return {"status": "error", "message": str(e)}

    def get_system_info(self) -> Dict[str, Any]:
        """Get system resource info."""
        try:
            uptime = time.time() - _START_TIME
            return {
                "platform": platform.platform(),
                "python_version": platform.python_version(),
                "uptime_seconds": uptime
            }
        except Exception as e:
            return {"error": str(e)}

    def get_full_status(self) -> Dict[str, Any]:
        """Aggregated health report."""
        return {
            "database": self.check_database(),
            "model": self.check_model_loaded(),
            "target_app": self.check_target_app(),
            "system_info": self.get_system_info()
        }
