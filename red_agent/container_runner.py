"""
Red Agent — Container entry-point with auto-start capability.

Behaviour:
  RED_AUTO_START=true  : Auto-start attacks after warm-up
  RED_AUTO_START=false : Wait indefinitely (triggered via Blue API)

  RED_WARMUP_SECONDS   : Seconds to wait after Blue Agent is healthy (default 30)
  RED_CAMPAIGN_ROUNDS  : Rounds per campaign (default 5)
  RED_CAMPAIGN_EVENTS  : Max events per round (default 25)
  RED_CAMPAIGN_INTERVAL: Seconds between campaigns (default 60)
"""
from __future__ import annotations

import os
import sys
import time

import httpx

from blue_agent.logging_cfg import get_logger

log = get_logger("red.container_runner")

BLUE_API_URL = os.getenv("BLUE_API_URL", "http://blue_agent:8000")
AUTO_START = os.getenv("RED_AUTO_START", "false").lower() in ("1", "true", "yes")
WARMUP_SECONDS = int(os.getenv("RED_WARMUP_SECONDS", "30"))
CAMPAIGN_ROUNDS = int(os.getenv("RED_CAMPAIGN_ROUNDS", "5"))
CAMPAIGN_EVENTS = int(os.getenv("RED_CAMPAIGN_EVENTS", "25"))
CAMPAIGN_INTERVAL = int(os.getenv("RED_CAMPAIGN_INTERVAL", "60"))
MAX_CAMPAIGNS = int(os.getenv("RED_MAX_CAMPAIGNS", "0"))  # 0 = unlimited


def _wait_for_blue_agent(timeout: int = 300) -> bool:
    """Poll until the Blue Agent health endpoint returns 200."""
    health_url = f"{BLUE_API_URL}/api/health"
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            resp = httpx.get(health_url, timeout=5.0)
            if resp.status_code == 200:
                log.info("blue_agent_healthy", attempts=attempt)
                return True
        except Exception:
            pass
        log.info("waiting_for_blue_agent", attempt=attempt,
                 remaining=int(deadline - time.time()))
        time.sleep(5)
    log.error("blue_agent_never_became_healthy", timeout=timeout)
    return False


def _trigger_campaign() -> dict:
    """POST to the Blue Agent API to start an autonomous Red campaign."""
    url = f"{BLUE_API_URL}/api/red/campaign/start"
    payload = {
        "rounds": CAMPAIGN_ROUNDS,
        "max_events": CAMPAIGN_EVENTS,
    }
    try:
        resp = httpx.post(url, json=payload, timeout=30.0)
        data = resp.json()
        log.info("campaign_triggered",
                 status=resp.status_code,
                 campaign_id=data.get("campaign_id", "?"))
        return data
    except Exception as exc:
        log.error("campaign_trigger_failed", error=str(exc))
        return {}


def _wait_for_campaign_end(campaign_id: str, poll_interval: int = 10, timeout: int = 600) -> dict:
    """Poll campaign status until it is no longer running."""
    if not campaign_id:
        time.sleep(CAMPAIGN_ROUNDS * CAMPAIGN_EVENTS * 3)
        return {}
    url = f"{BLUE_API_URL}/api/red/campaign"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = httpx.get(url, timeout=10.0)
            data = resp.json()
            status = data.get("status", "unknown")
            log.info("campaign_status_poll", campaign_id=campaign_id, status=status)
            if status not in ("running", "starting"):
                return data
        except Exception as exc:
            log.warning("campaign_status_poll_failed", error=str(exc))
        time.sleep(poll_interval)
    return {}


def main() -> None:
    log.info("red_agent_container_started",
             auto_start=AUTO_START,
             warmup_seconds=WARMUP_SECONDS,
             campaign_rounds=CAMPAIGN_ROUNDS)

    if not AUTO_START:
        log.info("auto_start_disabled_waiting_for_api_trigger")
        print(
            "Red Agent container started. Waiting for campaigns to be "
            "triggered via the Blue Agent UI...",
            flush=True,
        )
        while True:
            time.sleep(3600)
        return

    # Wait for Blue Agent to become healthy
    log.info("waiting_for_blue_agent_health_check")
    if not _wait_for_blue_agent(timeout=300):
        log.error("aborting_auto_start_blue_agent_unhealthy")
        sys.exit(1)

    # Warm-up delay
    if WARMUP_SECONDS > 0:
        log.info("warm_up_delay", seconds=WARMUP_SECONDS)
        time.sleep(WARMUP_SECONDS)

    # ── Continuous campaign loop ──────────────────────────────────────
    campaign_count = 0
    while True:
        campaign_count += 1
        log.info("auto_campaign_starting", campaign_number=campaign_count)

        result = _trigger_campaign()
        campaign_id = result.get("campaign_id", "")

        if not campaign_id and not result:
            log.warning("campaign_trigger_returned_empty_waiting_before_retry")
            time.sleep(30)
            continue

        # Wait for the campaign to finish before starting the next one
        summary = _wait_for_campaign_end(campaign_id)
        log.info("auto_campaign_completed",
                 campaign_number=campaign_count,
                 summary=summary)

        if MAX_CAMPAIGNS > 0 and campaign_count >= MAX_CAMPAIGNS:
            log.info("max_campaigns_reached_stopping", max_campaigns=MAX_CAMPAIGNS)
            break

        log.info("inter_campaign_pause", seconds=CAMPAIGN_INTERVAL)
        time.sleep(CAMPAIGN_INTERVAL)


if __name__ == "__main__":
    main()
