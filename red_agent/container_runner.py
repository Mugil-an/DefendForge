"""Container entrypoint for a bounded Red Agent campaign."""
from __future__ import annotations

import os
import time

import httpx


def main() -> None:
    api_url = os.getenv("BLUE_API_URL", "http://blue_agent:8000").rstrip("/")
    rounds = int(os.getenv("RED_CAMPAIGN_ROUNDS", "5"))
    max_events = int(os.getenv("RED_CAMPAIGN_EVENTS", "25"))
    timeout = float(os.getenv("RED_API_TIMEOUT", "10"))
    deadline = time.monotonic() + float(os.getenv("RED_STARTUP_TIMEOUT", "120"))

    with httpx.Client(timeout=timeout) as client:
        while True:
            try:
                if client.get(f"{api_url}/api/health").is_success:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("Blue Agent API did not become ready in time")
            time.sleep(2)

        response = client.post(
            f"{api_url}/api/red/campaign/start",
            json={"rounds": rounds, "max_events": max_events},
        )
        response.raise_for_status()
        print(response.json(), flush=True)


if __name__ == "__main__":
    main()
