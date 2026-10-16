#!/usr/bin/env python3
"""
DefendForge — Attack & Defense Arena CLI.

Allows you to specify any target Docker container location / URL,
and launches the Red Agent vs Blue Agent autonomous arena.

Usage:
    # Interactive mode (prompts you for container location):
    python run_arena.py

    # Direct arguments:
    python run_arena.py --target-url http://target_gateway:8080 --target-path ./target_app --rounds 5

    # Target external or custom local container:
    python run_arena.py --target-url http://localhost:5000 --target-path ./target_app
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import httpx

BANNER = r"""
========================================================================
   ____       __                 __ _____
  / __ \___  / _|___  ____  ____/ // ___/____  _________  _____
 / / / / _ \/ /_/ _ \/ __ \/ __  // /_  / __ \/ ___/ __ \/ _ \
/ /_/ /  __/ __/  __/ / / / /_/ // __/ / /_/ / /  / /_/ /  __/
\____/\___/_/  \___/_/ /_/\__,_//_/    \____/_/   \__, /\___/
                                                 /____/
     Red Agent (Attack) vs Blue Agent (Defense) Arena
========================================================================
"""


def _check_health(url: str, timeout: float = 5.0) -> bool:
    """Test if the target container endpoint is responding."""
    endpoints = [
        url.rstrip("/") + "/health",
        url.rstrip("/") + "/",
    ]
    for ep in endpoints:
        try:
            r = httpx.get(ep, timeout=timeout)
            if r.status_code in (200, 301, 302, 404):
                return True
        except Exception:
            pass
    return False


def run_via_api(api_url: str, target_url: str, target_path: str, rounds: int, events_per_round: int) -> bool:
    """Trigger the arena via Blue Agent REST API."""
    print(f"\n[*] Connecting to DefendForge API at {api_url}...")
    try:
        r = httpx.get(f"{api_url}/api/health", timeout=4.0)
        if r.status_code != 200:
            return False
    except Exception:
        return False

    print(f"[+] Blue Agent API is online.")
    print(f"[*] Dispatching arena campaign:")
    print(f"    Target URL       : {target_url}")
    print(f"    Source Path      : {target_path}")
    print(f"    Campaign Rounds  : {rounds}")
    print(f"    Events per Round : {events_per_round}")
    print(f"\n[*] Launching Red Agent vs Blue Agent...")

    payload = {
        "target_url": target_url,
        "target_path": target_path,
        "rounds": rounds,
        "events_per_round": events_per_round,
        "use_llm": True,
    }

    try:
        with httpx.Client(timeout=300.0) as client:
            resp = client.post(f"{api_url}/api/arena/start", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                print("\n[+] Arena execution finished!")
                print(f"    Rounds completed : {data.get('rounds_completed', rounds)}")
                print(f"    Attacks executed : {data.get('total_attacks', rounds * events_per_round)}")
                print(f"    Successful blocks: {data.get('blocked_attacks', '?')}")
                return True
            else:
                print(f"[-] API error: HTTP {resp.status_code}: {resp.text}")
                return False
    except Exception as exc:
        print(f"[-] Arena execution error: {exc}")
        return False


def run_standalone_arena(target_url: str, target_path: str, rounds: int, events_per_round: int) -> None:
    """Run the arena in-process using RedAgent and BlueAgent directly."""
    print(f"\n[*] Running standalone in-process arena...")
    from blue_agent.orchestrator import BlueAgent
    from blue_agent.config import settings
    from red_agent.orchestrator import RedAgent
    from red_agent.config import red_settings
    from red_agent.guardrails import TargetGuard

    # 1. Configure target
    red_settings.target_url = target_url.rstrip("/")
    TargetGuard.allow_target(target_url)
    if target_path:
        settings.audit.target_app_path = str(Path(target_path).resolve())

    print(f"[+] Target configured: {red_settings.target_url}")

    # 2. Initialize Agents
    print("[*] Initializing Blue Agent defense engine...")
    blue = BlueAgent()
    print("[*] Initializing Red Agent attack engine...")
    red = RedAgent()

    print(f"\n{'='*70}")
    print(f"   STARTING ATTACK & DEFENSE ARENA ({rounds} ROUNDS)")
    print(f"{'='*70}\n")

    total_attacks = 0
    total_blocked = 0
    total_detected = 0

    for r in range(1, rounds + 1):
        print(f"\n>>> ROUND {r}/{rounds} <<<")
        print(f"----------------------------------------------------------------------")

        # Red Agent executes attack batch
        scenario_result = red.run_autonomous_attack(rounds=1, max_events=events_per_round)
        traffic = scenario_result.traffic
        ground_truth = scenario_result.ground_truth
        total_attacks += len(traffic)

        # Enrich traffic for Blue Agent
        enriched = []
        for evt, truth in zip(traffic, ground_truth):
            enriched.append({
                **evt,
                "is_attack": truth.get("is_attack", True),
                "attack_type": truth.get("attack_type"),
                "severity": truth.get("severity", "low"),
            })

        # Blue Agent detects and defends
        snapshots = blue.process_traffic(enriched)
        details = getattr(blue, "last_round_details", [])

        # Display round attack vs defense outcomes
        for i, (evt, truth) in enumerate(zip(traffic, ground_truth)):
            attack_type = truth.get("attack_type", "Unknown")
            endpoint = evt.get("endpoint", "/")
            method = evt.get("method", "GET")
            detail = details[i] if i < len(details) else {}
            action = detail.get("action", "allowed")
            score = detail.get("confidence") or 0.0

            is_blocked = action in ("block_ip", "block_source_ip", "rate_limit", "update_security_rule")
            if is_blocked:
                total_blocked += 1
            if detail.get("outcome") != "MISSED":
                total_detected += 1

            status_icon = "🛡️ BLOCKED" if is_blocked else "⚠️ OBSERVED"
            print(f"  [Attack {i+1:02d}] {method} {endpoint:<18} | {attack_type:<22} -> {status_icon} ({action})")

        print(f"  Round {r} Summary: {len(traffic)} attacks | Actions: {[d.get('action') for d in details]}")

    print(f"\n{'='*70}")
    print(f"   ARENA FINAL SCOREBOARD")
    print(f"{'='*70}")
    print(f"  Target Container     : {target_url}")
    print(f"  Total Attacks Sent   : {total_attacks}")
    print(f"  Attacks Detected     : {total_detected} ({(total_detected/max(total_attacks,1)):.1%})")
    print(f"  Attacks Blocked      : {total_blocked} ({(total_blocked/max(total_attacks,1)):.1%})")
    print(f"  Active WAF Rules     : {len(blue.hardening.get_active_waf_rules())}")
    print(f"{'='*70}\n")


def main() -> None:
    print(BANNER)
    parser = argparse.ArgumentParser(description="DefendForge Attack & Defense Arena CLI")
    parser.add_argument("--target-url", default="", help="Target Docker container URL (e.g. http://target_gateway:8080)")
    parser.add_argument("--target-path", default="", help="Path to target app source code for patching (e.g. ./target_app)")
    parser.add_argument("--rounds", type=int, default=0, help="Number of campaign rounds (e.g. 5)")
    parser.add_argument("--events-per-round", type=int, default=10, help="Max attacks per round")
    parser.add_argument("--api-url", default="http://localhost:8000", help="DefendForge API URL")
    args = parser.parse_args()

    # Interactive prompts if arguments not supplied
    target_url = args.target_url
    if not target_url:
        if sys.stdin.isatty():
            prompt_val = input("Enter Target Container URL or Service [http://target_gateway:8080]: ").strip()
            target_url = prompt_val or "http://target_gateway:8080"
        else:
            target_url = "http://target_gateway:8080"

    target_path = args.target_path
    if not target_path:
        if sys.stdin.isatty():
            prompt_val = input("Enter Target App Source Code Path [./target_app]: ").strip()
            target_path = prompt_val or "./target_app"
        else:
            target_path = "./target_app"

    rounds = args.rounds
    if rounds <= 0:
        if sys.stdin.isatty():
            prompt_val = input("Enter Number of Campaign Rounds [5]: ").strip()
            rounds = int(prompt_val) if prompt_val.isdigit() else 5
        else:
            rounds = 5

    events_per_round = args.events_per_round

    print(f"\n[1] Checking connectivity to target: {target_url}...")
    healthy = _check_health(target_url)
    if healthy:
        print(f"[+] Target container responded successfully.")
    else:
        print(f"[!] Target at {target_url} did not respond to /health probe (proceeding anyway).")

    # Try API first; fallback to standalone in-process
    api_success = run_via_api(args.api_url, target_url, target_path, rounds, events_per_round)
    if not api_success:
        print("\n[*] API server not running or unreachable — switching to standalone mode.")
        run_standalone_arena(target_url, target_path, rounds, events_per_round)


if __name__ == "__main__":
    main()
