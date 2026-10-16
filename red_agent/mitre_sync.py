"""
MITRE ATT&CK Sync Script for DefendForge.

Downloads the live MITRE ATT&CK STIX feed and extracts ALL techniques
that are relevant to web applications / network services, then merges
them into red_agent/mitre_techniques.json.

Usage:
    python -m red_agent.mitre_sync               # full sync
    python -m red_agent.mitre_sync --dry-run     # show what would change
    python -m red_agent.mitre_sync --merge       # merge (keep hand-curated entries)

How it works:
  1. Downloads enterprise-attack STIX bundle from GitHub CDN (~7 MB)
  2. Filters techniques by relevance tags: x_mitre_platforms includes
     "Network", "Linux", "Windows", "Containers", "macOS"
  3. Cross-references against our curated tactic allowlist
  4. Normalises to our schema (adds payload_categories + evasion_variants)
  5. Writes / merges output into mitre_techniques.json

Payload category mapping is heuristic — the script looks for known
keywords in the technique name/description and maps to our supported
attack categories (sql_injection, xss, command_injection, etc.).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.request import urlopen, Request

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUTPUT_FILE = Path(__file__).parent / "mitre_techniques.json"

# Only include techniques from these tactics (MITRE tactic short-names)
RELEVANT_TACTICS = {
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
    "reconnaissance",
}

# Only include techniques mentioning these platforms
RELEVANT_PLATFORMS = {
    "Network", "Linux", "Windows", "macOS", "Containers",
    "IaaS", "SaaS", "Office Suite", "Identity Provider",
}

# Keyword → payload_category heuristic map
KEYWORD_TO_CATEGORY: list[tuple[str, str]] = [
    (r"sql.inject",                "sql_injection"),
    (r"nosql.inject",              "sql_injection"),
    (r"xpath.inject",              "sql_injection"),
    (r"union.select",              "sql_injection"),
    (r"cross.site.script|xss",    "xss"),
    (r"template.inject|ssti",     "xss"),
    (r"script.inject",            "xss"),
    (r"command.inject|cmd.inject","command_injection"),
    (r"os command|shell.inject|unix.shell","command_injection"),
    (r"path.travers|directory.travers","path_traversal"),
    (r"file.inclus|lfi|rfi",      "path_traversal"),
    (r"server.side request|ssrf", "ssrf"),
    (r"open.redirect",            "ssrf"),
    (r"brute.forc|password.spray|credential.stuff","brute_force"),
    (r"valid.account|default.cred","brute_force"),
    (r"scan|recon|enumerat|finger","reconnaissance"),
    (r"phish|spear.phish",        "reconnaissance"),
]

# Tactic short-name → our tactic label
TACTIC_LABEL: dict[str, str] = {
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command and Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
    "reconnaissance":       "Reconnaissance",
}

# Default evasion variants applied per payload category
DEFAULT_EVASION: dict[str, list[str]] = {
    "sql_injection":     ["comment_injection", "case_variation", "hex_encode",
                          "whitespace_obfuscation", "double_url_encode"],
    "xss":              ["html_entity_encode", "javascript_obfuscation",
                          "event_handler_variation", "svg_payload", "double_url_encode"],
    "command_injection": ["command_separator_variation", "shell_variable_insertion",
                          "base64_decode_exec", "backtick_substitution"],
    "path_traversal":   ["double_url_encode", "null_byte_injection",
                          "unicode_slash", "windows_backslash"],
    "ssrf":             ["decimal_ip", "ipv6_loopback", "redirect_chain"],
    "brute_force":      ["slow_timing", "user_agent_rotation", "session_rotation"],
    "reconnaissance":   ["slow_timing", "user_agent_rotation", "random_order"],
}


# ─────────────────────────────────────────────────────────────────────────────
# Fetch
# ─────────────────────────────────────────────────────────────────────────────

def fetch_stix(url: str, timeout: int = 30) -> dict[str, Any]:
    """Download and parse the STIX bundle JSON."""
    print(f"Downloading MITRE ATT&CK STIX bundle from:\n  {url}", flush=True)
    t0 = time.time()
    req = Request(url, headers={"User-Agent": "DefendForge-MitreSync/1.0"})
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    elapsed = time.time() - t0
    size_kb = len(raw) / 1024
    print(f"  Downloaded {size_kb:.0f} KB in {elapsed:.1f}s", flush=True)
    return json.loads(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Parse
# ─────────────────────────────────────────────────────────────────────────────

def _infer_payload_categories(name: str, desc: str) -> list[str]:
    """Heuristically infer payload categories from technique name/description."""
    combined = (name + " " + desc).lower()
    cats = []
    for pattern, category in KEYWORD_TO_CATEGORY:
        if re.search(pattern, combined):
            if category not in cats:
                cats.append(category)
    return cats


def _infer_severity(tactic: str) -> str:
    crit = {"initial-access", "execution", "privilege-escalation", "impact"}
    high = {"credential-access", "defense-evasion", "lateral-movement", "exfiltration"}
    if tactic in crit:
        return "critical"
    if tactic in high:
        return "high"
    return "medium"


def _extract_detection_signatures(desc: str) -> list[str]:
    """Pull short detection indicators from description text."""
    sigs = []
    # Look for lines mentioning monitoring/detection hints
    for line in desc.splitlines():
        line = line.strip()
        if any(w in line.lower() for w in ("monitor", "detect", "log", "alert", "signature")):
            # Truncate long lines
            if len(line) < 120:
                sigs.append(line)
    return sigs[:3]


def parse_stix(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract relevant web-app techniques from STIX bundle."""
    objects = bundle.get("objects", [])
    print(f"  STIX bundle contains {len(objects)} objects", flush=True)

    # Build tactic ID → short_name map from x-mitre-tactic objects
    tactic_map: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname", "")
            tid = obj.get("external_references", [{}])[0].get("external_id", "")
            tactic_map[tid] = short

    techniques = []
    skipped_platform = 0
    skipped_revoked = 0
    skipped_deprecated = 0
    skipped_no_category = 0
    skipped_no_tactic = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        # Skip revoked / deprecated
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            skipped_revoked += 1
            continue

        # Extract MITRE technique ID
        ext_refs = obj.get("external_references", [])
        tech_id = next(
            (r["external_id"] for r in ext_refs
             if r.get("source_name") == "mitre-attack"),
            None
        )
        if not tech_id:
            continue

        # Platform filter — must touch network/server tech
        platforms = set(obj.get("x_mitre_platforms", []))
        if not platforms.intersection(RELEVANT_PLATFORMS):
            skipped_platform += 1
            continue

        # Tactic filter
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = [
            phase["phase_name"]
            for phase in kill_chain
            if phase.get("kill_chain_name") == "mitre-attack"
            and phase.get("phase_name") in RELEVANT_TACTICS
        ]
        if not tactics:
            skipped_no_tactic += 1
            continue
        primary_tactic = tactics[0]

        name = obj.get("name", "")
        desc = obj.get("description", "").replace("\n", " ")[:500]

        # Payload category inference
        categories = _infer_payload_categories(name, desc)

        # For web-app focus, only include if we can map to a category
        # OR if the tactic is specifically web-relevant
        if not categories and primary_tactic not in (
            "initial-access", "reconnaissance", "credential-access"
        ):
            skipped_no_category += 1
            continue

        # If no specific category, use "reconnaissance" as catch-all
        if not categories:
            categories = ["reconnaissance"]

        severity = _infer_severity(primary_tactic)
        tactic_label = TACTIC_LABEL.get(primary_tactic, primary_tactic.title())
        evasion_variants = DEFAULT_EVASION.get(categories[0], ["slow_timing", "user_agent_rotation"])
        detection_sigs = _extract_detection_signatures(desc)

        # ── Build technique tags from platforms + categories ──
        tags = list(set(
            [c.replace("_", "-") for c in categories] +
            ["web", "network"] +
            [p.lower().replace(" ", "-") for p in list(platforms)[:3]]
        ))[:8]

        techniques.append({
            "technique_id": tech_id,
            "name": name,
            "tactic": tactic_label,
            "description": desc[:300],
            "payload_categories": categories,
            "severity": severity,
            "evasion_variants": evasion_variants,
            "detection_signatures": detection_sigs,
            "tags": tags,
            "platforms": sorted(list(platforms)),
        })

    print(f"\n  Filter results:")
    print(f"    Revoked/deprecated skipped : {skipped_revoked}")
    print(f"    Platform mismatch skipped  : {skipped_platform}")
    print(f"    No relevant tactic skipped : {skipped_no_tactic}")
    print(f"    No category mapped skipped : {skipped_no_category}")
    print(f"    Techniques extracted       : {len(techniques)}")

    # Sort: by tactic, then by technique_id
    techniques.sort(key=lambda t: (t["tactic"], t["technique_id"]))
    return techniques


# ─────────────────────────────────────────────────────────────────────────────
# Merge logic
# ─────────────────────────────────────────────────────────────────────────────

def merge_with_existing(
    new: list[dict[str, Any]],
    existing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge new STIX-derived entries with hand-curated existing entries.

    Rules:
    - Hand-curated entries WIN on conflicts (they have better evasion_variants)
    - New techniques not in existing are ADDED
    - Existing techniques not in new are KEPT (they may be sub-techniques we curated)
    """
    existing_ids = {e["technique_id"]: e for e in existing}
    merged = list(existing)  # start with all hand-curated
    added = 0
    for tech in new:
        tid = tech["technique_id"]
        if tid not in existing_ids:
            merged.append(tech)
            added += 1
    print(f"\n  Merged: {len(existing)} existing + {added} new = {len(merged)} total techniques")
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync MITRE ATT&CK techniques into DefendForge"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would change without writing any files"
    )
    parser.add_argument(
        "--merge", action="store_true",
        help="Merge with existing hand-curated entries (default: replace)"
    )
    parser.add_argument(
        "--url", default=STIX_URL,
        help="Custom STIX bundle URL"
    )
    parser.add_argument(
        "--output", default=str(OUTPUT_FILE),
        help="Output JSON file path"
    )
    parser.add_argument(
        "--min-categories", action="store_true",
        help="Require at least one payload category (strict mode)"
    )
    args = parser.parse_args()

    output_path = Path(args.output)

    print("=" * 60)
    print("  DefendForge - MITRE ATT&CK Sync")
    print("=" * 60)

    # 1. Download
    try:
        bundle = fetch_stix(args.url)
    except Exception as exc:
        print(f"\nERROR: Failed to download STIX bundle: {exc}", file=sys.stderr)
        sys.exit(1)

    # 2. Parse
    print("\nParsing techniques...")
    new_techniques = parse_stix(bundle)

    # 3. Optional merge with existing
    final_techniques = new_techniques
    if args.merge and output_path.exists():
        print("\nMerging with existing hand-curated entries...")
        existing = json.loads(output_path.read_text(encoding="utf-8"))
        final_techniques = merge_with_existing(new_techniques, existing)

    # 4. Summary
    categories: dict[str, int] = {}
    tactics: dict[str, int] = {}
    for t in final_techniques:
        for cat in t.get("payload_categories", []):
            categories[cat] = categories.get(cat, 0) + 1
        tac = t.get("tactic", "unknown")
        tactics[tac] = tactics.get(tac, 0) + 1

    print(f"\n{'='*60}")
    print(f"  Total techniques : {len(final_techniques)}")
    print(f"\n  By payload category:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        bar = "#" * min(count, 30)
        print(f"    {cat:<25} {count:>3}  {bar}")
    print(f"\n  By tactic:")
    for tac, count in sorted(tactics.items(), key=lambda x: -x[1]):
        print(f"    {tac:<35} {count:>3}")
    print(f"{'='*60}")

    if args.dry_run:
        print("\nDRY RUN - no files written.")
        return

    # 5. Write
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(final_techniques, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    print(f"\nWrote {len(final_techniques)} techniques to:\n  {output_path.resolve()}")
    print("\nThe Red Agent will use the updated techniques on next campaign start.")


if __name__ == "__main__":
    main()
