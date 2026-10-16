from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

app = FastAPI(title="DefendForge Target Gateway")
UPSTREAM_URL = os.getenv("UPSTREAM_URL", "http://target_app:5000").rstrip("/")
BLUE_AGENT_URL = os.getenv("BLUE_AGENT_URL", "http://blue_agent:8000/api/events")
TARGET_ID = os.getenv("TARGET_ID", "default")
PROVENANCE_SECRET = os.getenv("PROVENANCE_SECRET", "local-development-secret")
REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}


def _sign(value: str) -> str:
    return hmac.new(PROVENANCE_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {key: ("[REDACTED]" if key.lower() in REDACT_HEADERS else value) for key, value in headers.items()}


import re
from pathlib import Path

def _get_rules_dir() -> Path:
    env_dir = os.getenv("RULES_DIR")
    if env_dir and os.path.exists(env_dir):
        return Path(env_dir)
    container_dir = Path("/app/rules")
    if container_dir.exists():
        return container_dir
    local_dir = Path(__file__).resolve().parent.parent / "rules"
    return local_dir


def _is_ip_blocked(ip: str) -> bool:
    blocklist_path = _get_rules_dir() / "ip_blocklist.json"
    if not blocklist_path.exists():
        return False
    try:
        with open(blocklist_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        blocked_ips = [b.get("ip") for b in data.get("blocked_ips", []) if b.get("ip")]
        return ip in blocked_ips
    except Exception:
        return False


def _check_waf_rules(path: str, query: str, body_bytes: bytes) -> dict[str, str] | None:
    waf_path = _get_rules_dir() / "waf_rules.json"
    if not waf_path.exists():
        return None
    try:
        with open(waf_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        if not rules:
            return None
        
        # Build text to inspect: path, decoded query string, and decoded body
        body_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
        inspect_target = f"{path} {query} {body_text}"

        for rule in rules:
            pattern = rule.get("pattern")
            if not pattern:
                continue
            try:
                if re.search(pattern, inspect_target, re.IGNORECASE):
                    return {
                        "pattern": pattern,
                        "attack_type": rule.get("attack_type", "WAF Rule Match"),
                    }
            except re.error:
                continue
        return None
    except Exception:
        return None


async def _publish(event: dict[str, Any]) -> None:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(BLUE_AGENT_URL, json=event)
    except httpx.HTTPError:
        # The target request must not fail because Blue is temporarily unavailable.
        pass


@app.get("/health")
async def health() -> dict[str, str]:
    async with httpx.AsyncClient(timeout=3.0) as client:
        response = await client.get(f"{UPSTREAM_URL}/health")
    response.raise_for_status()
    return {"status": "ok", "upstream": "ok"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(request: Request, path: str) -> Response:
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
    body = await request.body()
    source_kind = request.headers.get("x-defendforge-agent", "user")
    campaign_id = request.headers.get("x-defendforge-campaign")
    signature_payload = f"{source_kind}:{campaign_id or ''}:{request_id}"
    signed = hmac.compare_digest(request.headers.get("x-defendforge-signature", ""), _sign(signature_payload))
    if source_kind == "red" and not signed:
        return Response("invalid Red provenance", status_code=403)
        
    # Enforce IP Blocklist (using real IP or simulated red IP)
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_ip = "127.0.0.1" if source_kind == "red" else client_ip
    
    if _is_ip_blocked(check_ip):
        event = {
            "event_id": str(uuid.uuid4()),
            "request_id": request_id,
            "target_id": TARGET_ID,
            "source_kind": source_kind,
            "campaign_id": campaign_id,
            "method": request.method,
            "path": "/" + path,
            "query": str(request.url.query),
            "status_code": 403,
            "duration_ms": 1.0,
            "request_size": len(body),
            "response_size": 13,
            "timestamp": time.time(),
            "action": "ip_blocked",
            "request_headers": _redact_headers(dict(request.headers)),
            "response_headers": {},
        }
        await _publish(event)
        return Response("IP is blocked by DefendForge", status_code=403)

    # Enforce Active WAF Rules on path, query parameters, and body
    matched_waf = _check_waf_rules("/" + path, str(request.url.query), body)
    if matched_waf:
        event = {
            "event_id": str(uuid.uuid4()),
            "request_id": request_id,
            "target_id": TARGET_ID,
            "source_kind": source_kind,
            "campaign_id": campaign_id,
            "method": request.method,
            "path": "/" + path,
            "query": str(request.url.query),
            "status_code": 403,
            "duration_ms": 1.0,
            "request_size": len(body),
            "response_size": 45,
            "timestamp": time.time(),
            "action": "waf_blocked",
            "attack_type": matched_waf["attack_type"],
            "matched_pattern": matched_waf["pattern"],
            "request_headers": _redact_headers(dict(request.headers)),
            "response_headers": {},
        }
        await _publish(event)
        return Response(
            f"Blocked by DefendForge WAF: matched rule '{matched_waf['attack_type']}'",
            status_code=403,
        )

    started = time.perf_counter()
    upstream = f"{UPSTREAM_URL}/{path}"
    if request.url.query:
        upstream += f"?{request.url.query}"
    forward_headers = dict(request.headers)
    forward_headers.pop("host", None)
    for internal_header in (
        "x-defendforge-agent",
        "x-defendforge-campaign",
        "x-defendforge-signature",
    ):
        forward_headers.pop(internal_header, None)
    forward_headers["x-request-id"] = request_id
    async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
        response = await client.request(request.method, upstream, headers=forward_headers, content=body)
    event = {
        "event_id": str(uuid.uuid4()),
        "request_id": request_id,
        "target_id": TARGET_ID,
        "source_kind": source_kind if source_kind in {"red", "user"} and (source_kind != "red" or signed) else "unknown",
        "campaign_id": campaign_id,
        "method": request.method,
        "path": "/" + path,
        "query": str(request.url.query),
        "status_code": response.status_code,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "request_size": len(body),
        "response_size": len(response.content),
        "timestamp": time.time(),
        "request_headers": _redact_headers(dict(request.headers)),
        "response_headers": _redact_headers(dict(response.headers)),
    }
    await _publish(event)
    excluded = {"content-length", "transfer-encoding", "connection"}
    headers = {k: v for k, v in response.headers.items() if k.lower() not in excluded}
    return Response(response.content, status_code=response.status_code, headers=headers, media_type=response.headers.get("content-type"))
