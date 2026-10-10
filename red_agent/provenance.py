"""Signed provenance shared by Red executors."""
from __future__ import annotations

import hashlib
import hmac
import os


def signed_provenance_headers(
    campaign_id: str,
    request_id: str,
    *,
    secret: str | None = None,
) -> dict[str, str]:
    """Create the internal Red identity headers used by the gateway."""
    source = "red"
    key = (secret or os.getenv("PROVENANCE_SECRET", "local-development-secret")).encode()
    message = f"{source}:{campaign_id}:{request_id}".encode()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    return {
        "X-DefendForge-Agent": source,
        "X-DefendForge-Campaign": campaign_id,
        "X-DefendForge-Request-Id": request_id,
        "X-DefendForge-Signature": signature,
    }


def verify_provenance(
    campaign_id: str,
    request_id: str,
    signature: str,
    *,
    secret: str | None = None,
) -> bool:
    expected = signed_provenance_headers(
        campaign_id, request_id, secret=secret
    )["X-DefendForge-Signature"]
    return hmac.compare_digest(expected, signature)
