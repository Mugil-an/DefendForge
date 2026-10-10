from __future__ import annotations

import json
import ipaddress
import os
import socket
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

import httpx


def _validation_command(value: object) -> tuple[str, ...]:
    """Normalize manifest command without ever enabling shell interpretation."""
    if value in (None, []):
        return ()
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError("validation.command must be a non-empty JSON array of strings")
    if any("\x00" in item for item in value):
        raise ValueError("validation.command cannot contain NUL bytes")
    return tuple(value)


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    parameters: tuple[str, ...] = ()
    request_schema: dict | None = None


@dataclass(frozen=True)
class AuditProfile:
    """Read-only audit tools and bounded execution settings for a target."""

    source_path: str = "/target"
    tools: tuple[str, ...] = ("pip-audit", "npm-audit", "semgrep")
    timeout_seconds: int = 300


@dataclass(frozen=True)
class ValidationProfile:
    """Bounded, argv-style validation command for a target workspace."""

    command: tuple[str, ...] = ()
    working_dir: str = "."
    timeout: int = 300


@dataclass(frozen=True)
class RegisteredTarget:
    name: str
    base_url: str
    health_path: str = "/health"
    service: str = ""
    openapi_path: str = "/openapi.json"
    crawl_enabled: bool = True
    allowed_methods: tuple[str, ...] = ("GET", "POST", "PUT", "PATCH")
    max_crawl_depth: int = 2
    endpoints: tuple[Endpoint, ...] = ()
    validation: ValidationProfile = field(default_factory=ValidationProfile)
    audit: AuditProfile = field(default_factory=AuditProfile)

    @property
    def validation_command(self) -> tuple[str, ...]:
        """Backward-compatible access to the manifest validation argv."""
        return self.validation.command

    @property
    def validation_working_dir(self) -> str:
        return self.validation.working_dir

    @property
    def validation_timeout(self) -> int:
        return self.validation.timeout

    @property
    def health_url(self) -> str:
        return self.base_url.rstrip("/") + "/" + self.health_path.lstrip("/")


class TargetRegistry:
    """Loads explicitly registered local targets and rejects remote targets."""

    def __init__(self, manifest_dir: str | Path | None = None) -> None:
        self.manifest_dir = Path(
            manifest_dir
            or os.getenv("TARGET_MANIFEST_DIR", Path(__file__).resolve().parent.parent / "targets")
        )

    @staticmethod
    def _validation_command(value: object) -> tuple[str, ...]:
        return _validation_command(value)

    def load(self, name: str = "default") -> RegisteredTarget:
        path = self.manifest_dir / f"{name}.json"
        if not path.is_file():
            raise FileNotFoundError(f"target manifest not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        target = RegisteredTarget(
            name=str(data["name"]),
            base_url=str(data["base_url"]).rstrip("/"),
            health_path=str(data.get("health", {}).get("path", "/health")),
            service=str(data.get("service", "")),
            openapi_path=str(data.get("discovery", {}).get("openapi_path", "/openapi.json")),
            crawl_enabled=bool(data.get("discovery", {}).get("crawl_enabled", True)),
            allowed_methods=tuple(data.get("limits", {}).get("allowed_methods", RegisteredTarget.allowed_methods)),
            max_crawl_depth=int(data.get("discovery", {}).get("max_depth", 2)),
            endpoints=tuple(
                Endpoint(
                    str(item.get("method", "GET")).upper(),
                    str(item["path"]),
                    tuple(str(p) for p in item.get("parameters", [])),
                    item.get("request_schema"),
                )
                for item in data.get("endpoints", [])
                if isinstance(item, dict) and item.get("path")
            ),
            validation=ValidationProfile(
                command=_validation_command(data.get("validation", {}).get("command", [])),
                working_dir=str(data.get("validation", {}).get("working_dir", ".")),
                timeout=int(
                    data.get("validation", {}).get(
                        "timeout", data.get("validation", {}).get("timeout_seconds", 300)
                    )
                ),
            ),
            audit=AuditProfile(
                source_path=str(data.get("audit", {}).get("source_path", "/target")),
                tools=tuple(data.get("audit", {}).get("tools", AuditProfile.tools)),
                timeout_seconds=int(data.get("audit", {}).get("timeout_seconds", 300)),
            ),
        )
        if target.validation.timeout <= 0:
            raise ValueError("validation.timeout must be greater than zero")
        if not target.validation.working_dir:
            raise ValueError("validation.working_dir must not be empty")
        self.validate_local(target)
        return target

    @staticmethod
    def validate_local(target: RegisteredTarget) -> None:
        parsed = urlparse(target.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("registered target must use an HTTP(S) URL")
        host = parsed.hostname
        if host in {"localhost", "127.0.0.1", "::1"} or (target.service and host == target.service):
            return
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 80)}
        except OSError as exc:
            raise ValueError(f"target host cannot be resolved locally: {host}") from exc
        if not any(ipaddress.ip_address(address).is_private for address in addresses):
            raise ValueError("registered target must resolve to a local/private address")

    def discover_openapi(self, target: RegisteredTarget, timeout: float = 5.0) -> tuple[Endpoint, ...]:
        try:
            response = httpx.get(target.base_url + target.openapi_path, timeout=timeout)
            response.raise_for_status()
            document = response.json()
        except (httpx.HTTPError, ValueError):
            return ()
        endpoints: list[Endpoint] = []
        for path, operations in document.get("paths", {}).items():
            for method, operation in operations.items():
                if method.upper() not in target.allowed_methods or not isinstance(operation, dict):
                    continue
                parameters = tuple(
                    str(item.get("name"))
                    for item in operation.get("parameters", [])
                    if isinstance(item, dict) and item.get("name")
                )
                endpoints.append(Endpoint(method.upper(), path, parameters, operation.get("requestBody")))
        return tuple(endpoints)

    def discover(self, target: RegisteredTarget, timeout: float = 5.0) -> tuple[Endpoint, ...]:
        """Prefer OpenAPI and use a bounded, non-destructive link crawl as fallback."""
        openapi = self.discover_openapi(target, timeout)
        if openapi or not target.crawl_enabled:
            return openapi or target.endpoints
        try:
            response = httpx.get(target.base_url.rstrip("/") + "/", timeout=timeout)
            response.raise_for_status()
        except httpx.HTTPError:
            return target.endpoints
        import re

        origin = f"{urlparse(target.base_url).scheme}://{urlparse(target.base_url).netloc}"
        queue = deque([(target.base_url + "/", 0)])
        visited: set[str] = set()
        paths: set[str] = set()
        while queue:
            page_url, depth = queue.popleft()
            page_url, _ = urldefrag(page_url)
            if page_url in visited or depth > target.max_crawl_depth:
                continue
            visited.add(page_url)
            if urlparse(page_url).netloc != urlparse(origin).netloc:
                continue
            try:
                page = httpx.get(page_url, timeout=timeout)
                page.raise_for_status()
            except httpx.HTTPError:
                continue
            for match in re.findall(r'href=["\']([^"\']+)["\']', page.text, flags=re.IGNORECASE):
                link = urldefrag(urljoin(page_url, match))[0]
                parsed = urlparse(link)
                if parsed.netloc != urlparse(origin).netloc or len(parsed.path) > 256:
                    continue
                paths.add(parsed.path or "/")
                if depth < target.max_crawl_depth:
                    queue.append((link, depth + 1))
        discovered = tuple(Endpoint("GET", path) for path in sorted(paths))
        return discovered or target.endpoints
