import json

import httpx
import pytest

from target_platform.registry import Endpoint, RegisteredTarget, TargetRegistry


def test_manifest_loads_and_accepts_declared_service(tmp_path):
    manifest_dir = tmp_path / "targets"
    manifest_dir.mkdir()
    (manifest_dir / "demo.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "service": "demo_app",
                "base_url": "http://demo_app:8000",
                "discovery": {"crawl_enabled": False},
                "validation": {
                    "command": ["python", "-m", "pytest", "tests"],
                    "working_dir": ".",
                    "timeout": 17,
                },
            }
        ),
        encoding="utf-8",
    )

    target = TargetRegistry(manifest_dir).load("demo")

    assert target.name == "demo"
    assert target.health_url == "http://demo_app:8000/health"
    assert target.validation_command == ("python", "-m", "pytest", "tests")
    assert target.validation_working_dir == "."
    assert target.validation_timeout == 17


def test_manifest_rejects_shell_command(tmp_path):
    manifest_dir = tmp_path / "targets"
    manifest_dir.mkdir()
    (manifest_dir / "unsafe.json").write_text(
        json.dumps({"name": "unsafe", "base_url": "http://127.0.0.1:8000",
                    "validation": {"command": "pytest tests"}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="JSON array"):
        TargetRegistry(manifest_dir).load("unsafe")


def test_rejects_remote_target():
    target = RegisteredTarget("remote", "http://8.8.8.8")

    with pytest.raises(ValueError, match="local/private"):
        TargetRegistry.validate_local(target)


def test_openapi_discovery_extracts_allowed_operations(monkeypatch):
    target = RegisteredTarget("demo", "http://127.0.0.1:8000")

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "paths": {
                    "/users": {
                        "get": {"parameters": [{"name": "q"}]},
                        "delete": {},
                    }
                }
            }

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())

    assert TargetRegistry().discover_openapi(target) == (
        Endpoint("GET", "/users", ("q",), None),
    )


def test_crawl_fallback_is_bounded(monkeypatch):
    target = RegisteredTarget("demo", "http://127.0.0.1:8000", max_crawl_depth=1)
    pages = {
        "http://127.0.0.1:8000/": '<a href="/one">one</a>',
        "http://127.0.0.1:8000/one": '<a href="/two">two</a>',
        "http://127.0.0.1:8000/two": '<a href="/three">three</a>',
    }

    class Response:
        def __init__(self, text):
            self.text = text

        def raise_for_status(self):
            return None

    monkeypatch.setattr(
        httpx,
        "get",
        lambda url, **kwargs: (
            (_ for _ in ()).throw(httpx.HTTPError("missing"))
            if url.endswith("/openapi.json")
            else Response(pages[url])
        ),
    )

    endpoints = TargetRegistry().discover(target)

    assert [endpoint.path for endpoint in endpoints] == ["/one", "/two"]
