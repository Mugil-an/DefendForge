import os
import tempfile
import pytest
from pathlib import Path

from target_platform.discovery import DiscoveredEndpoint, TargetSurface, TargetSurfaceDiscovery


def test_target_surface_properties():
    ep1 = DiscoveredEndpoint(path="/login", method="POST", parameters=["username", "password"], attack_suitability=["sql_injection", "brute_force"])
    ep2 = DiscoveredEndpoint(path="/status", method="GET", parameters=["user_id"], attack_suitability=["sql_injection"], is_benign_safe=True)
    ep3 = DiscoveredEndpoint(path="/", method="GET", attack_suitability=["reconnaissance"], is_benign_safe=True)

    surface = TargetSurface(target_url="http://localhost:8001", endpoints=[ep1, ep2, ep3])
    assert surface.total_routes == 3
    assert len(surface.get_endpoints_for_attack("sql_injection")) == 2
    assert len(surface.get_benign_endpoints()) == 2
    d = surface.to_dict()
    assert d["total_routes"] == 3
    assert len(d["endpoints"]) == 3


def test_ast_discovery_synthetic_flask_and_fastapi(tmp_path):
    # Create sample FastAPI and Flask source files
    fastapi_code = '''
from fastapi import APIRouter, Query

router = APIRouter()

@router.get("/users/{user_id}")
def get_user(user_id: int):
    return {"id": user_id}

@router.post("/items")
def create_item(name: str, price: float):
    return {"name": name, "price": price}

@router.get("/health")
def health():
    return {"status": "ok"}
'''
    (tmp_path / "routes.py").write_text(fastapi_code, encoding="utf-8")

    discovery = TargetSurfaceDiscovery(target_url="http://localhost:9999", target_path=str(tmp_path))
    surface = discovery.discover()

    assert surface.total_routes >= 3
    paths = {ep.path for ep in surface.endpoints}
    assert "/users/{user_id}" in paths
    assert "/items" in paths
    assert "/health" in paths

    user_ep = next(ep for ep in surface.endpoints if ep.path == "/users/{user_id}")
    assert user_ep.method == "GET"
    assert "user_id" in user_ep.parameters
    assert "sql_injection" in user_ep.attack_suitability

    health_ep = next(ep for ep in surface.endpoints if ep.path == "/health")
    assert health_ep.is_benign_safe is True
