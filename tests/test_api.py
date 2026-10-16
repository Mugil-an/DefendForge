import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from blue_agent.memory.repository import MemoryRepository


@pytest.fixture
def client():
    """Create test client with mocked BlueAgent."""
    with patch("blue_agent.api.routes._get_agent") as mock_get:
        mock_agent = MagicMock()
        mock_agent.metrics.get_snapshot.return_value = MagicMock(
            model_dump=MagicMock(return_value={"round": 1, "precision": 1.0})
        )
        mock_agent.memory.get_recent.return_value = []
        mock_agent.process_traffic.return_value = []
        mock_get.return_value = mock_agent
        
        from blue_agent.api.routes import app
        yield TestClient(app)


class TestAPIEndpoints:
    def test_health(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    
    def test_metrics(self, client):
        response = client.get("/api/metrics")
        assert response.status_code == 200

    def test_dashboard_snapshot(self, client):
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"
        assert "metrics" in data
        assert "events" in data

    def test_research_novelty_is_phase_one_scoped(self, client):
        response = client.get("/api/research/novelty")
        assert response.status_code == 200
        data = response.json()
        assert data["scope"] == "Phase 1 only"
        assert data["phase_2"] == "excluded"
        assert len(data["items"]) >= 3
    
    def test_memory(self, client):
        response = client.get("/api/memory?limit=5")
        assert response.status_code == 200
    
    def test_traffic_submission(self, client):
        payload = {"events": [{"source": "10.0.0.1", "endpoint": "/login", "method": "POST"}]}
        response = client.post("/api/traffic", json=payload)
        assert response.status_code == 200

    def test_gateway_event_is_durable_and_correlated(self, client, monkeypatch):
        import blue_agent.api.routes as routes

        repository = MemoryRepository(db_url="sqlite:///:memory:")
        monkeypatch.setattr(routes, "_event_repository", repository)
        payload = {
            "event_id": "evt-api-1",
            "request_id": "req-api-1",
            "campaign_id": "campaign-api-1",
            "target_id": "todo-app",
            "source_kind": "red",
            "method": "GET",
            "path": "/todos",
            "status_code": 403,
            "timestamp": 1700000000,
        }
        response = client.post("/api/events", json=payload)
        assert response.status_code == 200

        stored = repository.get_events(limit=1)[0]
        assert stored.event_id == "evt-api-1"
        assert stored.source_provenance["campaign_id"] == "campaign-api-1"
        assert stored.prediction_is_attack is True
        assert stored.patch_id is None

    def test_attack_presets(self, client):
        response = client.get("/api/attack/presets")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        categories = {p["category"] for p in data}
        assert "sql_injection" in categories
        assert "xss" in categories

    def test_trigger_attack(self, client):
        with patch("blue_agent.api.routes._get_red_agent") as mock_red:
            mock_red_instance = MagicMock()
            mock_red_instance.execute_single_attack.return_value = {
                "source": "10.0.0.66",
                "endpoint": "/login",
                "method": "POST",
                "params": {"username": "' OR 1=1--"},
                "payload": "' OR 1=1--",
                "response_code": 403,
                "response_time_ms": 12.5,
                "body_size": 45,
                "timestamp": 1700000000.0,
                "request_id": "req-123",
                "campaign_id": "single-123",
                "is_attack": True,
                "attack_type": "sql_injection",
                "severity": "high",
                "evasion": "none",
                "response_snippet": "Forbidden by WAF",
            }
            mock_red.return_value = mock_red_instance

            response = client.post("/api/attack/trigger", json={
                "attack_type": "sql_injection",
                "endpoint": "/login",
                "method": "POST",
                "payload": "' OR 1=1--",
            })
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["attack_type"] == "sql_injection"
            assert data["is_blocked"] is True

    def test_stop_arena(self, client):
        with patch("blue_agent.api.routes._get_red_agent") as mock_red:
            mock_red_instance = MagicMock()
            mock_red.return_value = mock_red_instance
            response = client.post("/api/arena/stop")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "stopped"
            mock_red_instance.stop_autonomous_campaign.assert_called_once()

    def test_start_arena_continuous(self, client):
        with patch("blue_agent.api.routes._run_continuous_arena_battle") as mock_loop:
            response = client.post("/api/arena/start", json={
                "target_url": "http://localhost:8001",
                "target_path": "./target_app",
            })
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "started"
            assert data["target_url"] == "http://localhost:8001"
            assert data["mode"] == "continuous_autonomous"

    def test_mtd_evaluate_endpoint(self, client):
        response = client.post("/api/mtd/evaluate")
        assert response.status_code == 200
        data = response.json()
        assert "static_baseline" in data
        assert "mtd_enabled" in data
        assert "comparison_metrics" in data
        assert data["comparison_metrics"]["success_criterion_met"] is True

    def test_mtd_status_endpoint(self, client):
        response = client.get("/api/mtd/status")
        assert response.status_code == 200
        data = response.json()
        assert "is_enabled" in data
        assert "current_port" in data
        assert "port_pool" in data

    def test_get_rules_endpoint(self, client):
        response = client.get("/api/rules")
        assert response.status_code == 200
        data = response.json()
        assert "ip_blocklist" in data
        assert "waf_rules" in data
        assert isinstance(data["waf_rules"], dict)
        assert "rules" in data["waf_rules"]

    def test_get_waf_rules_endpoint(self, client):
        response = client.get("/api/rules/waf")
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data

    def test_get_ip_blocklist_endpoint(self, client):
        response = client.get("/api/rules/blocklist")
        assert response.status_code == 200
        data = response.json()
        assert "blocked_ips" in data

    def test_settings_path_attributes(self):
        from blue_agent.config import settings, DATA_DIR, RULES_DIR, PROJECT_ROOT
        assert settings.DATA_DIR == DATA_DIR
        assert settings.RULES_DIR == RULES_DIR
        assert settings.PROJECT_ROOT == PROJECT_ROOT



