import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


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
