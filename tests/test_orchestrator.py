import pytest
from unittest.mock import MagicMock, patch
from blue_agent.schemas import (
    AttackEvent, BlueMemoryRecord, DecisionPath, MetricsSnapshot,
    Severity, ValidationDecision, ValidationResult, Patch, PatchOrigin,
)


class TestBlueAgentOrchestrator:
    @patch("blue_agent.orchestrator.MemoryRepository")
    @patch("blue_agent.orchestrator.RuleManager")
    @patch("blue_agent.orchestrator.PatchValidator")
    @patch("blue_agent.orchestrator.PatchGenerator")
    @patch("blue_agent.orchestrator.ReasoningEngine")
    @patch("blue_agent.orchestrator.DecisionEngine")
    @patch("blue_agent.orchestrator.AlertManager")
    @patch("blue_agent.orchestrator.IsolationForestDetector")
    @patch("blue_agent.orchestrator.register_tool")
    def test_initialization(self, mock_reg, mock_det, mock_alert, mock_dec, mock_re, mock_pg, mock_pv, mock_rm, mock_mem):
        from blue_agent.orchestrator import BlueAgent
        agent = BlueAgent()
        assert agent is not None
    
    @patch("blue_agent.orchestrator.MemoryRepository")
    @patch("blue_agent.orchestrator.RuleManager")
    @patch("blue_agent.orchestrator.PatchValidator")
    @patch("blue_agent.orchestrator.PatchGenerator")
    @patch("blue_agent.orchestrator.ReasoningEngine")
    @patch("blue_agent.orchestrator.DecisionEngine")
    @patch("blue_agent.orchestrator.AlertManager")
    @patch("blue_agent.orchestrator.IsolationForestDetector")
    @patch("blue_agent.orchestrator.register_tool")
    def test_process_traffic_no_alerts(self, mock_reg, mock_det, mock_alert, mock_dec, mock_re, mock_pg, mock_pv, mock_rm, mock_mem):
        from blue_agent.orchestrator import BlueAgent
        agent = BlueAgent()
        agent.alert_manager.process_batch.return_value = []  # no alerts
        
        results = agent.process_traffic([{"source": "192.168.1.1", "endpoint": "/", "method": "GET"}])
        assert isinstance(results, list)
        assert len(results) == 1
    
    def test_ingest_knowledge(self):
        with patch("blue_agent.orchestrator.MemoryRepository"), \
             patch("blue_agent.orchestrator.RuleManager"), \
             patch("blue_agent.orchestrator.PatchValidator"), \
             patch("blue_agent.orchestrator.PatchGenerator"), \
             patch("blue_agent.orchestrator.ReasoningEngine") as mock_re, \
             patch("blue_agent.orchestrator.DecisionEngine"), \
             patch("blue_agent.orchestrator.AlertManager"), \
             patch("blue_agent.orchestrator.IsolationForestDetector"), \
             patch("blue_agent.orchestrator.register_tool"), \
             patch("blue_agent.rag.knowledge_ingestion.ingest_initial_knowledge") as mock_ingest:
            
            from blue_agent.orchestrator import BlueAgent
            agent = BlueAgent()
            agent.ingest_knowledge()
            # Just verify it doesn't crash
