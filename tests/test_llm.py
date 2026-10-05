"""
Tests for blue_agent.llm — LLMClient and ReasoningEngine.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from pydantic import BaseModel

from blue_agent.schemas import AttackEvent, LLMAnalysis, Severity


class DummyResponseModel(BaseModel):
    action: str
    confidence: float
    reason: str


# =========================================================================
# LLMClient
# =========================================================================
class TestLLMClient:
    @patch("blue_agent.llm.llm_client.OpenAI")
    def test_initialization(self, mock_openai):
        from blue_agent.llm.llm_client import LLMClient
        client = LLMClient()
        mock_openai.assert_called_once()
        assert client._provider in ("openai", "ollama", "deepseek")

    @patch("blue_agent.llm.llm_client.OpenAI")
    def test_generate_structured_success(self, mock_openai):
        from blue_agent.llm.llm_client import LLMClient
        
        # Mock the OpenAI response
        mock_response = MagicMock()
        mock_response.choices[0].message.content = json.dumps({
            "action": "block",
            "confidence": 0.95,
            "reason": "Clear attack"
        })
        mock_client_instance = MagicMock()
        mock_client_instance.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client_instance

        client = LLMClient()
        result = client.generate_structured(
            system_prompt="System",
            user_prompt="User",
            response_model=DummyResponseModel
        )
        
        assert isinstance(result, DummyResponseModel)
        assert result.action == "block"
        assert result.confidence == 0.95

    @patch("blue_agent.llm.llm_client.OpenAI")
    def test_generate_structured_handles_markdown(self, mock_openai):
        from blue_agent.llm.llm_client import LLMClient
        
        mock_response = MagicMock()
        # Some LLMs still wrap JSON in markdown despite json_object format
        mock_response.choices[0].message.content = "```json\n" + json.dumps({
            "action": "rate_limit",
            "confidence": 0.8,
            "reason": "Suspicious"
        }) + "\n```"
        mock_client_instance = MagicMock()
        mock_client_instance.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client_instance

        client = LLMClient()
        result = client.generate_structured("sys", "user", DummyResponseModel)
        
        assert result.action == "rate_limit"

    @patch("blue_agent.llm.llm_client.OpenAI")
    def test_generate_structured_parse_error(self, mock_openai):
        from blue_agent.llm.llm_client import LLMClient
        
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "This is not JSON."
        mock_client_instance = MagicMock()
        mock_client_instance.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client_instance

        client = LLMClient()
        with pytest.raises(RuntimeError, match="Failed to parse LLM JSON"):
            client.generate_structured("sys", "user", DummyResponseModel)


# =========================================================================
# ReasoningEngine
# =========================================================================
class TestReasoningEngine:
    def test_analyze_event(self):
        from blue_agent.llm.reasoning_engine import ReasoningEngine
        
        # Mocks
        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = LLMAnalysis(
            recommended_action="block_source_ip",
            confidence=0.92,
            reasoning_summary="Looks like a severe SQLi.",
        )
        
        mock_retriever = MagicMock()
        mock_retriever.get_context_string.return_value = "RAG context about SQLi."
        
        mock_action_space = MagicMock()
        mock_action_space.all_actions.return_value = [
            MagicMock(name="block_source_ip", label="Block IP"),
            MagicMock(name="escalate_to_llm", label="Escalate")
        ]
        
        engine = ReasoningEngine(llm_client=mock_llm, retriever=mock_retriever, action_space=mock_action_space)
        
        event = AttackEvent(
            attack_type="SQL Injection",
            severity=Severity.HIGH,
            endpoint="/login",
            anomaly_score=0.95
        )
        
        analysis = engine.analyze_event(event)
        
        # Verify Mocks were called
        mock_retriever.get_context_string.assert_called_once()
        mock_llm.generate_structured.assert_called_once()
        
        # Verify output
        assert isinstance(analysis, LLMAnalysis)
        assert analysis.recommended_action == "block_source_ip"
        assert analysis.confidence == 0.92

    def test_invalid_action_fallback(self):
        from blue_agent.llm.reasoning_engine import ReasoningEngine
        
        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = LLMAnalysis(
            recommended_action="nuke_the_server",  # invalid action
            confidence=0.99,
            reasoning_summary="It's the only way.",
        )
        mock_retriever = MagicMock()
        mock_action_space = MagicMock()
        mock_action_space.get_by_name.side_effect = ValueError("Invalid action")
        
        engine = ReasoningEngine(llm_client=mock_llm, retriever=mock_retriever, action_space=mock_action_space)
        event = AttackEvent(anomaly_score=0.9)
        
        analysis = engine.analyze_event(event)
        
        # Fallback to no_action
        assert analysis.recommended_action == "no_action"
