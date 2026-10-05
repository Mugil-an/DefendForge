"""
Tests for blue_agent.safety.broker — tool allowlist enforcement,
parameter validation, and dispatch.
"""

from __future__ import annotations

import pytest

from blue_agent.schemas import ToolCall, ToolCallResult
from blue_agent.safety.broker import (
    _REGISTRY,
    execute_tool,
    is_tool_allowed,
    register_tool,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Ensure each test starts with a clean registry."""
    saved = dict(_REGISTRY)
    _REGISTRY.clear()
    yield
    _REGISTRY.clear()
    _REGISTRY.update(saved)


def _dummy_handler(ip: str = "0.0.0.0") -> str:
    return f"blocked {ip}"


async def _async_handler(ip: str = "0.0.0.0") -> str:
    return f"async blocked {ip}"


class TestRegisterTool:
    def test_register_allowed(self):
        register_tool("block_ip", _dummy_handler, {"ip": str})
        assert "block_ip" in _REGISTRY

    def test_register_disallowed(self):
        with pytest.raises(ValueError, match="not in the security allowlist"):
            register_tool("launch_missiles", lambda: None)


class TestIsToolAllowed:
    def test_allowed(self):
        assert is_tool_allowed("block_ip") is True
        assert is_tool_allowed("run_tests") is True

    def test_disallowed(self):
        assert is_tool_allowed("rm_rf_everything") is False


class TestExecuteTool:
    @pytest.mark.asyncio
    async def test_reject_not_in_allowlist(self):
        call = ToolCall(tool_name="hack_pentagon", parameters={})
        result = await execute_tool(call)
        assert result.success is False
        assert "NOT in the allowlist" in result.error

    @pytest.mark.asyncio
    async def test_reject_not_registered(self):
        call = ToolCall(tool_name="block_ip", parameters={"ip": "10.0.0.1"})
        result = await execute_tool(call)
        assert result.success is False
        assert "not yet registered" in result.error

    @pytest.mark.asyncio
    async def test_execute_sync_handler(self):
        register_tool("block_ip", _dummy_handler, {"ip": str})
        call = ToolCall(tool_name="block_ip", parameters={"ip": "10.0.0.1"})
        result = await execute_tool(call)
        assert result.success is True
        assert result.output == "blocked 10.0.0.1"

    @pytest.mark.asyncio
    async def test_execute_async_handler(self):
        register_tool("block_ip", _async_handler, {"ip": str})
        call = ToolCall(tool_name="block_ip", parameters={"ip": "10.0.0.1"})
        result = await execute_tool(call)
        assert result.success is True
        assert result.output == "async blocked 10.0.0.1"

    @pytest.mark.asyncio
    async def test_param_validation_missing(self):
        register_tool("block_ip", _dummy_handler, {"ip": str})
        call = ToolCall(tool_name="block_ip", parameters={})
        result = await execute_tool(call)
        assert result.success is False
        assert "Missing required parameter" in result.error

    @pytest.mark.asyncio
    async def test_param_validation_wrong_type(self):
        register_tool("block_ip", _dummy_handler, {"ip": str})
        call = ToolCall(tool_name="block_ip", parameters={"ip": 12345})
        result = await execute_tool(call)
        assert result.success is False
        assert "must be str" in result.error

    @pytest.mark.asyncio
    async def test_handler_exception(self):
        def bad_handler(**kwargs):
            raise RuntimeError("boom")

        register_tool("block_ip", bad_handler)
        call = ToolCall(tool_name="block_ip", parameters={})
        result = await execute_tool(call)
        assert result.success is False
        assert "boom" in result.error
