"""
Safety Gate / Tool Broker

Every tool invocation requested by the LLM or any automated
component MUST pass through this broker.  It:

1. Validates the tool name against a hard-coded allowlist.
2. Schema-validates the parameters.
3. Logs the call.
4. Dispatches to the real implementation.
5. Returns a structured ``ToolCallResult``.

If a tool is NOT in the allowlist, the call is **rejected**.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger
from blue_agent.schemas import ToolCall, ToolCallResult

log = get_logger("safety.broker")

# ---------------------------------------------------------------------------
# Tool registry: maps name → (handler_fn, param_schema_dict)
# param_schema_dict is a dict of param_name → type for lightweight checking.
# ---------------------------------------------------------------------------
_REGISTRY: Dict[str, Dict[str, Any]] = {}


def register_tool(
    name: str,
    handler: Callable[..., Any],
    param_schema: Optional[Dict[str, type]] = None,
) -> None:
    """Register an allowed tool with its handler and optional param types."""
    if name not in settings.security.tool_allowlist:
        raise ValueError(
            f"Cannot register tool '{name}': not in the security allowlist."
        )
    _REGISTRY[name] = {
        "handler": handler,
        "param_schema": param_schema or {},
    }
    log.info("tool_registered", tool=name)


def _validate_params(
    name: str, params: Dict[str, Any], schema: Dict[str, type]
) -> Optional[str]:
    """Return an error message string if params violate schema, else None."""
    for key, expected_type in schema.items():
        if key not in params:
            return f"Missing required parameter '{key}' for tool '{name}'"
        if not isinstance(params[key], expected_type):
            return (
                f"Parameter '{key}' must be {expected_type.__name__}, "
                f"got {type(params[key]).__name__}"
            )
    return None


async def execute_tool(call: ToolCall) -> ToolCallResult:
    """
    Validate and execute a single tool call.

    Steps
    -----
    1. Check allowlist
    2. Check registry
    3. Validate parameters
    4. Execute & return result
    """
    ts_start = time.perf_counter()

    # 1. Allowlist check
    if call.tool_name not in settings.security.tool_allowlist:
        msg = f"Tool '{call.tool_name}' is NOT in the allowlist — REJECTED"
        log.warning("tool_rejected", tool=call.tool_name, reason="not_in_allowlist")
        return ToolCallResult(
            tool_name=call.tool_name, success=False, error=msg
        )

    # 2. Registry check
    entry = _REGISTRY.get(call.tool_name)
    if entry is None:
        msg = f"Tool '{call.tool_name}' is allowed but not yet registered"
        log.warning("tool_not_registered", tool=call.tool_name)
        return ToolCallResult(
            tool_name=call.tool_name, success=False, error=msg
        )

    # 3. Parameter validation
    err = _validate_params(call.tool_name, call.parameters, entry["param_schema"])
    if err:
        log.warning("tool_param_invalid", tool=call.tool_name, error=err)
        return ToolCallResult(
            tool_name=call.tool_name, success=False, error=err
        )

    # 4. Execute
    handler = entry["handler"]
    log.info(
        "tool_executing",
        tool=call.tool_name,
        caller=call.caller,
        params=list(call.parameters.keys()),
    )
    try:
        result = handler(**call.parameters)
        # Support both sync and async handlers
        if hasattr(result, "__await__"):
            result = await result
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - ts_start) * 1000
        log.error(
            "tool_execution_failed",
            tool=call.tool_name,
            error=str(exc),
            elapsed_ms=round(elapsed_ms, 2),
        )
        return ToolCallResult(
            tool_name=call.tool_name, success=False, error=str(exc)
        )

    elapsed_ms = (time.perf_counter() - ts_start) * 1000
    log.info(
        "tool_executed",
        tool=call.tool_name,
        elapsed_ms=round(elapsed_ms, 2),
    )
    return ToolCallResult(
        tool_name=call.tool_name, success=True, output=result
    )


def get_registered_tools() -> list[str]:
    """Return a sorted list of currently registered tool names."""
    return sorted(_REGISTRY.keys())


def is_tool_allowed(name: str) -> bool:
    """Quick check for the allowlist."""
    return name in settings.security.tool_allowlist
