"""
Blue Agent — Gemini LLM Client.

Provides structured reasoning about attack events and vulnerability
remediation using Google's Gemini models via the
google-generativeai SDK.

Falls back gracefully to the existing OpenAI-compatible client
(Ollama) if GEMINI_API_KEY is not set.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Type, TypeVar

from pydantic import BaseModel

from blue_agent.logging_cfg import get_logger

log = get_logger("llm.gemini")

T = TypeVar("T", bound=BaseModel)

# ─────────────────────────────────────────────────────────────────────────────
# Patch generation prompt — richer than the base reasoning prompt
# ─────────────────────────────────────────────────────────────────────────────
_PATCH_SYSTEM_PROMPT = """\
You are an expert application security engineer and Python developer.
You are the remediation engine of an autonomous Blue Agent cybersecurity system.

Your task: Given an attack event and the vulnerable code, generate a minimal,
safe, correct patch that closes the vulnerability WITHOUT breaking existing
functionality.

CRITICAL RULES:
1. Only modify lines that are directly vulnerable — never rewrite unrelated logic.
2. Use parameterized queries for SQL injection, not string sanitization.
3. Use Flask's `escape()` or `markupsafe.escape()` for XSS.
4. For path traversal, use `os.path.abspath` + prefix check.
5. For command injection, never pass shell=True. Use shlex.split().
6. For SSRF, validate URLs against an allowlist of hostnames.
7. The patch must be valid, runnable Python.
8. Respond ONLY with valid JSON matching the requested schema — no markdown.
"""

_PATCH_USER_TEMPLATE = """\
ATTACK EVENT:
  Type       : {attack_type}
  Endpoint   : {endpoint}
  Severity   : {severity}
  Payload    : {payload_summary}
  Evidence   : {evidence}

VULNERABLE CODE (from {file_path}):
```python
{code_snippet}
```

SIMILAR PAST REMEDIATIONS (from knowledge base):
{rag_context}

Generate a complete patch. Include:
- "patch_code": the full corrected version of the vulnerable function/block
- "explanation": what was wrong and what the fix does
- "waf_rule_pattern": a regex pattern to add to the WAF for immediate blocking
- "hardening_actions": list of additional hardening steps
- "confidence": your confidence that this patch is correct (0.0–1.0)
"""


class GeminiClient:
    """
    Google Gemini client for structured vulnerability remediation.

    Usage::

        client = GeminiClient()
        result = client.generate_structured(system, user, MyModel)
    """

    def __init__(self, api_key: str | None = None, model: str = "gemini-3.8-flash"):
        self._api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self._model_name = model or os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
        self._available = False
        self._model = None
        self._quota_cooldown_until: float = 0.0
        self._quota_cooldown_duration: float = 180.0

        if not self._api_key:
            log.warning("gemini_api_key_missing", hint="Set GEMINI_API_KEY env var")
            return

        try:
            import google.generativeai as genai  # type: ignore[import]
            genai.configure(api_key=self._api_key)
            self._model = genai.GenerativeModel(
                model_name=self._model_name,
                generation_config={
                    "temperature": 0.15,
                    "top_p": 0.95,
                    "max_output_tokens": 4096,
                    "response_mime_type": "application/json",
                },
            )
            self._available = True
            log.info("gemini_client_ready", model=self._model_name)
        except ImportError:
            log.warning("gemini_sdk_not_installed",
                        hint="pip install google-generativeai")
        except Exception as exc:
            log.warning("gemini_client_init_failed", error=str(exc))

    @property
    def available(self) -> bool:
        if not self._available:
            return False
        if time.time() < self._quota_cooldown_until:
            return False
        return True

    @staticmethod
    def _is_quota_error(exc: Exception) -> bool:
        msg = str(exc).lower()
        return (
            "429" in msg
            or "quota" in msg
            or "resource_exhausted" in msg
            or "rate_limit" in msg
        )

    def _trip_circuit_breaker(self, exc: Exception) -> None:
        self._quota_cooldown_until = time.time() + self._quota_cooldown_duration
        log.warning(
            "gemini_quota_exhausted_tripping_circuit_breaker",
            cooldown_seconds=self._quota_cooldown_duration,
            error=str(exc)[:250],
        )

    def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: Type[T],
        temperature: float = 0.15,
    ) -> T:
        """
        Call Gemini and parse the response into a Pydantic model.
        Raises RuntimeError if unavailable or parse fails.
        """
        if not self.available or self._model is None:
            raise RuntimeError("Gemini client not available (or in quota cooldown)")

        schema_hint = (
            f"\n\nYou MUST respond with a raw JSON object exactly matching "
            f"this schema (no markdown, no explanation outside JSON):\n"
            f"{json.dumps(response_model.model_json_schema(), indent=2)}"
        )

        full_prompt = (
            f"SYSTEM:\n{system_prompt}{schema_hint}\n\n"
            f"USER:\n{user_prompt}"
        )

        log.info("gemini_request_start", model=self._model_name,
                 prompt_len=len(full_prompt))

        raw = ""
        try:
            response = self._model.generate_content(full_prompt)
            raw = response.text.strip()
        except Exception as exc:
            if self._is_quota_error(exc):
                self._trip_circuit_breaker(exc)
                raise RuntimeError(f"Gemini API quota exhausted: {exc}") from exc

            log.warning("gemini_primary_model_failed_trying_fallbacks", model=self._model_name, error=str(exc))
            import google.generativeai as genai
            succeeded = False
            for fb_model in ["gemini-3.8-flash", "gemini-flash-latest", "gemini-3.6-flash", "gemini-4-argon", "gemini-pro-latest"]:
                if fb_model == self._model_name:
                    continue
                try:
                    log.info("gemini_attempting_fallback_model", model=fb_model)
                    alt_model = genai.GenerativeModel(
                        model_name=fb_model,
                        generation_config={
                            "temperature": 0.15,
                            "top_p": 0.95,
                            "max_output_tokens": 4096,
                            "response_mime_type": "application/json",
                        },
                    )
                    response = alt_model.generate_content(full_prompt)
                    raw = response.text.strip()
                    self._model = alt_model
                    self._model_name = fb_model
                    succeeded = True
                    break
                except Exception as fb_err:
                    if self._is_quota_error(fb_err):
                        self._trip_circuit_breaker(fb_err)
                        raise RuntimeError(f"Gemini API quota exhausted on fallback: {fb_err}") from fb_err
                    log.debug("gemini_fallback_model_failed", model=fb_model, error=str(fb_err))
            if not succeeded:
                log.error("gemini_all_models_failed", error=str(exc))
                raise RuntimeError(f"Gemini API error: {exc}") from exc

        # Strip any accidental markdown fences
        if raw.startswith("```json"):
            raw = raw[7:]
        if raw.startswith("```"):
            raw = raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3]
        raw = raw.strip()

        log.info("gemini_response_received", response_len=len(raw))

        try:
            return response_model.model_validate_json(raw)
        except Exception as exc:
            log.error("gemini_json_parse_error", error=str(exc),
                      raw_preview=raw[:300])
            raise RuntimeError(
                f"Failed to parse Gemini response into {response_model.__name__}: {exc}"
            ) from exc

    def generate_text(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.15,
    ) -> str:
        """Generate free-form text or unified diffs from Gemini."""
        if not self.available or self._model is None:
            raise RuntimeError("Gemini client not available (or in quota cooldown)")
        full_prompt = f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}"
        try:
            response = self._model.generate_content(full_prompt)
            return response.text.strip()
        except Exception as exc:
            if self._is_quota_error(exc):
                self._trip_circuit_breaker(exc)
                raise RuntimeError(f"Gemini API quota exhausted: {exc}") from exc
            log.warning("gemini_text_model_failed_trying_fallbacks", model=self._model_name, error=str(exc))
            import google.generativeai as genai
            for fb_model in ["gemini-3.8-flash", "gemini-flash-latest", "gemini-3.6-flash", "gemini-4-argon", "gemini-pro-latest"]:
                if fb_model == self._model_name:
                    continue
                try:
                    alt_model = genai.GenerativeModel(model_name=fb_model)
                    response = alt_model.generate_content(full_prompt)
                    self._model = alt_model
                    self._model_name = fb_model
                    return response.text.strip()
                except Exception as fb_err:
                    if self._is_quota_error(fb_err):
                        self._trip_circuit_breaker(fb_err)
                        raise RuntimeError(f"Gemini API quota exhausted on fallback: {fb_err}") from fb_err
                    log.debug("gemini_text_fallback_failed", model=fb_model, error=str(fb_err))
            log.error("gemini_generate_text_error", error=str(exc))
            raise RuntimeError(f"Gemini text generation failed: {exc}") from exc

    def generate_patch(
        self,
        attack_type: str,
        endpoint: str,
        severity: str,
        payload_summary: str,
        evidence: str,
        file_path: str,
        code_snippet: str,
        rag_context: str,
    ) -> dict[str, Any]:
        """
        Specialized high-quality patch generation call.
        Returns raw dict with keys: patch_code, explanation,
        waf_rule_pattern, hardening_actions, confidence.
        """
        if not self.available or self._model is None:
            raise RuntimeError("Gemini client not available (or in quota cooldown)")

        user_prompt = _PATCH_USER_TEMPLATE.format(
            attack_type=attack_type,
            endpoint=endpoint,
            severity=severity,
            payload_summary=payload_summary,
            evidence=evidence,
            file_path=file_path,
            code_snippet=code_snippet,
            rag_context=rag_context or "No similar past remediations found.",
        )

        full_prompt = f"SYSTEM:\n{_PATCH_SYSTEM_PROMPT}\n\nUSER:\n{user_prompt}"

        response_schema_hint = (
            '\n\nRespond with JSON: {"patch_code": "...", "explanation": "...", '
            '"waf_rule_pattern": "...", "hardening_actions": [...], "confidence": 0.9}'
        )
        full_prompt += response_schema_hint

        try:
            response = self._model.generate_content(full_prompt)
            raw = response.text.strip()
        except Exception as exc:
            if self._is_quota_error(exc):
                self._trip_circuit_breaker(exc)
            raise RuntimeError(f"Gemini patch generation failed: {exc}") from exc

        if raw.startswith("```json"):
            raw = raw[7:]
        if raw.startswith("```"):
            raw = raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3]
        raw = raw.strip()

        try:
            result = json.loads(raw)
            log.info("gemini_patch_generated",
                     attack_type=attack_type,
                     confidence=result.get("confidence", 0))
            return result
        except json.JSONDecodeError as exc:
            log.error("gemini_patch_parse_error", raw_preview=raw[:300])
            raise RuntimeError(f"Could not parse Gemini patch JSON: {exc}") from exc
