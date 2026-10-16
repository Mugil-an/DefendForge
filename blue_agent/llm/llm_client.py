"""
LLM Client — Unified interface to Gemini (primary), Ollama, or OpenAI.

Provider selection (in priority order):
  1. Gemini (gemini-3.8-flash) — if GEMINI_API_KEY is set (or LLM_PROVIDER=gemini)
  2. Ollama (local)            — if LLM_PROVIDER=ollama or Gemini unavailable
  3. OpenAI                    — if LLM_PROVIDER=openai

Use generate_structured() for all structured calls. The implementation
transparently routes to whichever backend is available.
"""

from __future__ import annotations

import json
import os
from typing import Type, TypeVar

from pydantic import BaseModel

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

log = get_logger("llm.client")

T = TypeVar("T", bound=BaseModel)


class LLMClient:
    """
    Routing LLM client.

    Tries Gemini first (richest reasoning for vulnerability
    analysis), then falls back to Ollama/OpenAI for local operation.
    """

    def __init__(self):
        self._provider = settings.llm.provider.lower()
        self._model = settings.llm.model
        self._gemini = None
        self._openai_client = None

        # ── Attempt Gemini first ──────────────────────────────────────
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        if gemini_key or self._provider in ("gemini", "google"):
            try:
                from blue_agent.llm.gemini_client import GeminiClient
                target_model = os.getenv("GEMINI_MODEL", "")
                if not target_model:
                    target_model = self._model if "gemini" in self._model else "gemini-3.8-flash"
                self._gemini = GeminiClient(
                    api_key=gemini_key,
                    model=target_model,
                )
                if self._gemini.available:
                    log.info("llm_client_using_gemini", model=self._gemini._model_name)
                    return
                self._gemini = None
            except Exception as exc:
                log.warning("llm_gemini_init_error", error=str(exc))
                self._gemini = None

        # ── Fall back to Ollama / OpenAI ─────────────────────────────
        self._init_openai_compat()

    def _init_openai_compat(self) -> None:
        base_url = settings.llm.effective_base_url
        api_key = settings.llm.api_key or "not-needed"

        if OpenAI is not None:
            self._openai_client = OpenAI(base_url=base_url, api_key=api_key)
        else:
            self._openai_client = None
        log.info(
            "llm_client_initialized",
            provider=self._provider,
            model=self._model,
            base_url=base_url,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: Type[T],
        temperature: float = 0.2,
    ) -> T:
        """
        Generate a structured response parsed into a Pydantic model.

        Tries Gemini first, then OpenAI-compat (Ollama/OpenAI).
        """
        # ── Gemini path ────────────────────────────────────────────────
        if self._gemini and self._gemini.available:
            try:
                return self._gemini.generate_structured(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    temperature=temperature,
                )
            except Exception as exc:
                log.warning("gemini_call_failed_falling_back", error=str(exc))

        # ── OpenAI-compat path ─────────────────────────────────────────
        # Avoid making unauthenticated calls to api.openai.com if user configured Gemini
        if self._provider in ("gemini", "google") and (
            not settings.llm.base_url or settings.llm.api_key in ("dummy", "", "not-needed")
        ):
            raise RuntimeError(
                "Gemini model reasoning unavailable (or in cooldown) and no alternative LLM endpoint is configured"
            )

        if self._openai_client is None:
            self._init_openai_compat()

        log.debug("llm_request_openai_compat", provider=self._provider, model=self._model)

        system_prompt_with_json = (
            f"{system_prompt}\n\n"
            f"You MUST respond with a raw JSON object that perfectly matches this schema:\n"
            f"{json.dumps(response_model.model_json_schema(), indent=2)}\n\n"
            f"Do not include markdown blocks (like ```json), just the raw JSON object."
        )

        try:
            response = self._openai_client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt_with_json},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                response_format={"type": "json_object"},
            )
        except Exception as exc:
            log.warning("openai_compat_call_failed", error=str(exc))
            raise RuntimeError(f"OpenAI API call failed: {exc}") from exc

        raw_content = (response.choices[0].message.content or "{}").strip()
        for prefix in ("```json", "```"):
            if raw_content.startswith(prefix):
                raw_content = raw_content[len(prefix):]
        if raw_content.endswith("```"):
            raw_content = raw_content[:-3]
        raw_content = raw_content.strip()

        log.debug("llm_response_received", length=len(raw_content))

        try:
            return response_model.model_validate_json(raw_content)
        except Exception as exc:
            log.error("llm_json_parse_error", error=str(exc), raw_content=raw_content[:300])
            raise RuntimeError(
                f"Failed to parse LLM JSON into {response_model.__name__}: {exc}"
            ) from exc

    def generate_text(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.15,
    ) -> str:
        """
        Generate raw text or code (e.g. unified diff patches) from Gemini, Ollama, or OpenAI.
        """
        if self._gemini and self._gemini.available:
            try:
                return self._gemini.generate_text(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    temperature=temperature,
                )
            except Exception as exc:
                log.warning("gemini_text_call_failed_falling_back", error=str(exc))

        if self._provider in ("gemini", "google") and (
            not settings.llm.base_url or settings.llm.api_key in ("dummy", "", "not-needed")
        ):
            raise RuntimeError(
                "Gemini text generation unavailable (or in cooldown) and no alternative LLM endpoint is configured"
            )

        if self._openai_client is None:
            self._init_openai_compat()

        response = self._openai_client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
        )
        return (response.choices[0].message.content or "").strip()

    @property
    def using_gemini(self) -> bool:
        """True if Gemini is the active backend."""
        return self._gemini is not None and self._gemini.available
