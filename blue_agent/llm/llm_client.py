"""
LLM Client — Provides a unified interface to OpenAI, DeepSeek, or Ollama.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Type, TypeVar

from openai import OpenAI
from pydantic import BaseModel

from blue_agent.config import settings
from blue_agent.logging_cfg import get_logger

log = get_logger("llm.client")

T = TypeVar("T", bound=BaseModel)


class LLMClient:
    """
    Wrapper around the OpenAI Python client to standardize calls
    across different providers (OpenAI, DeepSeek, local Ollama).
    """

    def __init__(self):
        self._provider = settings.llm.provider.lower()
        self._model = settings.llm.model
        self._base_url = settings.llm.effective_base_url
        self._api_key = settings.llm.api_key if settings.llm.api_key else "not-needed"

        # Initialize the client
        self.client = OpenAI(
            base_url=self._base_url,
            api_key=self._api_key,
        )
        
        log.info(
            "llm_client_initialized",
            provider=self._provider,
            model=self._model,
            base_url=self._base_url,
        )

    def generate_structured(
        self,
        system_prompt: str,
        user_prompt: str,
        response_model: Type[T],
        temperature: float = 0.2,
    ) -> T:
        """
        Generate a structured response parsed into a Pydantic model.
        Forces the LLM into JSON mode and parses the result.
        """
        log.debug("llm_request", provider=self._provider, model=self._model)
        
        # We append a strong instruction to ensure JSON output
        system_prompt_with_json = (
            f"{system_prompt}\n\n"
            f"You MUST respond with a raw JSON object that perfectly matches this schema:\n"
            f"{json.dumps(response_model.model_json_schema(), indent=2)}\n\n"
            f"Do not include markdown blocks (like ```json), just the raw JSON object."
        )

        response = self.client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt_with_json},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            response_format={"type": "json_object"},
        )
        
        raw_content = response.choices[0].message.content or "{}"
        
        # Clean up any potential markdown formatting the LLM might have ignored
        raw_content = raw_content.strip()
        if raw_content.startswith("```json"):
            raw_content = raw_content[7:]
        if raw_content.startswith("```"):
            raw_content = raw_content[3:]
        if raw_content.endswith("```"):
            raw_content = raw_content[:-3]
            
        raw_content = raw_content.strip()
        
        log.debug("llm_response_received", length=len(raw_content))
        
        try:
            return response_model.model_validate_json(raw_content)
        except Exception as e:
            log.error("llm_json_parse_error", error=str(e), raw_content=raw_content)
            raise RuntimeError(f"Failed to parse LLM JSON into {response_model.__name__}: {e}")
