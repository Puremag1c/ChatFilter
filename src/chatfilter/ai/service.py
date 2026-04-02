"""AI service using LiteLLM for completion requests."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import litellm

from chatfilter.ai.models import AIConfig, AIResponse

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

# Suppress LiteLLM verbose output
litellm.set_verbose = False


class AIService:
    """Async AI completion service backed by LiteLLM."""

    def __init__(self, db: GroupDatabase) -> None:
        self._db = db

    def _load_config(self) -> AIConfig:
        """Load AI configuration from app_settings."""
        api_key = self._db.get_setting("openrouter_api_key") or ""
        model = self._db.get_setting("ai_model") or "openrouter/google/gemini-2.5-flash"
        fallback_models_raw = self._db.get_setting("ai_fallback_models") or "[]"
        try:
            fallback_models = json.loads(fallback_models_raw)
            if not isinstance(fallback_models, list):
                fallback_models = []
        except json.JSONDecodeError:
            fallback_models = []

        return AIConfig(api_key=api_key, model=model, fallback_models=fallback_models)

    async def complete(self, prompt: str, user_id: str | None = None) -> AIResponse:
        """Send a completion request and return an AIResponse.

        Args:
            prompt: The prompt to send.
            user_id: Optional user identifier for tracking.

        Returns:
            AIResponse with content, model used, token counts, and cost.
        """
        config = self._load_config()
        models_to_try = [config.model, *config.fallback_models]

        extra_kwargs: dict = {}
        if config.api_key:
            extra_kwargs["api_key"] = config.api_key
        if user_id:
            extra_kwargs["user"] = user_id

        last_error: Exception | None = None
        for model in models_to_try:
            try:
                response = await litellm.acompletion(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    **extra_kwargs,
                )
                usage = response.usage or {}
                tokens_in = getattr(usage, "prompt_tokens", 0) or 0
                tokens_out = getattr(usage, "completion_tokens", 0) or 0

                try:
                    cost_usd = litellm.completion_cost(completion_response=response)
                except Exception:
                    cost_usd = 0.0

                content = response.choices[0].message.content or ""
                used_model = response.model or model

                return AIResponse(
                    content=content,
                    model=used_model,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    cost_usd=cost_usd,
                )
            except Exception as exc:
                logger.warning("AI completion failed for model %s: %s", model, exc)
                last_error = exc

        raise RuntimeError(
            f"All AI models failed. Last error: {last_error}"
        ) from last_error
