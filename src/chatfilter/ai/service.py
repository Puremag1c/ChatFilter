"""AI service using LiteLLM for completion requests."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

import litellm
from pydantic import SecretStr

from chatfilter.ai.models import AIConfig, AIResponse

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

# Suppress LiteLLM verbose output and prevent API keys from appearing in logs
litellm.set_verbose = False  # type: ignore[attr-defined]
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logging.getLogger("LiteLLM Router").setLevel(logging.WARNING)
logging.getLogger("LiteLLM Proxy").setLevel(logging.WARNING)


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

        return AIConfig(
            api_key=SecretStr(api_key), model=model, fallback_models=fallback_models
        )

    # Fallback cost per token when LiteLLM cannot determine the real cost.
    # Uses conservative upper-bound pricing to avoid giving away free AI.
    _FALLBACK_COST_PER_INPUT_TOKEN = 5e-6  # $5 / 1M tokens
    _FALLBACK_COST_PER_OUTPUT_TOKEN = 15e-6  # $15 / 1M tokens
    _FALLBACK_MINIMUM_COST = 0.0001  # $0.0001 floor when tokens are also missing

    def _estimate_cost(
        self, response: object, tokens_in: int, tokens_out: int, model: str
    ) -> float:
        """Try to compute cost via LiteLLM; fall back to token-based estimate."""
        try:
            cost = litellm.completion_cost(completion_response=response)
            if cost is not None and cost > 0:
                return float(cost)
        except Exception:
            pass

        # LiteLLM couldn't determine cost — use fallback estimate
        if tokens_in > 0 or tokens_out > 0:
            estimated = (
                tokens_in * self._FALLBACK_COST_PER_INPUT_TOKEN
                + tokens_out * self._FALLBACK_COST_PER_OUTPUT_TOKEN
            )
            logger.warning(
                "Cost unavailable from LiteLLM for model %s; estimated $%.6f from %d/%d tokens",
                model,
                estimated,
                tokens_in,
                tokens_out,
            )
            return estimated

        # No cost AND no token counts — charge minimum floor
        logger.warning(
            "Cost and token counts unavailable from LiteLLM for model %s; charging minimum $%.4f",
            model,
            self._FALLBACK_MINIMUM_COST,
        )
        return self._FALLBACK_MINIMUM_COST

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

        extra_kwargs: dict[str, Any] = {}
        raw_api_key = config.api_key.get_secret_value()
        if raw_api_key:
            extra_kwargs["api_key"] = raw_api_key
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

                cost_usd = self._estimate_cost(response, tokens_in, tokens_out, model)

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

        raise RuntimeError(f"All AI models failed. Last error: {last_error}") from last_error
