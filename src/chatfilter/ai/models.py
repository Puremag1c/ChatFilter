"""Pydantic models for AI configuration and responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AIConfig(BaseModel):
    """AI service configuration loaded from app_settings."""

    api_key: str = Field(default="", description="OpenRouter API key")
    model: str = Field(
        default="openrouter/google/gemini-2.5-flash",
        description="Primary model identifier",
    )
    fallback_models: list[str] = Field(
        default_factory=list,
        description="Fallback model identifiers",
    )


class AIResponse(BaseModel):
    """Response from AI completion."""

    content: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
