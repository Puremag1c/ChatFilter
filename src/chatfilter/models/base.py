"""Base Pydantic models with common configuration."""

from __future__ import annotations

from pydantic import ConfigDict


class StrictModelConfig:
    """Common config for strict validation models."""

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )
