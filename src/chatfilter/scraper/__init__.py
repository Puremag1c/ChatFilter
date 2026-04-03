"""Scraper module for searching Telegram channels across platforms."""

from .base import BasePlatform, CostTier, PlatformMethod
from .registry import PlatformRegistry, registry

# Auto-register all platforms
from . import platforms as _platforms  # noqa: F401

__all__ = [
    "BasePlatform",
    "CostTier",
    "PlatformMethod",
    "PlatformRegistry",
    "registry",
]
