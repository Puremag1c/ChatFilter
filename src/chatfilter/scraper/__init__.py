"""Scraper module for searching Telegram channels across platforms."""

from .base import BasePlatform, CostTier, PlatformMethod
from .platforms import BazaTGPlatform, NicegramHubPlatform
from .registry import PlatformRegistry, registry

# Register built-in platforms
registry.register(NicegramHubPlatform())
registry.register(BazaTGPlatform())

__all__ = [
    "BasePlatform",
    "BazaTGPlatform",
    "CostTier",
    "NicegramHubPlatform",
    "PlatformMethod",
    "PlatformRegistry",
    "registry",
]
