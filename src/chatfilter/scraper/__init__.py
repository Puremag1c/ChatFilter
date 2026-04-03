"""Scraper module for searching Telegram channels across platforms."""

from .base import BasePlatform, CostTier, PlatformMethod
from .platforms import (
    CombotPlatform,
    HottgPlatform,
    LyzemPlatform,
    TelegramChannelsPlatform,
    TelemetrPlatform,
    TeletegPlatform,
    TlgrmPlatform,
)
from .registry import PlatformRegistry, registry

# Register all HTTP platforms
registry.register(TelemetrPlatform())
registry.register(TeletegPlatform())
registry.register(CombotPlatform())
registry.register(HottgPlatform())
registry.register(TelegramChannelsPlatform())
registry.register(TlgrmPlatform())
registry.register(LyzemPlatform())

__all__ = [
    "BasePlatform",
    "CombotPlatform",
    "CostTier",
    "HottgPlatform",
    "LyzemPlatform",
    "PlatformMethod",
    "PlatformRegistry",
    "TelegramChannelsPlatform",
    "TeletegPlatform",
    "TelemetrPlatform",
    "TlgrmPlatform",
    "registry",
]
