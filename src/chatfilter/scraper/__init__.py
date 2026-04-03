"""Scraper module for searching Telegram channels across platforms."""

from .base import BasePlatform, CostTier, PlatformMethod
from .platforms import (
    BazaTgPlatform,
    CombotPlatform,
    GoogleSearchPlatform,
    HottgPlatform,
    LyzemPlatform,
    NicegramPlatform,
    TelegramChannelsPlatform,
    TelegagoPlatform,
    TelemetrPlatform,
    TeletegPlatform,
    TgstatPlatform,
    TlgrmPlatform,
)
from .registry import PlatformRegistry, registry

# Register all platforms
registry.register(TelemetrPlatform())
registry.register(TeletegPlatform())
registry.register(CombotPlatform())
registry.register(HottgPlatform())
registry.register(TelegramChannelsPlatform())
registry.register(TlgrmPlatform())
registry.register(LyzemPlatform())
registry.register(TgstatPlatform())
registry.register(NicegramPlatform())
registry.register(BazaTgPlatform())
registry.register(TelegagoPlatform())
registry.register(GoogleSearchPlatform())

__all__ = [
    "BasePlatform",
    "BazaTgPlatform",
    "CombotPlatform",
    "CostTier",
    "GoogleSearchPlatform",
    "HottgPlatform",
    "LyzemPlatform",
    "NicegramPlatform",
    "PlatformMethod",
    "PlatformRegistry",
    "TelegramChannelsPlatform",
    "TelegagoPlatform",
    "TeletegPlatform",
    "TelemetrPlatform",
    "TgstatPlatform",
    "TlgrmPlatform",
    "registry",
]
