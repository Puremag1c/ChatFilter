"""Scraper platform implementations."""

from .combot import CombotPlatform
from .hottg import HottgPlatform
from .lyzem import LyzemPlatform
from .telegram_channels import TelegramChannelsPlatform
from .telemetr import TelemetrPlatform
from .teleteg import TeletegPlatform
from .tlgrm import TlgrmPlatform

__all__ = [
    "CombotPlatform",
    "HottgPlatform",
    "LyzemPlatform",
    "TelegramChannelsPlatform",
    "TeletegPlatform",
    "TelemetrPlatform",
    "TlgrmPlatform",
]
