"""Scraper platform implementations."""

from .combot import CombotPlatform
from .hottg import HottgPlatform
from .lyzem import LyzemPlatform
from .nicegram import NicegramPlatform
from .telegago import TelegagoPlatform
from .telegram_channels import TelegramChannelsPlatform
from .telemetr import TelemetrPlatform
from .teleteg import TeletegPlatform
from .tgstat import TgstatPlatform
from .tlgrm import TlgrmPlatform

__all__ = [
    "CombotPlatform",
    "HottgPlatform",
    "LyzemPlatform",
    "NicegramPlatform",
    "TelegramChannelsPlatform",
    "TelegagoPlatform",
    "TeletegPlatform",
    "TelemetrPlatform",
    "TgstatPlatform",
    "TlgrmPlatform",
]
