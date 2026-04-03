"""Scraper platform implementations."""

from .baza_tg import BazaTgPlatform
from .combot import CombotPlatform
from .google_search import GoogleSearchPlatform
from .hottg import HottgPlatform
from .lyzem import LyzemPlatform
from .nicegram import NicegramPlatform
from .telegram_channels import TelegramChannelsPlatform
from .telegago import TelegagoPlatform
from .telemetr import TelemetrPlatform
from .teleteg import TeletegPlatform
from .tgstat import TgstatPlatform
from .tlgrm import TlgrmPlatform

__all__ = [
    "BazaTgPlatform",
    "CombotPlatform",
    "GoogleSearchPlatform",
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
