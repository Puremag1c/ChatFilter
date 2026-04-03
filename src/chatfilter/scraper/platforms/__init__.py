"""Scraper platform implementations.

All platforms are auto-registered into the global registry on import.
Platforms requiring API keys are registered with placeholder credentials;
the registry's get_available() method filters by actual DB settings.
"""

from .google_search import GoogleSearchPlatform
from .telegago import TelegagoPlatform
from .tgstat import TGStatPlatform

# Register platforms that don't need API keys immediately.
# API-key platforms are instantiated by the orchestrator using DB settings.
from chatfilter.scraper.registry import registry

registry.register(GoogleSearchPlatform())

__all__ = [
    "GoogleSearchPlatform",
    "TelegagoPlatform",
    "TGStatPlatform",
]
