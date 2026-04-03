"""Abstract base class for Telegram search platforms."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

PlatformMethod = Literal["api", "http", "playwright"]
CostTier = Literal["cheap", "medium", "expensive"]


class BasePlatform(ABC):
    """Abstract base for all Telegram channel search platforms."""

    id: str  # e.g. 'tgstat'
    name: str  # display name
    url: str  # base URL
    method: PlatformMethod
    needs_api_key: bool
    cost_tier: CostTier

    @abstractmethod
    async def search(self, query: str) -> list[str]:
        """Search for Telegram chats matching query.

        Returns:
            List of chat_ref strings (e.g. '@channel', 't.me/channel').
        """

    async def is_available(self) -> bool:
        """Check if platform is configured and ready to use.

        Default implementation returns True for platforms that don't need an API key.
        Platforms requiring API keys should override this.
        """
        return not self.needs_api_key

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id!r} method={self.method!r}>"
