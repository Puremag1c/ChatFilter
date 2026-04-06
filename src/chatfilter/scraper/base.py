"""Abstract base class for Telegram search platforms."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from chatfilter.ai.service import AIService
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

PlatformMethod = Literal["api", "http"]
CostTier = Literal["cheap", "medium", "expensive"]


@dataclass
class PlatformSearchResult:
    """Result from a single platform search call."""

    refs: list[str] = field(default_factory=list)
    ai_cost: float = 0.0
    ai_model: str | None = None
    ai_tokens_in: int = 0
    ai_tokens_out: int = 0


class BasePlatform(ABC):
    """Abstract base for all Telegram channel search platforms."""

    id: str  # e.g. 'tgstat'
    name: str  # display name
    url: str  # base URL
    method: PlatformMethod
    needs_api_key: bool
    cost_tier: CostTier

    def __init__(self) -> None:
        self._ai_service: AIService | None = None
        self._db: GroupDatabase | None = None

    def _configure(self, ai_service: AIService, db: GroupDatabase) -> None:
        """Inject AI service and database after app startup."""
        self._ai_service = ai_service
        self._db = db

    @abstractmethod
    async def search(self, query: str) -> PlatformSearchResult:
        """Search for Telegram chats matching query.

        Returns:
            PlatformSearchResult with chat_ref strings and AI cost metadata.
        """

    async def is_available(self) -> bool:
        """Check if platform is configured and ready to use.

        Default implementation returns True for platforms that don't need an API key.
        Platforms requiring API keys should override this.
        """
        return not self.needs_api_key

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id!r} method={self.method!r}>"
