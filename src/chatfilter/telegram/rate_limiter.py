"""Proactive rate limiting for Telegram API requests to prevent FloodWaitError."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Configuration for Telegram API rate limiting.

    Attributes:
        get_messages_delay: Minimum delay between get_messages() calls (seconds)
        get_dialogs_delay: Minimum delay between get_dialogs() calls (seconds)
        join_chat_delay: Minimum delay between join_chat() calls (seconds)
        enabled: Whether rate limiting is enabled
    """

    get_messages_delay: float = 1.5  # 1.5 seconds default
    get_dialogs_delay: float = 1.0  # 1 second default
    join_chat_delay: float = 2.0  # 2 seconds default (more conservative for writes)
    enabled: bool = True


OperationType = Literal["get_messages", "get_dialogs", "join_chat"]


class TelegramRateLimiter:
    """Thread-safe rate limiter for Telegram API operations.

    Implements proactive throttling to prevent FloodWaitError by enforcing
    minimum delays between consecutive API calls of the same type.

    This works in conjunction with reactive FloodWait handling (see error_mapping.py)
    to provide both preventive and recovery mechanisms.

    Example:
        ```python
        # Initialize rate limiter with default config
        limiter = TelegramRateLimiter()

        # Before each API call, wait for rate limit
        await limiter.wait_if_needed("get_messages")
        messages = await client.iter_messages(...)

        # Configure custom delays
        config = RateLimitConfig(get_messages_delay=2.0)
        limiter = TelegramRateLimiter(config)
        ```
    """

    def __init__(self, config: RateLimitConfig | None = None) -> None:
        """Initialize rate limiter.

        Args:
            config: Rate limiting configuration (uses defaults if None)
        """
        self._config = config or RateLimitConfig()
        self._last_call_times: dict[OperationType, float] = {}
        self._lock = asyncio.Lock()

        logger.info(
            f"Rate limiter initialized: "
            f"get_messages={self._config.get_messages_delay}s, "
            f"get_dialogs={self._config.get_dialogs_delay}s, "
            f"join_chat={self._config.join_chat_delay}s, "
            f"enabled={self._config.enabled}"
        )

    async def wait_if_needed(self, operation: OperationType) -> None:
        """Wait if needed to respect rate limits for the given operation.

        This method checks the time since the last call of this operation type
        and sleeps if necessary to enforce the minimum delay.

        Args:
            operation: Type of operation ("get_messages", "get_dialogs", "join_chat")
        """
        if not self._config.enabled:
            return

        # Get configured delay for this operation type
        delay_map = {
            "get_messages": self._config.get_messages_delay,
            "get_dialogs": self._config.get_dialogs_delay,
            "join_chat": self._config.join_chat_delay,
        }
        min_delay = delay_map.get(operation, 1.0)

        async with self._lock:
            now = time.monotonic()
            last_call = self._last_call_times.get(operation)

            if last_call is not None:
                elapsed = now - last_call
                if elapsed < min_delay:
                    wait_time = min_delay - elapsed
                    logger.debug(
                        f"Rate limiting {operation}: waiting {wait_time:.2f}s "
                        f"(elapsed: {elapsed:.2f}s, min_delay: {min_delay:.2f}s)"
                    )
                    await asyncio.sleep(wait_time)
                    now = time.monotonic()  # Update after sleep

            # Record this call time
            self._last_call_times[operation] = now

    def reset(self) -> None:
        """Reset all rate limit tracking.

        Useful for testing or when starting a new batch of operations
        that should not be rate limited against previous calls.
        """
        self._last_call_times.clear()
        logger.debug("Rate limiter state reset")

    def get_config(self) -> RateLimitConfig:
        """Get the current rate limiting configuration.

        Returns:
            Current RateLimitConfig
        """
        return self._config

    def update_config(self, config: RateLimitConfig) -> None:
        """Update rate limiting configuration.

        Args:
            config: New configuration to apply
        """
        self._config = config
        logger.info(
            f"Rate limiter configuration updated: "
            f"get_messages={config.get_messages_delay}s, "
            f"get_dialogs={config.get_dialogs_delay}s, "
            f"join_chat={config.join_chat_delay}s, "
            f"enabled={config.enabled}"
        )


# Global rate limiter instance (can be replaced for testing or custom configs)
_global_limiter: TelegramRateLimiter | None = None


def get_rate_limiter(config: RateLimitConfig | None = None) -> TelegramRateLimiter:
    """Get the global rate limiter instance.

    Creates a new instance if one doesn't exist yet.

    Args:
        config: Optional configuration (only used for first initialization)

    Returns:
        Global TelegramRateLimiter instance
    """
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = TelegramRateLimiter(config)
    return _global_limiter


def set_rate_limiter(limiter: TelegramRateLimiter) -> None:
    """Set the global rate limiter instance.

    Useful for testing or using custom configurations.

    Args:
        limiter: Rate limiter instance to use globally
    """
    global _global_limiter
    _global_limiter = limiter
