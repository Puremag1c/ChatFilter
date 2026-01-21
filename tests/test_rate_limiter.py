"""Tests for Telegram API rate limiting."""

from __future__ import annotations

import asyncio
import time

import pytest

from chatfilter.telegram.rate_limiter import (
    RateLimitConfig,
    TelegramRateLimiter,
    get_rate_limiter,
    set_rate_limiter,
)


class TestRateLimitConfig:
    """Tests for RateLimitConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = RateLimitConfig()
        assert config.get_messages_delay == 1.5
        assert config.get_dialogs_delay == 1.0
        assert config.join_chat_delay == 2.0
        assert config.enabled is True

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = RateLimitConfig(
            get_messages_delay=2.5,
            get_dialogs_delay=1.5,
            join_chat_delay=3.0,
            enabled=False,
        )
        assert config.get_messages_delay == 2.5
        assert config.get_dialogs_delay == 1.5
        assert config.join_chat_delay == 3.0
        assert config.enabled is False


class TestTelegramRateLimiter:
    """Tests for TelegramRateLimiter."""

    @pytest.mark.asyncio
    async def test_first_call_no_delay(self) -> None:
        """Test that first call has no delay."""
        limiter = TelegramRateLimiter()
        start = time.monotonic()
        await limiter.wait_if_needed("get_messages")
        elapsed = time.monotonic() - start
        # First call should be immediate (allow small overhead)
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_second_call_enforces_delay(self) -> None:
        """Test that second call enforces minimum delay."""
        config = RateLimitConfig(get_messages_delay=0.5)
        limiter = TelegramRateLimiter(config)

        # First call
        await limiter.wait_if_needed("get_messages")

        # Second call should wait
        start = time.monotonic()
        await limiter.wait_if_needed("get_messages")
        elapsed = time.monotonic() - start

        # Should have waited approximately 0.5s
        assert 0.4 <= elapsed <= 0.7  # Allow some tolerance

    @pytest.mark.asyncio
    async def test_different_operations_independent(self) -> None:
        """Test that different operation types have independent rate limits."""
        config = RateLimitConfig(
            get_messages_delay=1.0,
            get_dialogs_delay=1.0,
        )
        limiter = TelegramRateLimiter(config)

        # Call get_messages
        await limiter.wait_if_needed("get_messages")

        # Immediate call to get_dialogs should not wait
        start = time.monotonic()
        await limiter.wait_if_needed("get_dialogs")
        elapsed = time.monotonic() - start

        # Should be immediate since it's a different operation
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_disabled_rate_limiting(self) -> None:
        """Test that disabled rate limiting has no effect."""
        config = RateLimitConfig(
            get_messages_delay=1.0,
            enabled=False,
        )
        limiter = TelegramRateLimiter(config)

        # First call
        await limiter.wait_if_needed("get_messages")

        # Second call should NOT wait when disabled
        start = time.monotonic()
        await limiter.wait_if_needed("get_messages")
        elapsed = time.monotonic() - start

        # Should be immediate
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_concurrent_calls_serialized(self) -> None:
        """Test that concurrent calls are properly serialized."""
        config = RateLimitConfig(get_messages_delay=0.3)
        limiter = TelegramRateLimiter(config)

        results = []

        async def call_with_timestamp() -> None:
            await limiter.wait_if_needed("get_messages")
            results.append(time.monotonic())

        # Launch 3 concurrent calls
        await asyncio.gather(
            call_with_timestamp(),
            call_with_timestamp(),
            call_with_timestamp(),
        )

        # All 3 calls should complete
        assert len(results) == 3

        # Calls should be spaced by at least the delay (with some tolerance)
        # First call: immediate
        # Second call: ~0.3s after first
        # Third call: ~0.3s after second
        if len(results) >= 2:
            gap1 = results[1] - results[0]
            assert gap1 >= 0.25  # Allow small tolerance

        if len(results) >= 3:
            gap2 = results[2] - results[1]
            assert gap2 >= 0.25

    @pytest.mark.asyncio
    async def test_natural_delay_honored(self) -> None:
        """Test that natural delays between calls are honored."""
        config = RateLimitConfig(get_messages_delay=0.3)
        limiter = TelegramRateLimiter(config)

        # First call
        await limiter.wait_if_needed("get_messages")

        # Wait longer than the rate limit naturally
        await asyncio.sleep(0.5)

        # Second call should be immediate (already waited enough)
        start = time.monotonic()
        await limiter.wait_if_needed("get_messages")
        elapsed = time.monotonic() - start

        # Should be immediate since we already waited
        assert elapsed < 0.1

    def test_reset_clears_state(self) -> None:
        """Test that reset() clears rate limiter state."""
        limiter = TelegramRateLimiter()
        limiter._last_call_times["get_messages"] = time.monotonic()

        assert len(limiter._last_call_times) > 0

        limiter.reset()

        assert len(limiter._last_call_times) == 0

    def test_get_config(self) -> None:
        """Test get_config returns current configuration."""
        config = RateLimitConfig(get_messages_delay=2.5)
        limiter = TelegramRateLimiter(config)

        retrieved_config = limiter.get_config()
        assert retrieved_config.get_messages_delay == 2.5

    def test_update_config(self) -> None:
        """Test update_config changes configuration."""
        limiter = TelegramRateLimiter()
        original_delay = limiter.get_config().get_messages_delay

        new_config = RateLimitConfig(get_messages_delay=3.0)
        limiter.update_config(new_config)

        assert limiter.get_config().get_messages_delay == 3.0
        assert limiter.get_config().get_messages_delay != original_delay

    @pytest.mark.asyncio
    async def test_all_operation_types(self) -> None:
        """Test all operation types are supported."""
        config = RateLimitConfig(
            get_messages_delay=0.2,
            get_dialogs_delay=0.2,
            join_chat_delay=0.2,
        )
        limiter = TelegramRateLimiter(config)

        # Test each operation type
        for operation in ["get_messages", "get_dialogs", "join_chat"]:
            await limiter.wait_if_needed(operation)  # type: ignore
            start = time.monotonic()
            await limiter.wait_if_needed(operation)  # type: ignore
            elapsed = time.monotonic() - start
            assert 0.15 <= elapsed <= 0.35  # Should enforce delay


class TestGlobalRateLimiter:
    """Tests for global rate limiter instance."""

    def test_get_rate_limiter_creates_instance(self) -> None:
        """Test that get_rate_limiter() creates an instance."""
        # Reset global state
        import chatfilter.telegram.rate_limiter

        chatfilter.telegram.rate_limiter._global_limiter = None

        limiter = get_rate_limiter()
        assert limiter is not None
        assert isinstance(limiter, TelegramRateLimiter)

    def test_get_rate_limiter_returns_same_instance(self) -> None:
        """Test that get_rate_limiter() returns the same instance."""
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2

    def test_set_rate_limiter_replaces_instance(self) -> None:
        """Test that set_rate_limiter() replaces global instance."""
        custom_limiter = TelegramRateLimiter(RateLimitConfig(get_messages_delay=5.0))
        set_rate_limiter(custom_limiter)

        retrieved = get_rate_limiter()
        assert retrieved is custom_limiter
        assert retrieved.get_config().get_messages_delay == 5.0

    def test_get_rate_limiter_with_config_on_first_call(self) -> None:
        """Test that config is used when creating first instance."""
        # Reset global state
        import chatfilter.telegram.rate_limiter

        chatfilter.telegram.rate_limiter._global_limiter = None

        config = RateLimitConfig(get_messages_delay=7.0)
        limiter = get_rate_limiter(config)

        assert limiter.get_config().get_messages_delay == 7.0
