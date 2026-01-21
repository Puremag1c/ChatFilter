"""Tests for retry logic with exponential backoff."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import patch

import pytest

from chatfilter.telegram.retry import (
    calculate_backoff_delay,
    with_retry,
    with_retry_for_reads,
    with_retry_for_writes,
)


class TestCalculateBackoffDelay:
    """Tests for backoff delay calculation."""

    def test_exponential_growth(self) -> None:
        """Test that delay grows exponentially."""
        delay_0 = calculate_backoff_delay(0, base_delay=1.0, jitter=0.0)
        delay_1 = calculate_backoff_delay(1, base_delay=1.0, jitter=0.0)
        delay_2 = calculate_backoff_delay(2, base_delay=1.0, jitter=0.0)

        # 2^0=1, 2^1=2, 2^2=4
        assert delay_0 == 1.0
        assert delay_1 == 2.0
        assert delay_2 == 4.0

    def test_max_delay_cap(self) -> None:
        """Test that delay is capped at max_delay."""
        delay = calculate_backoff_delay(10, base_delay=1.0, max_delay=10.0, jitter=0.0)
        assert delay == 10.0

    def test_jitter_adds_randomness(self) -> None:
        """Test that jitter adds randomness to delay."""
        delays = [calculate_backoff_delay(2, base_delay=1.0, jitter=0.1) for _ in range(100)]

        # With jitter, delays should vary
        assert len(set(delays)) > 1

        # All delays should be roughly around 4.0 ± 10%
        for delay in delays:
            assert 3.6 <= delay <= 4.4

    def test_zero_jitter_deterministic(self) -> None:
        """Test that zero jitter produces deterministic delays."""
        delays = [calculate_backoff_delay(2, base_delay=1.0, jitter=0.0) for _ in range(10)]
        assert len(set(delays)) == 1
        assert delays[0] == 4.0

    def test_negative_delay_prevented(self) -> None:
        """Test that negative delays are prevented."""
        # Even with extreme jitter, delay should be non-negative
        delay = calculate_backoff_delay(0, base_delay=0.1, jitter=1.0)
        assert delay >= 0


class TestRetryDecorator:
    """Tests for retry decorator."""

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self) -> None:
        """Test that function succeeds on first attempt without retry."""
        call_count = 0

        @with_retry(max_attempts=3)
        async def succeeds_immediately() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = await succeeds_immediately()
        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_connection_error(self) -> None:
        """Test retry on ConnectionError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_twice() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Network error")
            return "success"

        result = await fails_twice()
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_retry_on_timeout_error(self) -> None:
        """Test retry on TimeoutError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_timeout() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise TimeoutError("Request timeout")
            return "success"

        result = await fails_with_timeout()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_on_asyncio_timeout_error(self) -> None:
        """Test retry on asyncio.TimeoutError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_asyncio_timeout() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise TimeoutError()
            return "success"

        result = await fails_with_asyncio_timeout()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_on_os_error(self) -> None:
        """Test retry on OSError (network switch scenarios)."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_os_error() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise OSError("Network unreachable")
            return "success"

        result = await fails_with_os_error()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_on_ssl_error(self) -> None:
        """Test retry on SSL errors."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_ssl_error() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ssl.SSLError("SSL handshake failed")
            return "success"

        result = await fails_with_ssl_error()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_no_retry_on_cancelled_error(self) -> None:
        """Test that CancelledError is not retried (propagates immediately)."""
        call_count = 0

        @with_retry(max_attempts=3)
        async def raises_cancelled() -> str:
            nonlocal call_count
            call_count += 1
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await raises_cancelled()

        # Should not retry - only called once
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_failure_after_max_attempts(self) -> None:
        """Test that exception is raised after max attempts exhausted."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def always_fails() -> str:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Always fails")

        with pytest.raises(ConnectionError, match="Always fails"):
            await always_fails()

        assert call_count == 3

    @pytest.mark.asyncio
    async def test_exponential_backoff_delays(self) -> None:
        """Test that delays grow exponentially between retries."""
        call_times: list[float] = []

        @with_retry(max_attempts=3, base_delay=0.1, jitter=0.0)
        async def fails_twice() -> str:
            call_times.append(asyncio.get_event_loop().time())
            if len(call_times) < 3:
                raise ConnectionError("Retry me")
            return "success"

        await fails_twice()

        # Calculate delays between attempts
        assert len(call_times) == 3
        delay_1 = call_times[1] - call_times[0]
        delay_2 = call_times[2] - call_times[1]

        # Delays should follow exponential pattern: ~0.1s, ~0.2s
        assert 0.08 <= delay_1 <= 0.12  # ~0.1s (base_delay * 2^0)
        assert 0.18 <= delay_2 <= 0.22  # ~0.2s (base_delay * 2^1)

    @pytest.mark.asyncio
    async def test_custom_retryable_exceptions(self) -> None:
        """Test that custom retryable exceptions work."""

        class CustomError(Exception):
            pass

        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01, retryable_exceptions=(CustomError,))
        async def fails_with_custom_error() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise CustomError("Custom error")
            return "success"

        result = await fails_with_custom_error()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_non_retryable_exception_not_caught(self) -> None:
        """Test that non-retryable exceptions are not caught."""

        @with_retry(max_attempts=3, base_delay=0.01)
        async def raises_value_error() -> str:
            raise ValueError("Not retryable")

        with pytest.raises(ValueError, match="Not retryable"):
            await raises_value_error()

    @pytest.mark.asyncio
    async def test_operation_name_in_logs(self) -> None:
        """Test that operation_name appears in log messages."""
        call_count = 0

        @with_retry(max_attempts=2, base_delay=0.01, operation_name="test_operation")
        async def fails_once() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Fail once")
            return "success"

        with patch("chatfilter.telegram.retry.logger") as mock_logger:
            await fails_once()
            # Check that warning was logged with operation name
            mock_logger.warning.assert_called()
            call_args = str(mock_logger.warning.call_args)
            assert "test_operation" in call_args


class TestConvenienceDecorators:
    """Tests for convenience decorator variants."""

    @pytest.mark.asyncio
    async def test_with_retry_for_reads(self) -> None:
        """Test that read decorator uses appropriate defaults."""
        call_count = 0

        @with_retry_for_reads()
        async def read_operation() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Network error")
            return "data"

        result = await read_operation()
        assert result == "data"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_with_retry_for_writes(self) -> None:
        """Test that write decorator uses conservative defaults."""
        call_count = 0

        @with_retry_for_writes()
        async def write_operation() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("Network error")
            return "written"

        result = await write_operation()
        assert result == "written"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_write_decorator_more_conservative(self) -> None:
        """Test that write decorator has fewer attempts than read decorator."""
        read_call_count = 0
        write_call_count = 0

        @with_retry_for_reads()
        async def read_op() -> None:
            nonlocal read_call_count
            read_call_count += 1
            raise ConnectionError()

        @with_retry_for_writes()
        async def write_op() -> None:
            nonlocal write_call_count
            write_call_count += 1
            raise ConnectionError()

        with pytest.raises(ConnectionError):
            await read_op()

        with pytest.raises(ConnectionError):
            await write_op()

        # Write should be more conservative (fewer attempts)
        # Default: reads=3, writes=2
        assert read_call_count == 3
        assert write_call_count == 2


class TestRetryIntegration:
    """Integration tests for retry logic."""

    @pytest.mark.asyncio
    async def test_multiple_concurrent_retries(self) -> None:
        """Test that multiple concurrent operations with retries work correctly."""
        call_counts = {"op1": 0, "op2": 0, "op3": 0}

        @with_retry(max_attempts=3, base_delay=0.01)
        async def operation(name: str) -> str:
            call_counts[name] += 1
            if call_counts[name] < 2:
                raise ConnectionError(f"{name} failed")
            return f"{name} success"

        # Run multiple operations concurrently
        results = await asyncio.gather(
            operation("op1"),
            operation("op2"),
            operation("op3"),
        )

        assert results == ["op1 success", "op2 success", "op3 success"]
        assert all(count == 2 for count in call_counts.values())

    @pytest.mark.asyncio
    async def test_timeout_with_retry(self) -> None:
        """Test retry behavior with asyncio.wait_for timeout."""

        @with_retry(max_attempts=2, base_delay=0.01)
        async def slow_operation() -> str:
            await asyncio.sleep(0.5)
            return "success"

        # First attempt times out, but retry succeeds quickly
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def sometimes_slow() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise TimeoutError()
            return "success"

        result = await sometimes_slow()
        assert result == "success"
        assert call_count == 2
