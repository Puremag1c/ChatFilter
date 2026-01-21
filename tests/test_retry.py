"""Tests for retry logic with exponential backoff."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import patch

import pytest
from telethon.errors import (
    FileMigrateError,
    FloodWaitError,
    NetworkMigrateError,
    PhoneMigrateError,
    RpcCallFailError,
    ServerError,
    StatsMigrateError,
    UserMigrateError,
)

from chatfilter.telegram.retry import (
    _format_flood_wait_duration,
    calculate_backoff_delay,
    with_flood_wait_handling,
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


class TestFloodWaitHandling:
    """Tests for FloodWaitError handling in with_retry decorator."""

    @pytest.mark.asyncio
    async def test_flood_wait_success_after_retry(self) -> None:
        """Test that FloodWaitError is retried after waiting."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01, handle_flood_wait=True)
        async def fails_with_flood_wait() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                # Create FloodWaitError with seconds attribute
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 1  # Wait 1 second
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None  # Make sleep instant
            result = await fails_with_flood_wait()
            assert result == "success"
            assert call_count == 2
            # Verify that we slept for the flood wait duration
            mock_sleep.assert_called_with(1)

    @pytest.mark.asyncio
    async def test_flood_wait_disabled(self) -> None:
        """Test that FloodWaitError is not handled when handle_flood_wait=False."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01, handle_flood_wait=False)
        async def raises_flood_wait() -> str:
            nonlocal call_count
            call_count += 1
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 1
            raise error

        with pytest.raises(FloodWaitError):
            await raises_flood_wait()

        # Should not retry when handle_flood_wait is False
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_flood_wait_exceeds_max_wait(self) -> None:
        """Test that FloodWaitError exceeding max_flood_wait is not retried."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01, max_flood_wait=60)
        async def raises_long_flood_wait() -> str:
            nonlocal call_count
            call_count += 1
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 120  # 2 minutes, exceeds max_flood_wait of 60s
            raise error

        with pytest.raises(FloodWaitError):
            await raises_long_flood_wait()

        # Should fail on first attempt
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_flood_wait_on_final_attempt(self) -> None:
        """Test that FloodWaitError on final attempt is raised."""
        call_count = 0

        @with_retry(max_attempts=2, base_delay=0.01)
        async def always_floods() -> str:
            nonlocal call_count
            call_count += 1
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 1
            raise error

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            with pytest.raises(FloodWaitError):
                await always_floods()

        # Should try max_attempts times
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_flood_wait_cancelled_during_sleep(self) -> None:
        """Test that FloodWait sleep can be cancelled."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def raises_flood_wait() -> str:
            nonlocal call_count
            call_count += 1
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 10
            raise error

        async def cancel_sleep(*args, **kwargs):
            raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=cancel_sleep):
            with pytest.raises(asyncio.CancelledError):
                await raises_flood_wait()

        # Should have tried once before cancellation
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_flood_wait_with_explicit_seconds(self) -> None:
        """Test that FloodWaitError with explicit seconds is handled."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def raises_flood_wait_with_seconds() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 5
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await raises_flood_wait_with_seconds()
            assert result == "success"
            # Should use the explicit seconds value
            mock_sleep.assert_called_with(5)


class TestFormatFloodWaitDuration:
    """Tests for _format_flood_wait_duration helper function."""

    def test_format_seconds(self) -> None:
        """Test formatting seconds."""
        assert _format_flood_wait_duration(1) == "1 second"
        assert _format_flood_wait_duration(30) == "30 seconds"
        assert _format_flood_wait_duration(59) == "59 seconds"

    def test_format_minutes(self) -> None:
        """Test formatting minutes."""
        assert _format_flood_wait_duration(60) == "1 minute"
        assert _format_flood_wait_duration(120) == "2 minutes"
        assert _format_flood_wait_duration(300) == "5 minutes"
        assert _format_flood_wait_duration(3599) == "59 minutes"

    def test_format_hours(self) -> None:
        """Test formatting hours."""
        assert _format_flood_wait_duration(3600) == "1 hour"
        assert _format_flood_wait_duration(7200) == "2 hours"

    def test_format_hours_and_minutes(self) -> None:
        """Test formatting hours and minutes."""
        assert _format_flood_wait_duration(3660) == "1 hour 1 minute"
        assert _format_flood_wait_duration(3720) == "1 hour 2 minutes"
        assert _format_flood_wait_duration(7260) == "2 hours 1 minute"
        assert _format_flood_wait_duration(7320) == "2 hours 2 minutes"


class TestWithFloodWaitHandlingDecorator:
    """Tests for with_flood_wait_handling decorator."""

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self) -> None:
        """Test successful operation without FloodWait."""
        call_count = 0

        @with_flood_wait_handling()
        async def succeeds() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        result = await succeeds()
        assert result == "success"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_handles_flood_wait(self) -> None:
        """Test handling FloodWaitError."""
        call_count = 0

        @with_flood_wait_handling(max_attempts=3)
        async def floods_once() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 1
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await floods_once()
            assert result == "success"
            assert call_count == 2

    @pytest.mark.asyncio
    async def test_exponential_backoff_enabled(self) -> None:
        """Test exponential backoff on subsequent FloodWait attempts."""
        call_count = 0

        @with_flood_wait_handling(max_attempts=3, use_exponential_backoff=True)
        async def floods_twice() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 10
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await floods_twice()
            assert result == "success"

            # Check that backoff was applied
            calls = [call.args[0] for call in mock_sleep.call_args_list]
            assert len(calls) == 2
            # First attempt: 10s (no backoff)
            assert calls[0] == 10
            # Second attempt: 10 * 1.5 = 15s (with backoff multiplier)
            assert calls[1] == 15

    @pytest.mark.asyncio
    async def test_exponential_backoff_disabled(self) -> None:
        """Test that exponential backoff can be disabled."""
        call_count = 0

        @with_flood_wait_handling(max_attempts=3, use_exponential_backoff=False)
        async def floods_twice() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 10
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await floods_twice()
            assert result == "success"

            # All waits should be the same (no backoff)
            calls = [call.args[0] for call in mock_sleep.call_args_list]
            assert all(wait == 10 for wait in calls)

    @pytest.mark.asyncio
    async def test_max_flood_wait_limit(self) -> None:
        """Test that max_flood_wait is enforced."""

        @with_flood_wait_handling(max_flood_wait=30)
        async def long_flood() -> str:
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 60  # Exceeds max_flood_wait
            raise error

        with pytest.raises(FloodWaitError):
            await long_flood()

    @pytest.mark.asyncio
    async def test_cancelled_error_not_retried(self) -> None:
        """Test that CancelledError is not retried."""
        call_count = 0

        @with_flood_wait_handling()
        async def raises_cancelled() -> str:
            nonlocal call_count
            call_count += 1
            raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await raises_cancelled()

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_cancelled_during_flood_wait(self) -> None:
        """Test cancellation during FloodWait sleep."""

        @with_flood_wait_handling()
        async def floods() -> str:
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 10
            raise error

        async def cancel_sleep(*args, **kwargs):
            raise asyncio.CancelledError()

        with patch("asyncio.sleep", side_effect=cancel_sleep):
            with pytest.raises(asyncio.CancelledError):
                await floods()

    @pytest.mark.asyncio
    async def test_final_attempt_flood_wait(self) -> None:
        """Test that FloodWait on final attempt is raised."""
        call_count = 0

        @with_flood_wait_handling(max_attempts=2)
        async def always_floods() -> str:
            nonlocal call_count
            call_count += 1
            error = FloodWaitError("FLOOD_WAIT_X")
            error.seconds = 1
            raise error

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            with pytest.raises(FloodWaitError):
                await always_floods()

        assert call_count == 2

    @pytest.mark.asyncio
    async def test_flood_wait_with_explicit_seconds(self) -> None:
        """Test handling FloodWait with explicit seconds."""
        call_count = 0

        @with_flood_wait_handling()
        async def floods_with_seconds() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 5
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await floods_with_seconds()
            assert result == "success"
            # Should use the explicit seconds value
            mock_sleep.assert_called_with(5)

    @pytest.mark.asyncio
    async def test_backoff_capped_at_max_flood_wait(self) -> None:
        """Test that exponential backoff doesn't exceed max_flood_wait."""
        call_count = 0

        @with_flood_wait_handling(max_attempts=3, max_flood_wait=20, use_exponential_backoff=True)
        async def floods_twice() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                error = FloodWaitError("FLOOD_WAIT_X")
                error.seconds = 15
                raise error
            return "success"

        with patch("asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await floods_twice()
            assert result == "success"

            calls = [call.args[0] for call in mock_sleep.call_args_list]
            # First: 15s, Second would be 15*1.5=22.5s but capped at 20s
            assert calls[0] == 15
            assert calls[1] == 20  # Capped at max_flood_wait


class TestTelethonErrorRetries:
    """Tests for retrying Telethon-specific errors."""

    @pytest.mark.asyncio
    async def test_retry_broken_pipe_error(self) -> None:
        """Test retry on BrokenPipeError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_broken_pipe() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise BrokenPipeError()
            return "success"

        result = await fails_with_broken_pipe()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_connection_reset_error(self) -> None:
        """Test retry on ConnectionResetError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_reset() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionResetError()
            return "success"

        result = await fails_with_reset()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_connection_aborted_error(self) -> None:
        """Test retry on ConnectionAbortedError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_aborted() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionAbortedError()
            return "success"

        result = await fails_with_aborted()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_connection_refused_error(self) -> None:
        """Test retry on ConnectionRefusedError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_refused() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionRefusedError()
            return "success"

        result = await fails_with_refused()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_file_migrate_error(self) -> None:
        """Test retry on FileMigrateError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_file_migrate() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise FileMigrateError("FILE_MIGRATE_X")
            return "success"

        result = await fails_with_file_migrate()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_network_migrate_error(self) -> None:
        """Test retry on NetworkMigrateError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_network_migrate() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise NetworkMigrateError("NETWORK_MIGRATE_X")
            return "success"

        result = await fails_with_network_migrate()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_phone_migrate_error(self) -> None:
        """Test retry on PhoneMigrateError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_phone_migrate() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise PhoneMigrateError("PHONE_MIGRATE_X")
            return "success"

        result = await fails_with_phone_migrate()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_user_migrate_error(self) -> None:
        """Test retry on UserMigrateError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_user_migrate() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise UserMigrateError("USER_MIGRATE_X")
            return "success"

        result = await fails_with_user_migrate()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_stats_migrate_error(self) -> None:
        """Test retry on StatsMigrateError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_stats_migrate() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise StatsMigrateError("STATS_MIGRATE_X")
            return "success"

        result = await fails_with_stats_migrate()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_rpc_call_fail_error(self) -> None:
        """Test retry on RpcCallFailError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_rpc_fail() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RpcCallFailError("RPC_CALL_FAIL")
            return "success"

        result = await fails_with_rpc_fail()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_server_error(self) -> None:
        """Test retry on ServerError."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def fails_with_server_error() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                # ServerError requires request and message parameters
                raise ServerError(request=None, message="INTERNAL")
            return "success"

        result = await fails_with_server_error()
        assert result == "success"
        assert call_count == 2


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    @pytest.mark.asyncio
    async def test_max_attempts_one(self) -> None:
        """Test that max_attempts=1 means no retries."""
        call_count = 0

        @with_retry(max_attempts=1, base_delay=0.01)
        async def fails() -> str:
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Fail")

        with pytest.raises(ConnectionError):
            await fails()

        # Should only be called once (no retries)
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_custom_operation_name(self) -> None:
        """Test custom operation_name is used in logs."""

        @with_retry(max_attempts=2, base_delay=0.01, operation_name="custom_op")
        async def fails() -> str:
            raise ConnectionError("Fail")

        with patch("chatfilter.telegram.retry.logger") as mock_logger:
            with pytest.raises(ConnectionError):
                await fails()

            # Check that custom operation name was logged
            assert mock_logger.error.called
            error_call = str(mock_logger.error.call_args)
            assert "custom_op" in error_call

    @pytest.mark.asyncio
    async def test_zero_base_delay(self) -> None:
        """Test that zero base delay works."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.0)
        async def fails_twice() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError()
            return "success"

        result = await fails_twice()
        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_very_large_max_delay(self) -> None:
        """Test that very large max_delay doesn't cause issues."""
        call_count = 0

        @with_retry(max_attempts=2, base_delay=0.01, max_delay=1000000.0)
        async def fails_once() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError()
            return "success"

        result = await fails_once()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_function_with_args_and_kwargs(self) -> None:
        """Test that decorated function preserves args and kwargs."""
        call_count = 0

        @with_retry(max_attempts=3, base_delay=0.01)
        async def func_with_params(a: int, b: str, c: int = 10) -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError()
            return f"{a}-{b}-{c}"

        result = await func_with_params(1, "test", c=20)
        assert result == "1-test-20"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_decorated_function_preserves_name(self) -> None:
        """Test that decorator preserves function name."""

        @with_retry()
        async def my_function() -> str:
            return "test"

        assert my_function.__name__ == "my_function"

    @pytest.mark.asyncio
    async def test_multiple_exception_types_in_sequence(self) -> None:
        """Test handling different retryable exceptions in sequence."""
        call_count = 0

        @with_retry(max_attempts=5, base_delay=0.01)
        async def fails_with_different_errors() -> str:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError()
            elif call_count == 2:
                raise TimeoutError()
            elif call_count == 3:
                raise OSError()
            elif call_count == 4:
                raise ssl.SSLError()
            return "success"

        result = await fails_with_different_errors()
        assert result == "success"
        assert call_count == 5
