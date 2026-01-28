"""Retry logic with exponential backoff for Telegram network operations."""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import ParamSpec, TypeVar

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

logger = logging.getLogger(__name__)

# Type variables for generic decorator
P = ParamSpec("P")
T = TypeVar("T")

# Default retry configuration
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_MAX_DELAY = 30.0  # seconds
DEFAULT_JITTER = 0.1  # 10% jitter

# Exceptions that should trigger retry
RETRYABLE_EXCEPTIONS = (
    # Network errors
    ConnectionError,
    TimeoutError,
    asyncio.TimeoutError,
    OSError,
    ssl.SSLError,
    # TCP connection reset errors during network switches (Wi-Fi↔mobile, VPN on/off)
    # These are explicit for clarity, though covered by ConnectionError/OSError
    BrokenPipeError,  # TCP connection broken mid-operation
    ConnectionResetError,  # Connection explicitly reset by peer
    ConnectionAbortedError,  # Connection aborted by local system
    ConnectionRefusedError,  # Temporary refusal during network transition
    # DC migration errors - Telethon handles these automatically, but they can
    # cause temporary failures during the migration window
    FileMigrateError,
    NetworkMigrateError,
    PhoneMigrateError,
    UserMigrateError,
    StatsMigrateError,
    # RPC/Server errors - transient failures that should be retried
    RpcCallFailError,
    ServerError,
)

# Exceptions that should never be retried
NON_RETRYABLE_EXCEPTIONS = (asyncio.CancelledError,)


def calculate_backoff_delay(
    attempt: int,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: float = DEFAULT_JITTER,
) -> float:
    """Calculate exponential backoff delay with jitter.

    Args:
        attempt: Current attempt number (0-indexed)
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds
        jitter: Jitter factor (0.0 to 1.0)

    Returns:
        Delay in seconds before next retry
    """
    # Exponential backoff: base_delay * 2^attempt
    delay = min(base_delay * (2**attempt), max_delay)

    # Add jitter: randomize ±jitter% of delay
    if jitter > 0:
        jitter_amount = delay * jitter
        delay += random.uniform(-jitter_amount, jitter_amount)

    return float(max(0, delay))  # Ensure non-negative


def with_retry(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: float = DEFAULT_JITTER,
    retryable_exceptions: tuple[type[Exception], ...] = RETRYABLE_EXCEPTIONS,
    operation_name: str | None = None,
    handle_flood_wait: bool = True,
    max_flood_wait: int = 3600,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Decorator to add retry logic with exponential backoff to async functions.

    Retries on network-related exceptions (ConnectionError, TimeoutError, OSError, SSL errors).
    Also handles FloodWaitError by waiting for the specified time before retry.
    Never retries on asyncio.CancelledError (propagates immediately for graceful shutdown).

    Args:
        max_attempts: Maximum number of attempts (including first try)
        base_delay: Base delay in seconds for exponential backoff
        max_delay: Maximum delay in seconds between retries
        jitter: Jitter factor (0.0 to 1.0) to randomize delays
        retryable_exceptions: Tuple of exception types that should trigger retry
        operation_name: Optional name for logging (defaults to function name)
        handle_flood_wait: If True, automatically handle FloodWaitError (default: True)
        max_flood_wait: Maximum seconds to wait for FloodWait (default: 3600 = 1 hour)

    Returns:
        Decorated async function with retry logic

    Example:
        @with_retry(max_attempts=3, base_delay=1.0)
        async def fetch_messages():
            # Network operation that may fail
            pass
    """

    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            op_name = operation_name or func.__name__
            last_exception: Exception | None = None

            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except NON_RETRYABLE_EXCEPTIONS:
                    # Don't retry on CancelledError - propagate immediately
                    logger.debug(f"{op_name}: CancelledError received, not retrying")
                    raise
                except FloodWaitError as e:
                    if not handle_flood_wait:
                        # If FloodWait handling is disabled, propagate immediately
                        raise

                    last_exception = e
                    is_final_attempt = attempt == max_attempts - 1

                    # Extract wait time from FloodWaitError
                    wait_seconds = getattr(e, "seconds", 60)  # Default to 60s if not found

                    # Check if wait time exceeds max_flood_wait
                    if wait_seconds > max_flood_wait:
                        duration_str = _format_flood_wait_duration(wait_seconds)
                        max_duration_str = _format_flood_wait_duration(max_flood_wait)
                        logger.error(
                            f"{op_name}: FloodWait requires {duration_str} "
                            f"which exceeds maximum allowed wait of {max_duration_str}. "
                            f"Aborting operation."
                        )
                        raise

                    if is_final_attempt:
                        duration_str = _format_flood_wait_duration(wait_seconds)
                        logger.error(
                            f"{op_name}: FloodWait persists after {max_attempts} attempts. "
                            f"Last wait was {duration_str}. Aborting."
                        )
                        raise

                    # Log user-friendly message about the wait
                    duration_str = _format_flood_wait_duration(wait_seconds)
                    logger.warning(
                        f"{op_name}: Rate limited by Telegram (FloodWait). "
                        f"Attempt {attempt + 1}/{max_attempts}. "
                        f"Waiting {duration_str} before retry... "
                        f"(Operation can be cancelled if needed)"
                    )

                    try:
                        # Wait for the exact time specified by Telegram (interruptible by cancellation)
                        await asyncio.sleep(wait_seconds)
                    except asyncio.CancelledError:
                        logger.info(f"{op_name}: FloodWait cancelled by user")
                        raise

                    logger.info(f"{op_name}: Resuming after FloodWait delay...")

                except retryable_exceptions as e:
                    last_exception = e
                    is_final_attempt = attempt == max_attempts - 1

                    if is_final_attempt:
                        logger.error(f"{op_name}: Failed after {max_attempts} attempts: {e}")
                        raise
                    else:
                        delay = calculate_backoff_delay(attempt, base_delay, max_delay, jitter)
                        logger.warning(
                            f"{op_name}: Attempt {attempt + 1}/{max_attempts} failed "
                            f"with {type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
                        )
                        await asyncio.sleep(delay)

            # Should never reach here, but satisfy type checker
            if last_exception:
                raise last_exception
            raise RuntimeError(f"{op_name}: Unexpected retry loop exit")

        return wrapper

    return decorator


def with_retry_for_reads(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Convenience decorator for read operations (idempotent, safe to retry).

    Uses default retry configuration optimized for read operations.

    Args:
        max_attempts: Maximum number of attempts
        base_delay: Base delay in seconds
        max_delay: Maximum delay in seconds

    Returns:
        Decorated async function with retry logic
    """
    return with_retry(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
    )


def _format_flood_wait_duration(seconds: int) -> str:
    """Format FloodWait duration for user-friendly logging.

    Args:
        seconds: Duration in seconds

    Returns:
        Human-readable duration string
    """
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours = seconds // 3600
        remainder_minutes = (seconds % 3600) // 60
        if remainder_minutes > 0:
            return f"{hours} hour{'s' if hours != 1 else ''} {remainder_minutes} minute{'s' if remainder_minutes != 1 else ''}"
        return f"{hours} hour{'s' if hours != 1 else ''}"


class RetryContext:
    """Context for retry loops with exponential backoff inside functions.

    Unlike the @with_retry decorator which wraps an entire function,
    RetryContext is designed for cases where retry logic needs to be
    embedded within a larger function with partial result collection.

    Example:
        retry = RetryContext(max_attempts=3, operation_name="fetch messages")
        while retry.should_continue():
            try:
                # fetch some data with resume capability
                break  # success
            except RETRYABLE_EXCEPTIONS as e:
                await retry.handle_exception(e)

        if retry.was_interrupted:
            logger.info(f"Returning partial results after {retry.attempts} attempts")
    """

    def __init__(
        self,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_delay: float = DEFAULT_BASE_DELAY,
        max_delay: float = DEFAULT_MAX_DELAY,
        jitter: float = DEFAULT_JITTER,
        retryable_exceptions: tuple[type[Exception], ...] = RETRYABLE_EXCEPTIONS,
        operation_name: str = "operation",
    ):
        """Initialize retry context.

        Args:
            max_attempts: Maximum number of attempts (including first try)
            base_delay: Base delay in seconds for exponential backoff
            max_delay: Maximum delay in seconds between retries
            jitter: Jitter factor (0.0 to 1.0) to randomize delays
            retryable_exceptions: Tuple of exception types that should trigger retry
            operation_name: Name for logging
        """
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions
        self.operation_name = operation_name
        self._attempt = 0
        self._was_interrupted = False
        self._last_exception: Exception | None = None

    @property
    def attempts(self) -> int:
        """Number of attempts made so far."""
        return self._attempt

    @property
    def was_interrupted(self) -> bool:
        """Whether max retries was reached (operation was interrupted)."""
        return self._was_interrupted

    @property
    def last_exception(self) -> Exception | None:
        """The last exception that triggered a retry."""
        return self._last_exception

    def should_continue(self) -> bool:
        """Check if retry loop should continue.

        Returns:
            True if within retry limits, False if max attempts reached.
        """
        return self._attempt < self.max_attempts and not self._was_interrupted

    async def handle_exception(self, exc: Exception, context: str = "") -> bool:
        """Handle an exception and wait before retry if appropriate.

        Args:
            exc: The exception that occurred
            context: Additional context for logging (e.g., "topic 123")

        Returns:
            True if should retry, False if max attempts reached
        """
        self._attempt += 1
        self._last_exception = exc

        ctx_str = f" ({context})" if context else ""
        is_final_attempt = self._attempt >= self.max_attempts

        if is_final_attempt:
            self._was_interrupted = True
            logger.warning(
                f"{self.operation_name}{ctx_str}: Max retries ({self.max_attempts}) reached. "
                f"Last error: {type(exc).__name__}: {exc}"
            )
            return False

        delay = calculate_backoff_delay(
            self._attempt - 1, self.base_delay, self.max_delay, self.jitter
        )
        logger.warning(
            f"{self.operation_name}{ctx_str}: Attempt {self._attempt}/{self.max_attempts} failed "
            f"with {type(exc).__name__}: {exc}. Retrying in {delay:.2f}s..."
        )
        await asyncio.sleep(delay)
        return True

    def reset(self) -> None:
        """Reset retry context for reuse (e.g., for a new topic in same function)."""
        self._attempt = 0
        self._was_interrupted = False
        self._last_exception = None
