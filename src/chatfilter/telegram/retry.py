"""Retry logic with exponential backoff for Telegram network operations."""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
from functools import wraps
from typing import Callable, TypeVar, ParamSpec

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
    ConnectionError,
    TimeoutError,
    asyncio.TimeoutError,
    OSError,
    ssl.SSLError,
)

# Exceptions that should never be retried
NON_RETRYABLE_EXCEPTIONS = (
    asyncio.CancelledError,
)


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

    return max(0, delay)  # Ensure non-negative


def with_retry(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    jitter: float = DEFAULT_JITTER,
    retryable_exceptions: tuple[type[Exception], ...] = RETRYABLE_EXCEPTIONS,
    operation_name: str | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator to add retry logic with exponential backoff to async functions.

    Only retries on network-related exceptions (ConnectionError, TimeoutError, OSError, SSL errors).
    Never retries on asyncio.CancelledError (propagates immediately for graceful shutdown).

    Args:
        max_attempts: Maximum number of attempts (including first try)
        base_delay: Base delay in seconds for exponential backoff
        max_delay: Maximum delay in seconds between retries
        jitter: Jitter factor (0.0 to 1.0) to randomize delays
        retryable_exceptions: Tuple of exception types that should trigger retry
        operation_name: Optional name for logging (defaults to function name)

    Returns:
        Decorated async function with retry logic

    Example:
        @with_retry(max_attempts=3, base_delay=1.0)
        async def fetch_messages():
            # Network operation that may fail
            pass
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            op_name = operation_name or func.__name__
            last_exception: Exception | None = None

            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except NON_RETRYABLE_EXCEPTIONS:
                    # Don't retry on CancelledError - propagate immediately
                    logger.debug(
                        f"{op_name}: CancelledError received, not retrying"
                    )
                    raise
                except retryable_exceptions as e:
                    last_exception = e
                    is_final_attempt = attempt == max_attempts - 1

                    if is_final_attempt:
                        logger.error(
                            f"{op_name}: Failed after {max_attempts} attempts: {e}"
                        )
                        raise
                    else:
                        delay = calculate_backoff_delay(
                            attempt, base_delay, max_delay, jitter
                        )
                        logger.warning(
                            f"{op_name}: Attempt {attempt + 1}/{max_attempts} failed "
                            f"with {type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
                        )
                        await asyncio.sleep(delay)

            # Should never reach here, but satisfy type checker
            if last_exception:
                raise last_exception
            raise RuntimeError(f"{op_name}: Unexpected retry loop exit")

        return wrapper  # type: ignore

    return decorator


def with_retry_for_reads(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
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


def with_retry_for_writes(
    max_attempts: int = 2,  # More conservative for writes
    base_delay: float = 2.0,  # Longer delays for writes
    max_delay: float = 10.0,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Convenience decorator for write operations (use cautiously, ensure idempotency).

    Uses more conservative retry configuration for write operations.
    Only use this if your write operation is idempotent (safe to retry).

    Args:
        max_attempts: Maximum number of attempts (default: 2, more conservative)
        base_delay: Base delay in seconds (default: 2.0, longer than reads)
        max_delay: Maximum delay in seconds

    Returns:
        Decorated async function with retry logic
    """
    return with_retry(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
    )
