"""Retry logic for Telegram API calls with FloodWait and account reassignment.

This module provides retry mechanisms for handling:
- FloodWait errors with backoff
- Account bans requiring reassignment
- Cumulative timeout tracking per chat
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, TypeVar

from telethon import errors

from chatfilter.utils.network import detect_network_error

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    """Configuration for retry behavior.

    Attributes:
        max_retries: Maximum number of retries for a single operation.
        max_floodwait_seconds: Maximum FloodWait duration to tolerate (skip if longer).
        max_chat_timeout: Maximum cumulative wait time per chat across all retries.
        backoff_buffer_percent: Safety buffer added to FloodWait duration (e.g., 0.1 = 10%).
        max_global_retries: Maximum number of global retries when all accounts are rate-limited.
    """

    max_retries: int = 5
    max_floodwait_seconds: int = 1800  # 30 minutes
    max_chat_timeout: int = 600  # 10 minutes cumulative
    backoff_buffer_percent: float = 0.1  # 10% safety buffer
    max_global_retries: int = 3  # Global retry limit when all accounts hit FloodWait


@dataclass(frozen=True)
class RetryResult:
    """Result of a retry operation.

    Attributes:
        success: Whether the operation succeeded.
        value: The returned value if successful.
        error: Error message if failed.
        account_used: Account ID that succeeded (if any).
        tried_accounts: List of accounts that were tried.
    """

    success: bool
    value: Any = None
    error: str | None = None
    account_used: str | None = None
    tried_accounts: list[str] | None = None


def select_next_account(
    tried_accounts: set[str],
    all_accounts: list[str],
) -> str | None:
    """Select next untried account for reassignment.

    Args:
        tried_accounts: Set of account IDs already tried.
        all_accounts: List of all available account IDs.

    Returns:
        Next untried account ID, or None if all exhausted.
    """
    untried = set(all_accounts) - tried_accounts
    if not untried:
        return None
    # Deterministic selection: sort and pick first
    return sorted(untried)[0]


def should_retry_floodwait(
    wait_seconds: int,
    cumulative_wait: float,
    policy: RetryPolicy,
) -> tuple[bool, str | None]:
    """Check if FloodWait should be retried or skipped.

    Args:
        wait_seconds: FloodWait duration from Telegram.
        cumulative_wait: Total wait time already spent on this chat.
        policy: Retry policy configuration.

    Returns:
        Tuple of (should_retry, reason_if_not).
        - should_retry: True if retry is safe, False if should skip.
        - reason_if_not: Error message if should not retry.
    """
    # Check if single FloodWait exceeds limit
    if wait_seconds > policy.max_floodwait_seconds:
        return False, f"FloodWait too long: {wait_seconds}s (limit: {policy.max_floodwait_seconds}s)"

    # Calculate new cumulative wait with buffer
    buffer = int(wait_seconds * policy.backoff_buffer_percent)
    total_wait = wait_seconds + buffer
    new_cumulative = cumulative_wait + total_wait

    # Check if cumulative wait would exceed timeout
    if new_cumulative > policy.max_chat_timeout:
        return False, f"Timeout exceeded: {int(cumulative_wait)}s cumulative (limit: {policy.max_chat_timeout}s)"

    return True, None


async def try_with_retry(
    fn: Callable[[str, dict], Awaitable[T]],
    chat: dict,
    accounts: list[str],
    policy: RetryPolicy | None = None,
) -> RetryResult:
    """Execute function with retry logic for FloodWait and account reassignment.

    This function:
    1. Tries each account in sequence
    2. Handles FloodWait with backoff (if within limits)
    3. Reassigns to next account on ban
    4. Tracks cumulative wait time per chat
    5. When all accounts hit FloodWait, waits for minimum FloodWait and retries
    6. Returns result or exhaustion error

    Args:
        fn: Async function to execute. Signature: fn(account_id, chat) -> result.
        chat: Chat dictionary containing at least {"id": str, "chat_ref": str}.
        accounts: List of account IDs to try in order.
        policy: Retry policy (uses defaults if None).

    Returns:
        RetryResult with success status, value/error, and account info.

    Example:
        >>> async def fetch_chat(account_id: str, chat: dict):
        ...     # Some Telegram API call
        ...     return await client.get_entity(chat["chat_ref"])
        >>> result = await try_with_retry(
        ...     fetch_chat,
        ...     {"id": "chat-123", "chat_ref": "https://t.me/test"},
        ...     ["account1", "account2"],
        ... )
        >>> if result.success:
        ...     print(f"Success with {result.account_used}")
        ... else:
        ...     print(f"Failed: {result.error}")
    """
    if not policy:
        policy = RetryPolicy()

    chat_id = chat["id"]
    chat_ref = chat.get("chat_ref", chat_id)
    cumulative_wait: float = 0.0
    tried_accounts: list[str] = []
    global_retry_count = 0

    while True:
        # Track FloodWait expiry times per account
        floodwait_expires: dict[str, float] = {}
        had_non_floodwait_error = False
        accounts_tried_this_round = 0

        for account_id in accounts:
            # Skip accounts already tried in this round
            if account_id in tried_accounts:
                continue

            tried_accounts.append(account_id)
            accounts_tried_this_round += 1
            retry_count = 0

            while retry_count < policy.max_retries:
                try:
                    # Execute the function
                    result = await fn(account_id, chat)
                    logger.info(
                        f"Account '{account_id}' succeeded on '{chat_ref}' "
                        f"(attempt {retry_count + 1}/{policy.max_retries})"
                    )
                    return RetryResult(
                        success=True,
                        value=result,
                        account_used=account_id,
                        tried_accounts=tried_accounts,
                    )

                except errors.FloodWaitError as e:
                    wait_seconds = getattr(e, "seconds", 0)
                    retry_count += 1

                    # Check if we should retry this FloodWait
                    should_retry, skip_reason = should_retry_floodwait(
                        wait_seconds, cumulative_wait, policy,
                    )

                    if not should_retry:
                        logger.warning(
                            f"Account '{account_id}' on '{chat_ref}': {skip_reason}. "
                            f"Trying next account (attempt {retry_count}/{policy.max_retries})."
                        )
                        had_non_floodwait_error = True
                        break  # Move to next account

                    # Check if we've exhausted retries for this account
                    if retry_count >= policy.max_retries:
                        logger.warning(
                            f"Account '{account_id}' on '{chat_ref}': "
                            f"FloodWait retries exhausted ({policy.max_retries}). "
                            f"Trying next account."
                        )
                        # Track when this account will be available
                        buffer = int(wait_seconds * policy.backoff_buffer_percent)
                        total_wait = wait_seconds + buffer
                        floodwait_expires[account_id] = time.time() + total_wait
                        break  # Move to next account

                    # Wait with buffer
                    buffer = int(wait_seconds * policy.backoff_buffer_percent)
                    total_wait = wait_seconds + buffer
                    cumulative_wait += total_wait

                    logger.warning(
                        f"Account '{account_id}' on '{chat_ref}': FloodWait {wait_seconds}s "
                        f"(attempt {retry_count}/{policy.max_retries}). "
                        f"Waiting {total_wait}s... (cumulative: {int(cumulative_wait)}s/{policy.max_chat_timeout}s)"
                    )

                    await asyncio.sleep(total_wait)
                    # Retry with same account (don't increment tried_accounts)

                except (
                    errors.ChannelBannedError,
                    errors.ChannelPrivateError,
                    errors.UserBannedInChannelError,
                ) as e:
                    logger.warning(
                        f"Account '{account_id}' banned in '{chat_ref}': {e}. "
                        f"Trying next account."
                    )
                    had_non_floodwait_error = True
                    break  # Move to next account

                except Exception as e:
                    # Check if this is a network error
                    if detect_network_error(e):
                        # Network error: try next account (don't propagate)
                        logger.warning(
                            f"Account '{account_id}' on '{chat_ref}': network error: {e}. "
                            f"Trying next account."
                        )
                        had_non_floodwait_error = True
                        break  # Move to next account
                    else:
                        # Unknown error — do not retry with this account
                        logger.error(
                            f"Account '{account_id}' on '{chat_ref}': unexpected error: {e}. "
                            f"Trying next account.",
                            exc_info=True,
                        )
                        had_non_floodwait_error = True
                        break  # Move to next account

        # Check if all accounts tried this round hit FloodWait (no other errors)
        if floodwait_expires and not had_non_floodwait_error and len(floodwait_expires) == accounts_tried_this_round:
            # All accounts are rate-limited — wait for minimum FloodWait
            min_wait_account = min(floodwait_expires.items(), key=lambda x: x[1])
            account_id, expiry_time = min_wait_account
            wait_duration = max(0, expiry_time - time.time())

            global_retry_count += 1
            if global_retry_count >= policy.max_global_retries:
                logger.error(
                    f"All accounts rate-limited for '{chat_ref}', max global retries exhausted. "
                    f"Chat stays PENDING for manual resume."
                )
                return RetryResult(
                    success=False,
                    error=f"All accounts rate-limited, max retries ({policy.max_global_retries}) exhausted. Chat PENDING.",
                    tried_accounts=tried_accounts,
                )

            logger.warning(
                f"All accounts rate-limited for '{chat_ref}', waiting {int(wait_duration)}s before retry "
                f"(global retry {global_retry_count}/{policy.max_global_retries})..."
            )

            await asyncio.sleep(wait_duration)

            # Reset tried_accounts to retry from the account with shortest wait
            tried_accounts = []
            continue  # Retry with all accounts

        # Mixed errors or all accounts exhausted with non-FloodWait errors
        break

    # All accounts exhausted
    error_msg = f"All {len(tried_accounts)} accounts exhausted for '{chat_ref}'"
    logger.error(error_msg)
    return RetryResult(
        success=False,
        error=error_msg,
        tried_accounts=tried_accounts,
    )
