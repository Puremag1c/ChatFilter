"""Telegram message fetching and streaming."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING

from telethon.errors import (
    ChannelBannedError,
    ChannelPrivateError,
    ChatForbiddenError,
    ChatRestrictedError,
    FloodWaitError,
    UserBannedInChannelError,
)
from telethon.tl.functions.messages import GetForumTopicsRequest
from telethon.tl.types import Channel, MessageService

from chatfilter.models.message import Message
from chatfilter.telegram.rate_limiter import get_rate_limiter
from chatfilter.telegram.retry import (
    RETRYABLE_EXCEPTIONS,
    RetryContext,
    with_retry_for_reads,
)

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType
    from telethon.tl.types import Message as TelegramMessage

logger = logging.getLogger(__name__)


# Maximum messages to fetch to protect against OOM
MAX_MESSAGES_LIMIT = 10_000

# Telegram API returns max 100 messages per request
TELEGRAM_BATCH_SIZE = 100


class MessageFetchError(Exception):
    """Raised when fetching messages fails."""


class ChatAccessDeniedError(MessageFetchError):
    """Raised when access to a chat is denied (kicked, banned, left, or chat is private/deleted)."""


def _telethon_message_to_model(msg: TelegramMessage, chat_id: int) -> Message | None:
    """Convert Telethon Message to our Message model.

    Args:
        msg: Telethon Message object
        chat_id: Chat ID this message belongs to

    Returns:
        Message model or None if message is empty/deleted, is a service message,
        or has no sender

    Note:
        Service messages (join, leave, pin, etc.) are filtered out as they are
        system-generated events rather than user-authored content. This ensures
        metrics reflect actual user participation.
    """
    from datetime import UTC

    # Skip service messages (join/leave/pin/etc.)
    # MessageService represents system-generated events, not user messages
    if isinstance(msg, MessageService):
        return None

    # Skip empty/deleted messages (Telethon represents them as MessageEmpty)
    # Check if this is a MessageEmpty (deleted message)
    if (
        getattr(msg, "message", None) is None
        and getattr(msg, "media", None) is None
        and (not hasattr(msg, "date") or msg.date is None)
    ):
        return None

    # Get sender ID - can be None for channel posts without author
    sender_id = getattr(msg, "sender_id", None) or getattr(msg, "from_id", None)
    if sender_id is None:
        # For channel posts and anonymous admins, use the chat's ID as author.
        # This means all anonymous messages in a chat are attributed to one "author"
        # (the chat itself) for unique_authors counting. This is a deliberate design
        # decision to handle anonymous posts consistently without skipping them.
        sender_id = chat_id

    # Handle from_id being a PeerUser/PeerChannel object
    if hasattr(sender_id, "user_id"):
        sender_id = sender_id.user_id
    elif hasattr(sender_id, "channel_id"):
        sender_id = sender_id.channel_id

    # Ensure positive IDs
    sender_id = abs(sender_id) if sender_id else chat_id

    # Get message timestamp
    timestamp = msg.date
    if timestamp is None:
        return None

    # Ensure timezone-aware (Telethon returns UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    # Get message text
    text = msg.message or ""

    return Message(
        id=msg.id,
        chat_id=chat_id,
        author_id=sender_id,
        timestamp=timestamp,
        text=text,
    )


async def _get_forum_topics(
    client: TelegramClientType,
    chat_id: int,
) -> list[int]:
    """Get list of forum topic IDs from a Telegram forum chat.

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the forum chat

    Returns:
        List of topic IDs (message IDs of the first message in each topic)

    Raises:
        Exception: If fetching topics fails
    """
    try:
        # Get forum topics using Telegram API
        result = await client(
            GetForumTopicsRequest(
                channel=chat_id,
                offset_date=0,
                offset_id=0,
                offset_topic=0,
                limit=100,  # Should be enough for most forums
            )
        )

        # Extract topic IDs from the result
        # Each topic has an ID which is the message ID of the first message
        topic_ids = []
        if hasattr(result, "topics"):
            for topic in result.topics:
                # Topic ID is stored in the 'id' attribute
                if hasattr(topic, "id"):
                    topic_ids.append(topic.id)

        return topic_ids
    except Exception as e:
        # If we can't get topics, log and return empty list
        # This allows graceful fallback to default behavior
        logger.debug(f"Failed to get forum topics for chat {chat_id}: {e}")
        return []


async def _fetch_forum_topic_messages(
    client: TelegramClientType,
    chat_id: int,
    topic_ids: list[int],
    effective_limit: int,
    messages: list[Message],
    seen_ids: set[int],
) -> bool:
    """Fetch messages from forum topics.

    Args:
        client: Connected TelegramClient instance
        chat_id: Forum chat ID
        topic_ids: List of topic IDs to fetch from
        effective_limit: Maximum total messages to fetch
        messages: List to append messages to (mutated)
        seen_ids: Set of seen message IDs for deduplication (mutated)

    Returns:
        True if fetch was interrupted by retryable errors
    """
    fetch_interrupted = False
    logger.info(f"Found {len(topic_ids)} topics in forum {chat_id}")

    for topic_id in topic_ids:
        if len(messages) >= effective_limit:
            logger.info(
                f"Reached message limit ({effective_limit}), "
                f"stopping forum topic fetch at topic {topic_id}"
            )
            break

        topic_messages_before = len(messages)
        retry = RetryContext(
            operation_name=f"fetch topic {topic_id}",
            retryable_exceptions=RETRYABLE_EXCEPTIONS,
        )

        while retry.should_continue():
            try:
                topic_msgs = [m for m in messages if m.id not in seen_ids]
                offset_id = (
                    min(m.id for m in topic_msgs if m in messages[topic_messages_before:])
                    if len(messages) > topic_messages_before
                    else 0
                )
                remaining = effective_limit - len(messages)

                async for telethon_msg in client.iter_messages(
                    chat_id,
                    limit=remaining,
                    reply_to=topic_id,
                    offset_id=offset_id if offset_id > 0 else None,
                ):
                    msg = _telethon_message_to_model(telethon_msg, chat_id)
                    if msg is None:
                        continue
                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    messages.append(msg)
                    if len(messages) >= effective_limit:
                        break

                break

            except RETRYABLE_EXCEPTIONS as e:
                fetch_interrupted = True
                await retry.handle_exception(
                    e, f"collected {len(messages) - topic_messages_before} msgs"
                )
            except Exception as e:
                logger.warning(f"Failed to fetch messages from topic {topic_id}: {e}")
                break

    return fetch_interrupted


async def _fetch_regular_chat_messages(
    client: TelegramClientType,
    chat_id: int,
    effective_limit: int,
    messages: list[Message],
    seen_ids: set[int],
    *,
    operation_name: str | None = None,
) -> bool:
    """Fetch messages from a regular (non-forum) chat.

    Args:
        client: Connected TelegramClient instance
        chat_id: Chat ID to fetch from
        effective_limit: Maximum messages to fetch
        messages: List to append messages to (mutated)
        seen_ids: Set of seen message IDs for deduplication (mutated)
        operation_name: Custom operation name for retry context

    Returns:
        True if fetch was interrupted by retryable errors
    """
    fetch_interrupted = False
    retry = RetryContext(
        operation_name=operation_name or f"fetch chat {chat_id}",
        retryable_exceptions=RETRYABLE_EXCEPTIONS,
    )

    while retry.should_continue() and len(messages) < effective_limit:
        try:
            offset_id = min(messages, key=lambda m: m.id).id if messages else 0
            remaining = effective_limit - len(messages)

            async for telethon_msg in client.iter_messages(
                chat_id,
                limit=remaining,
                offset_id=offset_id if offset_id > 0 else None,
            ):
                msg = _telethon_message_to_model(telethon_msg, chat_id)
                if msg is None:
                    continue
                if msg.id in seen_ids:
                    continue
                seen_ids.add(msg.id)
                messages.append(msg)

            break

        except RETRYABLE_EXCEPTIONS as e:
            fetch_interrupted = True
            await retry.handle_exception(e, f"collected {len(messages)}/{effective_limit} msgs")

    return fetch_interrupted


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_messages(
    client: TelegramClientType,
    chat_id: int,
    limit: int = 100,
) -> list[Message]:
    """Get messages from a Telegram chat.

    Fetches messages from the specified chat and converts them to Message models.
    Handles pagination automatically for limits > 100.

    For forum chats (supergroups with topics enabled), this function automatically
    fetches messages from ALL topics and aggregates them. This ensures complete
    statistics and avoids the limitation where get_messages() by default only
    returns messages from the "General" topic.

    Network errors (ConnectionError, TimeoutError, OSError, SSL errors) are
    automatically retried with exponential backoff (up to 3 attempts).

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to fetch messages from
        limit: Maximum number of messages to fetch (default 100, max 10000)
               For forums, this is applied per-topic to ensure coverage across all topics.

    Returns:
        List of Message models, sorted by timestamp (oldest first)

    Raises:
        ChatAccessDeniedError: If access to chat is denied (user kicked/banned/left,
                                or chat is private/deleted)
        MessageFetchError: If chat doesn't exist or other error
        ValueError: If limit is invalid

    Example:
        ```python
        async with loader.create_client() as client:
            # Get last 50 messages (per topic if forum)
            messages = await get_messages(client, chat_id=123, limit=50)

            # Process messages
            for msg in messages:
                print(f"{msg.timestamp}: {msg.text[:50]}")
        ```
    """
    if limit <= 0:
        raise ValueError("limit must be positive")

    # Proactive rate limiting to prevent FloodWaitError
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_messages")

    # Cap at maximum to prevent OOM
    effective_limit = min(limit, MAX_MESSAGES_LIMIT)

    messages: list[Message] = []
    seen_ids: set[int] = set()
    fetch_interrupted = False

    try:
        # Check if this is a forum chat by getting the entity
        entity = await client.get_entity(chat_id)
        is_forum = (
            isinstance(entity, Channel)
            and getattr(entity, "megagroup", False)
            and getattr(entity, "forum", False)
        )

        if is_forum:
            # For forums, fetch messages from all topics
            logger.info(f"Chat {chat_id} is a forum, fetching from all topics")
            topic_ids = await _get_forum_topics(client, chat_id)

            if topic_ids:
                fetch_interrupted = await _fetch_forum_topic_messages(
                    client, chat_id, topic_ids, effective_limit, messages, seen_ids
                )
            else:
                # No topics found or error getting topics, fall back to default behavior
                logger.info(f"No topics found for forum {chat_id}, using default fetch")
                fetch_interrupted = await _fetch_regular_chat_messages(
                    client,
                    chat_id,
                    effective_limit,
                    messages,
                    seen_ids,
                    operation_name=f"fetch forum {chat_id}",
                )
        else:
            # Regular chat, use standard fetch with resume capability
            fetch_interrupted = await _fetch_regular_chat_messages(
                client, chat_id, effective_limit, messages, seen_ids
            )

    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ) as e:
        # User has limited access to this chat (kicked, banned, left, or chat is private/deleted)
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except FloodWaitError as e:
        # FloodWait that persisted through retries - inform user with exact wait time
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise MessageFetchError(
            f"Rate limited by Telegram for chat {chat_id}. {friendly_msg}"
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to fetch messages: {e}") from e

    # Sort by timestamp (oldest first) to handle out-of-order pagination
    messages.sort(key=lambda m: m.timestamp)

    # Clear seen_ids to free memory (no longer needed after deduplication)
    seen_ids.clear()

    # Log if fetch was interrupted but we're returning partial results
    if fetch_interrupted:
        logger.info(
            f"Returning {len(messages)} partial messages for chat {chat_id} "
            f"(fetch was interrupted, requested limit was {effective_limit})"
        )

    return messages


async def get_messages_streaming(
    client: TelegramClientType,
    chat_id: int,
    batch_size: int = 1000,
    max_messages: int | None = None,
) -> AsyncGenerator[list[Message], None]:
    """Stream messages from a Telegram chat in batches (generator).

    Similar to get_messages() but yields batches of messages instead of loading
    all messages into memory. Ideal for processing large chats (>100k messages)
    with memory constraints.

    For forum chats (supergroups with topics enabled), this function automatically
    fetches messages from ALL topics and aggregates them.

    Network errors (ConnectionError, TimeoutError, OSError, SSL errors) are
    automatically retried with exponential backoff (up to 3 attempts per batch).

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to fetch messages from
        batch_size: Number of messages per batch (default 1000)
        max_messages: Maximum total messages to fetch (None = unlimited)
                     For forums, this is the total across all topics.

    Yields:
        Batches of Message models as list[Message], sorted by timestamp within batch

    Raises:
        ChatAccessDeniedError: If access to chat is denied (user kicked/banned/left,
                                or chat is private/deleted)
        MessageFetchError: If chat doesn't exist or other error
        ValueError: If batch_size is invalid

    Example:
        ```python
        from chatfilter.analyzer.metrics import StreamingMetricsAggregator

        async with loader.create_client() as client:
            aggregator = StreamingMetricsAggregator()

            # Process messages in batches
            async for batch in get_messages_streaming(client, chat_id=123):
                aggregator.add_batch(batch)
                print(f"Processed batch of {len(batch)} messages")

            # Get final metrics without storing all messages
            metrics = aggregator.get_metrics()
            print(f"Total: {metrics.message_count} messages")
        ```
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if max_messages is not None and max_messages <= 0:
        raise ValueError("max_messages must be positive or None")

    # Proactive rate limiting
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_messages")

    total_fetched = 0
    seen_ids: set[int] = set()

    try:
        # Check if this is a forum chat
        entity = await client.get_entity(chat_id)
        is_forum = (
            isinstance(entity, Channel)
            and getattr(entity, "megagroup", False)
            and getattr(entity, "forum", False)
        )

        if is_forum:
            # For forums, fetch messages from all topics
            logger.info(f"Chat {chat_id} is a forum, streaming from all topics")

            # Get all topics
            topic_ids = await _get_forum_topics(client, chat_id)

            if topic_ids:
                logger.info(f"Found {len(topic_ids)} topics in forum {chat_id}")

                # Stream messages from each topic
                for topic_id in topic_ids:
                    # Check if we've reached max_messages limit
                    if max_messages and total_fetched >= max_messages:
                        logger.info(
                            f"Reached max_messages limit ({max_messages}), "
                            f"stopping forum topic fetch"
                        )
                        return

                    batch: list[Message] = []
                    retry = RetryContext(
                        operation_name=f"stream topic {topic_id}",
                        retryable_exceptions=RETRYABLE_EXCEPTIONS,
                    )

                    while retry.should_continue():
                        try:
                            # Calculate remaining messages to fetch
                            remaining = max_messages - total_fetched if max_messages else batch_size
                            fetch_limit = min(batch_size, remaining)

                            async for telethon_msg in client.iter_messages(
                                chat_id,
                                limit=fetch_limit,
                                reply_to=topic_id,
                            ):
                                msg = _telethon_message_to_model(telethon_msg, chat_id)
                                if msg is None:
                                    continue

                                # Deduplicate
                                if msg.id in seen_ids:
                                    continue
                                seen_ids.add(msg.id)
                                batch.append(msg)

                                # Yield batch when it reaches batch_size
                                if len(batch) >= batch_size:
                                    batch.sort(key=lambda m: m.timestamp)
                                    yield batch
                                    total_fetched += len(batch)
                                    batch = []

                                    # Check if we've reached max_messages
                                    if max_messages and total_fetched >= max_messages:
                                        return

                            # Yield remaining messages in final batch for this topic
                            if batch:
                                batch.sort(key=lambda m: m.timestamp)
                                yield batch
                                total_fetched += len(batch)

                            # Successfully fetched from this topic
                            break

                        except RETRYABLE_EXCEPTIONS as e:
                            await retry.handle_exception(e)
                        except Exception as e:
                            logger.warning(f"Failed to stream from topic {topic_id}: {e}")
                            break
            else:
                # No topics found, fall back to default behavior
                logger.info(f"No topics found for forum {chat_id}, using default streaming")

        # Regular chat or forum fallback: stream messages
        current_batch: list[Message] = []
        retry = RetryContext(
            operation_name=f"stream chat {chat_id}",
            retryable_exceptions=RETRYABLE_EXCEPTIONS,
        )

        while retry.should_continue():
            try:
                # Calculate remaining messages to fetch
                if max_messages:
                    remaining = max_messages - total_fetched
                    if remaining <= 0:
                        # Yield final batch if any
                        if current_batch:
                            current_batch.sort(key=lambda m: m.timestamp)
                            yield current_batch
                        return
                    fetch_limit = min(batch_size * 10, remaining)  # Fetch larger chunks
                else:
                    fetch_limit = batch_size * 10

                async for telethon_msg in client.iter_messages(
                    chat_id,
                    limit=fetch_limit,
                ):
                    msg = _telethon_message_to_model(telethon_msg, chat_id)
                    if msg is None:
                        continue

                    # Deduplicate
                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    current_batch.append(msg)

                    # Yield batch when it reaches batch_size
                    if len(current_batch) >= batch_size:
                        current_batch.sort(key=lambda m: m.timestamp)
                        yield current_batch
                        total_fetched += len(current_batch)
                        current_batch = []

                        # Check if we've reached max_messages
                        if max_messages and total_fetched >= max_messages:
                            return

                # Yield remaining messages in final batch
                if current_batch:
                    current_batch.sort(key=lambda m: m.timestamp)
                    yield current_batch
                    total_fetched += len(current_batch)

                # Successfully completed streaming
                break

            except RETRYABLE_EXCEPTIONS as e:
                await retry.handle_exception(e, f"fetched {total_fetched} so far")
                if retry.was_interrupted and current_batch:
                    # Yield any remaining batch before giving up
                    current_batch.sort(key=lambda m: m.timestamp)
                    yield current_batch

    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ) as e:
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except FloodWaitError as e:
        # FloodWait that persisted through retries - inform user with exact wait time
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise MessageFetchError(
            f"Rate limited by Telegram for chat {chat_id}. {friendly_msg}"
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to stream messages: {e}") from e
    finally:
        # Clear seen_ids to free memory
        seen_ids.clear()


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_messages_since(
    client: TelegramClientType,
    chat_id: int,
    min_id: int,
    limit: int = 10000,
) -> list[Message]:
    """Get messages from a chat newer than a specified message ID.

    Used for incremental/delta sync to fetch only new messages since the
    last sync. This is efficient for continuous monitoring as it avoids
    re-fetching the entire message history.

    For forum chats, this fetches from all topics.

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to fetch messages from
        min_id: Minimum message ID - only fetch messages with ID > min_id
        limit: Maximum number of messages to fetch (default 10000)

    Returns:
        List of Message models with ID > min_id, sorted by timestamp (oldest first)

    Raises:
        ChatAccessDeniedError: If access to chat is denied
        MessageFetchError: If chat doesn't exist or other error
        ValueError: If min_id or limit is invalid

    Example:
        ```python
        async with loader.create_client() as client:
            # Initial sync - get last 1000 messages
            messages = await get_messages(client, chat_id, limit=1000)
            last_id = max(m.id for m in messages)

            # Later - get only new messages
            new_messages = await get_messages_since(client, chat_id, min_id=last_id)
            print(f"Found {len(new_messages)} new messages")
        ```
    """
    if min_id < 0:
        raise ValueError("min_id must be non-negative")
    if limit <= 0:
        raise ValueError("limit must be positive")

    # Proactive rate limiting
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_messages")

    effective_limit = min(limit, MAX_MESSAGES_LIMIT)
    messages: list[Message] = []
    seen_ids: set[int] = set()

    try:
        # Check if this is a forum chat
        entity = await client.get_entity(chat_id)
        is_forum = (
            isinstance(entity, Channel)
            and getattr(entity, "megagroup", False)
            and getattr(entity, "forum", False)
        )

        if is_forum:
            # For forums, fetch from all topics
            logger.info(f"Chat {chat_id} is a forum, fetching new messages from all topics")

            topic_ids = await _get_forum_topics(client, chat_id)

            if topic_ids:
                for topic_id in topic_ids:
                    if len(messages) >= effective_limit:
                        break

                    remaining = effective_limit - len(messages)

                    try:
                        async for telethon_msg in client.iter_messages(
                            chat_id,
                            limit=remaining,
                            reply_to=topic_id,
                            min_id=min_id,
                        ):
                            msg = _telethon_message_to_model(telethon_msg, chat_id)
                            if msg is None:
                                continue

                            if msg.id in seen_ids:
                                continue
                            seen_ids.add(msg.id)
                            messages.append(msg)

                            if len(messages) >= effective_limit:
                                break

                    except Exception as e:
                        logger.warning(f"Failed to fetch new messages from topic {topic_id}: {e}")
                        continue
            else:
                # No topics found, fall back to default behavior
                async for telethon_msg in client.iter_messages(
                    chat_id,
                    limit=effective_limit,
                    min_id=min_id,
                ):
                    msg = _telethon_message_to_model(telethon_msg, chat_id)
                    if msg is None:
                        continue

                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    messages.append(msg)
        else:
            # Regular chat - fetch messages with min_id filter
            async for telethon_msg in client.iter_messages(
                chat_id,
                limit=effective_limit,
                min_id=min_id,
            ):
                msg = _telethon_message_to_model(telethon_msg, chat_id)
                if msg is None:
                    continue

                if msg.id in seen_ids:
                    continue
                seen_ids.add(msg.id)
                messages.append(msg)

    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ) as e:
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise MessageFetchError(
            f"Rate limited by Telegram for chat {chat_id}. {friendly_msg}"
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to fetch messages: {e}") from e
    finally:
        seen_ids.clear()

    # Sort by timestamp (oldest first)
    messages.sort(key=lambda m: m.timestamp)

    logger.info(f"Fetched {len(messages)} new messages from chat {chat_id} (min_id={min_id})")

    return messages
