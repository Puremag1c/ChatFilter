"""GroupAnalysisEngine: orchestrates group chat analysis workflow.

Phase 1 (Resolve): Determine chat metadata without joining.
Phase 2 (Activity): Join chats only when activity metrics are needed.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

from telethon import errors
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.functions.messages import CheckChatInviteRequest
from telethon.tl.types import Channel, ChatInvite, ChatInviteAlready, ChatInvitePeek
from telethon.tl.types import Chat as TelegramChat

from chatfilter.models.group import (
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.client import (
    _parse_chat_reference,
    _telethon_message_to_model,
    join_chat,
    leave_chat,
)
from chatfilter.telegram.session_manager import SessionManager

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

# Captcha bot usernames (lowercase, without @)
CAPTCHA_BOTS = frozenset({
    "missrose_bot",
    "shieldy_bot",
    "join_captcha_bot",
    "grouphelpbot",
    "combot",
})


@dataclass
class GroupProgressEvent:
    """Progress event for group analysis workflow.

    Attributes:
        group_id: Group identifier
        status: Current status
        current: Current chat index
        total: Total number of chats
        chat_title: Currently processing chat title
        message: Status message
        error: Error message if failed
        task_id: Optional underlying task_id
    """

    group_id: str
    status: str
    current: int
    total: int
    chat_title: str | None = None
    message: str | None = None
    error: str | None = None
    task_id: UUID | None = None


class GroupEngineError(Exception):
    """Base exception for GroupEngine errors."""


class GroupNotFoundError(GroupEngineError):
    """Raised when group ID doesn't exist in database."""


class NoConnectedAccountsError(GroupEngineError):
    """Raised when no accounts are connected to perform analysis."""


@dataclass
class _ResolvedChat:
    """Internal data structure holding Phase 1 resolution results."""

    db_chat_id: int
    chat_ref: str
    chat_type: str  # ChatTypeEnum value
    title: str | None
    subscribers: int | None
    moderation: bool | None  # join_request flag
    numeric_id: int | None  # Telegram numeric chat ID (if resolved)
    linked_chat_id: int | None = None  # For broadcast channels with discussion group
    status: str  # "done" | "dead" | "failed"
    error: str | None = None


class GroupAnalysisEngine:
    """Orchestrates two-phase group analysis workflow.

    Phase 1 (Resolve): For each chat, resolve metadata (type, subscribers,
    moderation) WITHOUT joining. Uses get_entity() for public chats and
    CheckChatInviteRequest for invite links.

    Phase 2 (Activity): Only if settings.needs_join() is True. Joins each
    chat, fetches messages, calculates activity metrics, detects captcha,
    and ALWAYS leaves after analysis.

    Attributes:
        db: GroupDatabase for persistence.
        session_manager: SessionManager for Telegram client access.
    """

    def __init__(
        self,
        db: GroupDatabase,
        session_manager: SessionManager,
    ) -> None:
        self._db = db
        self._session_mgr = session_manager
        self._active_tasks: dict[str, list[asyncio.Task]] = {}
        self._subscribers: dict[str, list[asyncio.Queue[GroupProgressEvent]]] = {}

    async def start_analysis(self, group_id: str) -> None:
        """Start two-phase analysis for a group.

        1. Load group and validate
        2. Clear old results atomically before starting
        3. Distribute PENDING chats across connected accounts
        4. Phase 1: Resolve metadata without joining
        5. Phase 2: Join for activity metrics (only if needed)

        Args:
            group_id: Group identifier to analyze.

        Raises:
            GroupNotFoundError: If group doesn't exist.
            NoConnectedAccountsError: If no accounts are connected.
        """
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

        # Clear old analysis results atomically before starting new analysis.
        # This ensures re-runs refresh all data. If analysis crashes mid-run,
        # old data is already cleared, but partial new data from Phase 1/2
        # will be saved via save_result() calls.
        self._db.clear_results(group_id)
        logger.info(f"Cleared old results for group '{group_id}'")

        settings = GroupSettings.from_dict(group_data["settings"])

        connected_accounts = [
            sid for sid in self._session_mgr.list_sessions()
            if await self._session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
            raise NoConnectedAccountsError(
                "No connected Telegram accounts available. "
                "Please connect at least one account to start analysis."
            )

        pending_chats = self._db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.PENDING.value,
        )

        if not pending_chats:
            logger.warning(f"No pending chats found for group '{group_id}'")
            return

        # Distribute chats round-robin across accounts
        for idx, chat in enumerate(pending_chats):
            account_id = connected_accounts[idx % len(connected_accounts)]
            self._db.update_chat_status(
                chat_id=chat["id"],
                status=GroupChatStatus.PENDING.value,
                assigned_account=account_id,
            )

        # Set group status to IN_PROGRESS
        self._db.save_group(
            group_id=group_id,
            name=group_data["name"],
            settings=group_data["settings"],
            status=GroupStatus.IN_PROGRESS.value,
            created_at=group_data["created_at"],
            updated_at=datetime.now(UTC),
        )

        logger.info(
            f"Starting analysis for group '{group_id}' with "
            f"{len(connected_accounts)} accounts, {len(pending_chats)} chats"
        )

        # Phase 1: Resolve metadata per-account in parallel
        phase1_tasks = []
        for account_id in connected_accounts:
            task = asyncio.create_task(
                self._phase1_resolve_account(group_id, account_id, settings)
            )
            phase1_tasks.append(task)

        self._active_tasks[group_id] = phase1_tasks
        results = await asyncio.gather(*phase1_tasks, return_exceptions=True)
        self._active_tasks.pop(group_id, None)

        for account_id, result in zip(connected_accounts, results):
            if isinstance(result, Exception):
                logger.error(
                    f"Account '{account_id}' Phase 1 failed: {result}",
                    exc_info=result,
                )

        # Check completion after Phase 1 if Phase 2 not needed
        if not settings.needs_join():
            self._check_and_complete_if_done(group_id)
            return

        # Phase 2: Activity metrics (only if needed)
        if settings.needs_join():
            logger.info(f"Phase 2: Activity metrics needed for group '{group_id}'")
            phase2_tasks = []
            for account_id in connected_accounts:
                task = asyncio.create_task(
                    self._phase2_activity_account(group_id, account_id, settings)
                )
                phase2_tasks.append(task)

            self._active_tasks[group_id] = phase2_tasks
            results = await asyncio.gather(*phase2_tasks, return_exceptions=True)
            self._active_tasks.pop(group_id, None)

            for account_id, result in zip(connected_accounts, results):
                if isinstance(result, Exception):
                    logger.error(
                        f"Account '{account_id}' Phase 2 failed: {result}",
                        exc_info=result,
                    )

            # Check completion after Phase 2
            self._check_and_complete_if_done(group_id)
        else:
            logger.info(
                f"Phase 2 skipped for group '{group_id}': "
                f"no activity metrics requested"
            )

    # ------------------------------------------------------------------
    # Phase 1: Resolve without joining
    # ------------------------------------------------------------------

    async def _phase1_resolve_account(
        self,
        group_id: str,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Phase 1: Resolve chat metadata for chats assigned to this account.

        For each chat:
        - Parse chat_ref to get username or invite_hash
        - If username: client.get_entity(username) to get type/subscribers/etc.
        - If invite_hash: CheckChatInviteRequest(hash) for metadata
        - Save resolved data to group_results immediately
        - 1-2s delay between calls for rate limiting

        Args:
            group_id: Group identifier.
            account_id: Account/session identifier.
            settings: Group analysis settings.
        """
        account_chats = self._db.load_chats(
            group_id=group_id,
            assigned_account=account_id,
            status=GroupChatStatus.PENDING.value,
        )

        if not account_chats:
            return

        logger.info(
            f"Phase 1: Account '{account_id}' resolving {len(account_chats)} chats"
        )

        try:
            async with self._session_mgr.session(
                account_id,
                auto_disconnect=False,
            ) as client:
                for i, chat in enumerate(account_chats):
                    try:
                        resolved = await self._resolve_chat(
                            client, chat, account_id,
                        )
                        self._save_phase1_result(
                            group_id, chat, resolved, account_id, settings,
                        )
                    except errors.FloodWaitError as e:
                        wait_seconds = getattr(e, "seconds", 0)
                        logger.warning(
                            f"Account '{account_id}': FloodWait {wait_seconds}s "
                            f"on '{chat['chat_ref']}'. Stopping account."
                        )
                        self._db.update_chat_status(
                            chat_id=chat["id"],
                            status=GroupChatStatus.FAILED.value,
                            error=f"FloodWait: {wait_seconds}s",
                        )
                        break

                    # Rate limiting: 1-2s delay between get_entity calls
                    if i < len(account_chats) - 1:
                        delay = 1.0 + random.random()
                        await asyncio.sleep(delay)

        except Exception as e:
            logger.error(
                f"Account '{account_id}': Phase 1 error: {e}",
                exc_info=True,
            )
            remaining = self._db.load_chats(
                group_id=group_id,
                assigned_account=account_id,
                status=GroupChatStatus.PENDING.value,
            )
            for chat in remaining:
                self._db.update_chat_status(
                    chat_id=chat["id"],
                    status=GroupChatStatus.FAILED.value,
                    error=f"Account error: {e}",
                )

    async def _resolve_chat(
        self,
        client: TelegramClient,
        chat: dict,
        account_id: str,
    ) -> _ResolvedChat:
        """Resolve a single chat's metadata without joining.

        Args:
            client: Connected TelegramClient.
            chat: Chat record dict from database.
            account_id: Account identifier (for logging).

        Returns:
            _ResolvedChat with resolved metadata.
        """
        chat_ref = chat["chat_ref"]
        username, invite_hash = _parse_chat_reference(chat_ref)

        if username:
            return await self._resolve_by_username(
                client, chat, username, account_id,
            )
        elif invite_hash:
            return await self._resolve_by_invite(
                client, chat, invite_hash, account_id,
            )
        else:
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                title=None,
                subscribers=None,
                moderation=None,
                numeric_id=None,
                status="failed",
                error=f"Invalid chat reference: {chat_ref}",
            )

    async def _resolve_by_username(
        self,
        client: TelegramClient,
        chat: dict,
        username: str,
        account_id: str,
    ) -> _ResolvedChat:
        """Resolve chat metadata via get_entity(username).

        Does NOT join the chat.
        """
        chat_ref = chat["chat_ref"]
        try:
            entity = await client.get_entity(username)

            if isinstance(entity, Channel):
                chat_type = self._channel_to_chat_type(entity)
                title = entity.title
                subscribers = getattr(entity, "participants_count", None)

                # If subscribers not available, try GetFullChannelRequest
                if subscribers is None:
                    try:
                        full_channel = await client(GetFullChannelRequest(entity))
                        subscribers = getattr(full_channel.full_chat, "participants_count", None)
                    except errors.FloodWaitError:
                        raise  # Let caller handle
                    except Exception as e:
                        logger.debug(
                            f"Account '{account_id}': failed to get full channel info for '{chat_ref}': {e}"
                        )

                moderation = getattr(entity, "join_request", None) or False
                numeric_id = abs(entity.id)
            elif isinstance(entity, TelegramChat):
                chat_type = ChatTypeEnum.GROUP.value
                title = entity.title
                subscribers = getattr(entity, "participants_count", None)
                moderation = False
                numeric_id = abs(entity.id)
            else:
                # User or unknown — not analyzable
                return _ResolvedChat(
                    db_chat_id=chat["id"],
                    chat_ref=chat_ref,
                    chat_type=ChatTypeEnum.DEAD.value,
                    title=getattr(entity, "first_name", None),
                    subscribers=None,
                    moderation=None,
                    numeric_id=abs(entity.id) if hasattr(entity, "id") else None,
                    status="dead",
                )

            logger.info(
                f"Account '{account_id}': resolved '{chat_ref}' "
                f"(type={chat_type}, subs={subscribers})"
            )

            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=chat_type,
                title=title,
                subscribers=subscribers,
                moderation=moderation,
                numeric_id=numeric_id,
                status="done",
            )

        except errors.FloodWaitError:
            raise  # Let caller handle

        except (
            errors.ChatForbiddenError,
            errors.ChannelPrivateError,
            errors.ChatRestrictedError,
            errors.ChannelBannedError,
            errors.UserBannedInChannelError,
        ) as e:
            logger.info(
                f"Account '{account_id}': '{chat_ref}' inaccessible "
                f"({type(e).__name__})"
            )
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                title=None,
                subscribers=None,
                moderation=None,
                numeric_id=None,
                status="dead",
                error=str(e),
            )

        except Exception as e:
            logger.error(
                f"Account '{account_id}': failed to resolve '{chat_ref}': {e}",
                exc_info=True,
            )
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                title=None,
                subscribers=None,
                moderation=None,
                numeric_id=None,
                status="dead",
                error=str(e),
            )

    async def _resolve_by_invite(
        self,
        client: TelegramClient,
        chat: dict,
        invite_hash: str,
        account_id: str,
    ) -> _ResolvedChat:
        """Resolve chat metadata via CheckChatInviteRequest.

        Does NOT join the chat (only checks invite info).
        For invite-only chats: gracefully handles missing subscribers count.
        """
        chat_ref = chat["chat_ref"]
        try:
            result = await client(CheckChatInviteRequest(hash=invite_hash))

            if isinstance(result, ChatInviteAlready):
                # Already a member — resolve from the chat entity
                entity = result.chat
                if isinstance(entity, Channel):
                    chat_type = self._channel_to_chat_type(entity)
                    title = entity.title
                    subscribers = getattr(entity, "participants_count", None)

                    # If subscribers not available, try GetFullChannelRequest
                    if subscribers is None:
                        try:
                            full_channel = await client(GetFullChannelRequest(entity))
                            subscribers = getattr(full_channel.full_chat, "participants_count", None)
                        except errors.FloodWaitError:
                            raise  # Let caller handle
                        except Exception as e:
                            logger.debug(
                                f"Account '{account_id}': failed to get full channel info for '{chat_ref}': {e}"
                            )

                    moderation = getattr(entity, "join_request", None) or False
                    numeric_id = abs(entity.id)
                else:
                    chat_type = ChatTypeEnum.GROUP.value
                    title = getattr(entity, "title", None)
                    subscribers = getattr(entity, "participants_count", None)
                    moderation = False
                    numeric_id = abs(entity.id)

            elif isinstance(result, ChatInvite):
                # Not a member — extract info from invite preview
                title = result.title
                subscribers = result.participants_count
                moderation = result.request_needed or False

                # Determine type from invite flags
                if result.broadcast:
                    chat_type = ChatTypeEnum.CHANNEL_NO_COMMENTS.value
                elif result.megagroup:
                    chat_type = ChatTypeEnum.GROUP.value
                else:
                    chat_type = ChatTypeEnum.GROUP.value

                # No numeric_id available from invite preview
                numeric_id = None

                # Note: subscribers unavailable for ChatInvite (no entity access)
            elif isinstance(result, ChatInvitePeek):
                # Temporary peek access — extract from chat entity
                entity = result.chat
                if isinstance(entity, Channel):
                    chat_type = self._channel_to_chat_type(entity)
                    title = entity.title
                    subscribers = getattr(entity, "participants_count", None)

                    # If subscribers not available, try GetFullChannelRequest
                    if subscribers is None:
                        try:
                            full_channel = await client(GetFullChannelRequest(entity))
                            subscribers = getattr(full_channel.full_chat, "participants_count", None)
                        except errors.FloodWaitError:
                            raise  # Let caller handle
                        except Exception as e:
                            logger.debug(
                                f"Account '{account_id}': failed to get full channel info for '{chat_ref}': {e}"
                            )

                    moderation = getattr(entity, "join_request", None) or False
                    numeric_id = abs(entity.id)
                else:
                    chat_type = ChatTypeEnum.GROUP.value
                    title = getattr(entity, "title", None)
                    subscribers = getattr(entity, "participants_count", None)
                    moderation = False
                    numeric_id = abs(entity.id)
            else:
                # Unknown type
                title = None
                chat_type = ChatTypeEnum.PENDING.value
                subscribers = None
                moderation = None
                numeric_id = None

            logger.info(
                f"Account '{account_id}': resolved invite '{chat_ref}' "
                f"(type={chat_type}, subs={subscribers}, moderation={moderation})"
            )

            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=chat_type,
                title=title,
                subscribers=subscribers,
                moderation=moderation,
                numeric_id=numeric_id,
                status="done",
            )

        except errors.FloodWaitError:
            raise

        except errors.InviteHashExpiredError:
            logger.info(
                f"Account '{account_id}': invite '{chat_ref}' expired"
            )
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                title=None,
                subscribers=None,
                moderation=None,
                numeric_id=None,
                status="dead",
                error="Invite link expired",
            )

        except Exception as e:
            logger.error(
                f"Account '{account_id}': failed to check invite '{chat_ref}': {e}",
                exc_info=True,
            )
            return _ResolvedChat(
                db_chat_id=chat["id"],
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                title=None,
                subscribers=None,
                moderation=None,
                numeric_id=None,
                status="dead",
                error=str(e),
            )

    def _save_phase1_result(
        self,
        group_id: str,
        chat: dict,
        resolved: _ResolvedChat,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Save Phase 1 resolution results to database.

        Updates chat status and saves metrics_data to group_results.
        """
        # Map resolved status to GroupChatStatus
        if resolved.status == "dead":
            db_status = GroupChatStatus.FAILED.value
        elif resolved.status == "failed":
            db_status = GroupChatStatus.FAILED.value
        else:
            db_status = GroupChatStatus.DONE.value

        # Update chat record
        self._db.save_chat(
            group_id=group_id,
            chat_ref=resolved.chat_ref,
            chat_type=resolved.chat_type,
            status=db_status,
            assigned_account=account_id,
            error=resolved.error,
            chat_id=resolved.db_chat_id,
        )

        # Build metrics_data for non-join metrics
        metrics: dict = {
            "chat_type": resolved.chat_type,
            "title": resolved.title,
            "chat_ref": resolved.chat_ref,
            "status": resolved.status,
        }

        if settings.detect_subscribers:
            metrics["subscribers"] = resolved.subscribers
        if settings.detect_moderation:
            metrics["moderation"] = resolved.moderation

        # Activity metrics are not available in Phase 1 — mark as pending
        # They will be filled in Phase 2 if needs_join()
        if settings.needs_join() and resolved.status == "done":
            if settings.detect_activity:
                metrics["messages_per_hour"] = None
            if settings.detect_unique_authors:
                metrics["unique_authors_per_hour"] = None
            if settings.detect_captcha:
                metrics["captcha"] = None

        # Save result
        self._db.save_result(
            group_id=group_id,
            chat_ref=resolved.chat_ref,
            metrics_data=metrics,
        )

    # ------------------------------------------------------------------
    # Phase 2: Join for activity metrics
    # ------------------------------------------------------------------

    async def _phase2_activity_account(
        self,
        group_id: str,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Phase 2: Join chats for activity metrics.

        Only called when settings.needs_join() is True.
        For each DONE chat assigned to this account:
        - Check join_request flag — if True, skip join, mark N/A
        - Join chat
        - Fetch messages within time_window
        - Calculate messages_per_hour, unique_authors_per_hour
        - Detect captcha
        - ALWAYS leave after analysis
        """
        done_chats = self._db.load_chats(
            group_id=group_id,
            assigned_account=account_id,
            status=GroupChatStatus.DONE.value,
        )

        if not done_chats:
            return

        # Filter out dead chats
        analyzable = [
            c for c in done_chats
            if c["chat_type"] != ChatTypeEnum.DEAD.value
        ]

        if not analyzable:
            return

        logger.info(
            f"Phase 2: Account '{account_id}' analyzing "
            f"{len(analyzable)} chats for activity"
        )

        try:
            async with self._session_mgr.session(
                account_id,
                auto_disconnect=False,
            ) as client:
                for i, chat in enumerate(analyzable):
                    await self._analyze_chat_activity(
                        client, group_id, chat, account_id, settings,
                    )

                    # Rate limiting between chats
                    if i < len(analyzable) - 1:
                        delay = 1.0 + random.random()
                        await asyncio.sleep(delay)

        except Exception as e:
            logger.error(
                f"Account '{account_id}': Phase 2 error: {e}",
                exc_info=True,
            )

    async def _analyze_chat_activity(
        self,
        client: TelegramClient,
        group_id: str,
        chat: dict,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Analyze a single chat for activity metrics.

        Joins the chat, fetches messages, calculates metrics,
        detects captcha, and ALWAYS leaves.
        """
        chat_ref = chat["chat_ref"]
        chat_id = chat["id"]

        # Load existing result to check moderation flag
        existing_result = self._db.load_result(group_id, chat_ref)
        existing_metrics = existing_result["metrics_data"] if existing_result else {}

        # If join_request is True (moderation enabled), skip join
        if existing_metrics.get("moderation") is True:
            logger.info(
                f"Account '{account_id}': '{chat_ref}' requires approval "
                f"to join (moderation=True), marking activity as N/A"
            )
            self._update_activity_metrics(
                group_id, chat_ref, existing_metrics,
                messages_per_hour="N/A",
                unique_authors_per_hour="N/A",
                captcha="N/A",
                settings=settings,
            )
            return

        # Update status to ANALYZING
        self._db.update_chat_status(
            chat_id=chat_id,
            status=GroupChatStatus.ANALYZING.value,
        )

        numeric_id = None
        try:
            # Join the chat
            joined = await join_chat(client, chat_ref)
            numeric_id = joined.id

            # Fetch messages within time_window
            now = datetime.now(UTC)
            offset_date = now - timedelta(hours=settings.time_window)

            messages = []
            msg_count = 0
            authors: set[int] = set()
            has_captcha = False

            async for msg in client.iter_messages(
                numeric_id,
                limit=500,
                offset_date=offset_date,
            ):
                converted = _telethon_message_to_model(msg, numeric_id)
                if converted is None:
                    continue

                # Only count messages within time window
                if converted.timestamp < offset_date:
                    break

                msg_count += 1
                authors.add(converted.author_id)
                messages.append(converted)

            # Calculate metrics
            hours = settings.time_window
            messages_per_hour = round(msg_count / hours, 2) if hours > 0 else 0
            unique_authors_per_hour = round(len(authors) / hours, 2) if hours > 0 else 0

            # Detect captcha
            if settings.detect_captcha:
                has_captcha = await self._detect_captcha(
                    client, numeric_id, messages,
                )

            logger.info(
                f"Account '{account_id}': '{chat_ref}' activity: "
                f"{messages_per_hour} msg/h, {unique_authors_per_hour} authors/h, "
                f"captcha={has_captcha}"
            )

            # Update metrics
            self._update_activity_metrics(
                group_id, chat_ref, existing_metrics,
                messages_per_hour=messages_per_hour,
                unique_authors_per_hour=unique_authors_per_hour,
                captcha=has_captcha,
                settings=settings,
            )

            # Update chat status back to DONE
            self._db.update_chat_status(
                chat_id=chat_id,
                status=GroupChatStatus.DONE.value,
            )

        except errors.FloodWaitError as e:
            wait_seconds = getattr(e, "seconds", 0)
            logger.warning(
                f"Account '{account_id}': FloodWait {wait_seconds}s "
                f"on '{chat_ref}' during Phase 2"
            )
            self._db.update_chat_status(
                chat_id=chat_id,
                status=GroupChatStatus.DONE.value,
                error=f"Phase 2 FloodWait: {wait_seconds}s",
            )

        except Exception as e:
            logger.error(
                f"Account '{account_id}': Phase 2 failed for '{chat_ref}': {e}",
                exc_info=True,
            )
            # Keep DONE status from Phase 1, just log the error
            self._db.update_chat_status(
                chat_id=chat_id,
                status=GroupChatStatus.DONE.value,
                error=f"Phase 2 error: {e}",
            )

        finally:
            # ALWAYS leave after analysis
            if numeric_id is not None:
                try:
                    await leave_chat(client, numeric_id)
                    logger.debug(
                        f"Account '{account_id}': left '{chat_ref}'"
                    )
                except Exception as e:
                    logger.warning(
                        f"Account '{account_id}': failed to leave "
                        f"'{chat_ref}': {e}"
                    )

    async def _detect_captcha(
        self,
        client: TelegramClient,
        chat_id: int,
        messages: list,
    ) -> bool:
        """Detect captcha presence in a chat.

        Checks:
        1. Known captcha bot usernames in recent messages
        2. Restricted status on the channel (may indicate captcha)

        Args:
            client: Connected TelegramClient.
            chat_id: Numeric chat ID.
            messages: Already-fetched messages to scan.

        Returns:
            True if captcha is detected.
        """
        # Scan messages for captcha bot senders
        for msg in messages:
            sender_id = msg.author_id
            try:
                sender = await client.get_entity(sender_id)
                username = getattr(sender, "username", None)
                if username and username.lower() in CAPTCHA_BOTS:
                    return True
                is_bot = getattr(sender, "bot", False)
                if is_bot and username:
                    # Check if bot name suggests captcha
                    lower_name = username.lower()
                    if "captcha" in lower_name or "verify" in lower_name:
                        return True
            except Exception:
                # Can't resolve sender — skip
                continue

        return False

    def _update_activity_metrics(
        self,
        group_id: str,
        chat_ref: str,
        existing_metrics: dict,
        messages_per_hour: float | str,
        unique_authors_per_hour: float | str,
        captcha: bool | str,
        settings: GroupSettings,
    ) -> None:
        """Update group_results with Phase 2 activity metrics.

        Merges activity data into the existing metrics_data from Phase 1.
        """
        metrics = dict(existing_metrics)

        if settings.detect_activity:
            metrics["messages_per_hour"] = messages_per_hour
        if settings.detect_unique_authors:
            metrics["unique_authors_per_hour"] = unique_authors_per_hour
        if settings.detect_captcha:
            metrics["captcha"] = captcha

        # Save updated result (replaces existing)
        self._db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data=metrics,
        )

    def _check_and_complete_if_done(self, group_id: str) -> None:
        """Check if all chats processed and mark group COMPLETED if done.

        Counts DONE + FAILED chats vs total. If all processed, sets group
        status to COMPLETED and publishes completion event to subscribers.

        Args:
            group_id: Group identifier to check.
        """
        all_chats = self._db.load_chats(group_id=group_id)
        if not all_chats:
            return

        total = len(all_chats)
        done = sum(
            1 for c in all_chats
            if c["status"] in (GroupChatStatus.DONE.value, GroupChatStatus.FAILED.value)
        )

        if done >= total:
            logger.info(
                f"Group '{group_id}': all {total} chats processed "
                f"— marking COMPLETED"
            )

            group_data = self._db.load_group(group_id)
            if group_data:
                self._db.save_group(
                    group_id=group_id,
                    name=group_data["name"],
                    settings=group_data["settings"],
                    status=GroupStatus.COMPLETED.value,
                    created_at=group_data["created_at"],
                    updated_at=datetime.now(UTC),
                )

                # Publish completion event to SSE subscribers
                event = GroupProgressEvent(
                    group_id=group_id,
                    status=GroupStatus.COMPLETED.value,
                    current=done,
                    total=total,
                    message="Analysis completed",
                )
                self._publish_event(event)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _channel_to_chat_type(self, entity: Channel) -> str:
        """Map a Telethon Channel entity to ChatTypeEnum value."""
        if getattr(entity, "megagroup", False):
            if getattr(entity, "forum", False):
                return ChatTypeEnum.FORUM.value
            return ChatTypeEnum.GROUP.value
        return ChatTypeEnum.CHANNEL_NO_COMMENTS.value

    def _map_chat_type_to_enum(self, chat_type_str: str) -> str:
        """Map ChatType string to ChatTypeEnum value.

        Args:
            chat_type_str: ChatType value from models.chat.

        Returns:
            Mapped ChatTypeEnum value string.
        """
        mapping = {
            "group": ChatTypeEnum.GROUP.value,
            "supergroup": ChatTypeEnum.GROUP.value,
            "forum": ChatTypeEnum.FORUM.value,
            "channel": ChatTypeEnum.CHANNEL_NO_COMMENTS.value,
            "private": ChatTypeEnum.DEAD.value,
        }
        return mapping.get(chat_type_str, ChatTypeEnum.PENDING.value)

    # ------------------------------------------------------------------
    # Lifecycle: stop, resume, subscribe
    # ------------------------------------------------------------------

    def stop_analysis(self, group_id: str) -> None:
        """Stop ongoing analysis for a group.

        Cancels all active tasks and sets group status back to PENDING.

        Args:
            group_id: Group identifier to stop.
        """
        active = self._active_tasks.get(group_id, [])
        for task in active:
            if not task.done():
                task.cancel()
                logger.info(f"Cancelled task for group '{group_id}'")

        self._active_tasks.pop(group_id, None)

        group_data = self._db.load_group(group_id)
        if group_data:
            self._db.save_group(
                group_id=group_id,
                name=group_data["name"],
                settings=group_data["settings"],
                status=GroupStatus.PENDING.value,
                created_at=group_data["created_at"],
                updated_at=datetime.now(UTC),
            )

        logger.info(f"Analysis stopped for group '{group_id}'")

    async def resume_analysis(self, group_id: str) -> None:
        """Resume analysis for a group.

        Resets FAILED chats to PENDING and re-runs analysis.

        Args:
            group_id: Group identifier to resume.

        Raises:
            GroupNotFoundError: If group doesn't exist.
        """
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

        logger.info(f"Resuming analysis for group '{group_id}'")

        failed_chats = self._db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.FAILED.value,
        )

        for chat in failed_chats:
            self._db.update_chat_status(
                chat_id=chat["id"],
                status=GroupChatStatus.PENDING.value,
                error=None,
            )

        logger.info(f"Reset {len(failed_chats)} failed chats to PENDING")

        await self.start_analysis(group_id)

    def subscribe(self, group_id: str) -> asyncio.Queue[GroupProgressEvent]:
        """Subscribe to progress events for a group analysis.

        Args:
            group_id: Group identifier to subscribe to.

        Returns:
            Queue that will receive progress events.
        """
        queue: asyncio.Queue[GroupProgressEvent] = asyncio.Queue()
        self._subscribers.setdefault(group_id, []).append(queue)
        return queue

    def _publish_event(self, event: GroupProgressEvent) -> None:
        """Publish progress event to all subscribers of the group.

        Args:
            event: Progress event to publish.
        """
        subscribers = self._subscribers.get(event.group_id, [])
        for queue in subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    f"Subscriber queue full for group '{event.group_id}', "
                    f"dropping event"
                )
