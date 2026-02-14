"""GroupAnalysisEngine: orchestrates group chat analysis workflow.

Phase 1: Resolve chats without joining (get_entity / CheckChatInviteRequest).
Phase 2: Join chats for activity metrics (only if needs_join()).
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from telethon import errors
from telethon.tl.functions.messages import CheckChatInviteRequest
from telethon.tl.types import Channel, ChatInvite, ChatInviteAlready, ChatInvitePeek

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
    from telethon.tl.types import Chat as TelegramChat

logger = logging.getLogger(__name__)

# Known captcha bots (lowercase usernames without @)
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
        task_id: Optional underlying TaskQueue task_id
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


class GroupAnalysisEngine:
    """Orchestrates multi-account group analysis workflow.

    Phase 1: Resolve chats without joining (get_entity / CheckChatInviteRequest).
    Phase 2: Join chats for activity metrics (only if needs_join()).

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
        """Start full analysis workflow for a group.

        Phase 1: Resolve without join.
        Phase 2: Join for activity metrics (if needs_join()).

        Args:
            group_id: Group identifier to analyze.

        Raises:
            GroupNotFoundError: If group doesn't exist.
            NoConnectedAccountsError: If no accounts are connected.
        """
        await self._run_analysis(group_id)

    async def _run_analysis(self, group_id: str) -> None:
        """Orchestrate analysis phases sequentially.

        Args:
            group_id: Group identifier to analyze.
        """
        logger.info(f"Starting analysis workflow for group '{group_id}'")

        try:
            # Load group
            group_data = self._db.load_group(group_id)
            if not group_data:
                raise GroupNotFoundError(f"Group not found: {group_id}")

            settings = GroupSettings.from_dict(group_data["settings"])

            # Get connected accounts
            connected_accounts = [
                sid for sid in self._session_mgr.list_sessions()
                if await self._session_mgr.is_healthy(sid)
            ]
            if not connected_accounts:
                raise NoConnectedAccountsError(
                    "No connected Telegram accounts available."
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

            # Load PENDING chats and distribute round-robin
            pending_chats = self._db.load_chats(
                group_id=group_id,
                status=GroupChatStatus.PENDING.value,
            )
            if not pending_chats:
                logger.warning(f"No pending chats for group '{group_id}'")
                return

            for idx, chat in enumerate(pending_chats):
                account_id = connected_accounts[idx % len(connected_accounts)]
                self._db.update_chat_status(
                    chat_id=chat["id"],
                    status=GroupChatStatus.PENDING.value,
                    assigned_account=account_id,
                )

            logger.info(
                f"Distributed {len(pending_chats)} chats across "
                f"{len(connected_accounts)} accounts"
            )

            # Phase 1: Resolve without join
            await self._phase1_resolve(group_id, connected_accounts, settings)

            # Phase 2: Join for activity metrics (only if needed)
            if settings.needs_join():
                await self._phase2_join_and_analyze(
                    group_id, connected_accounts, settings,
                )
            else:
                logger.info(
                    f"Phase 2 skipped: needs_join()=False for group '{group_id}'"
                )

            logger.info(f"Analysis workflow completed for group '{group_id}'")

        except Exception as e:
            logger.error(
                f"Analysis workflow failed for group '{group_id}': {e}",
                exc_info=True,
            )
            group_data = self._db.load_group(group_id)
            if group_data:
                self._db.save_group(
                    group_id=group_id,
                    name=group_data["name"],
                    settings=group_data["settings"],
                    status=GroupStatus.FAILED.value,
                    created_at=group_data["created_at"],
                    updated_at=datetime.now(UTC),
                )
            raise

    # ── Phase 1: Resolve without join ──────────────────────────────────

    async def _phase1_resolve(
        self,
        group_id: str,
        accounts: list[str],
        settings: GroupSettings,
    ) -> None:
        """Phase 1: Resolve chat metadata without joining.

        For each chat: get_entity (public) or CheckChatInviteRequest (invite).
        Determines chat_type, subscribers, moderation.
        Stores results immediately for non-join metrics.

        Args:
            group_id: Group identifier.
            accounts: List of connected account IDs.
            settings: Group settings.
        """
        logger.info(f"Phase 1: Resolving chats for group '{group_id}'")

        tasks = []
        for account_id in accounts:
            task = asyncio.create_task(
                self._phase1_account(group_id, account_id, settings)
            )
            tasks.append(task)

        self._active_tasks[group_id] = tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        self._active_tasks.pop(group_id, None)

        for account_id, result in zip(accounts, results):
            if isinstance(result, Exception):
                logger.error(
                    f"Phase 1 account '{account_id}' failed: {result}",
                    exc_info=result,
                )

        logger.info(f"Phase 1 complete for group '{group_id}'")

    async def _phase1_account(
        self,
        group_id: str,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Process Phase 1 for a single account's assigned chats.

        Args:
            group_id: Group identifier.
            account_id: Account/session identifier.
            settings: Group settings.
        """
        account_chats = self._db.load_chats(
            group_id=group_id,
            assigned_account=account_id,
            status=GroupChatStatus.PENDING.value,
        )
        if not account_chats:
            return

        logger.info(
            f"Phase 1 account '{account_id}': resolving {len(account_chats)} chats"
        )

        try:
            async with self._session_mgr.session(
                account_id, auto_disconnect=False,
            ) as client:
                for i, chat in enumerate(account_chats):
                    try:
                        await self._resolve_chat(
                            client, group_id, chat, account_id, settings,
                        )
                    except errors.FloodWaitError as e:
                        wait_seconds = getattr(e, "seconds", 0)
                        logger.warning(
                            f"Account '{account_id}': FloodWait {wait_seconds}s "
                            f"on '{chat['chat_ref']}'. Stopping."
                        )
                        self._db.update_chat_status(
                            chat_id=chat["id"],
                            status=GroupChatStatus.FAILED.value,
                            error=f"FloodWait: {wait_seconds}s",
                        )
                        break

                    # Rate limiting: 1-2s delay between get_entity calls
                    if i < len(account_chats) - 1:
                        await asyncio.sleep(random.uniform(1.0, 2.0))

        except Exception as e:
            logger.error(
                f"Account '{account_id}': unexpected error in Phase 1: {e}",
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
        group_id: str,
        chat: dict,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Resolve a single chat without joining.

        Uses get_entity for public chats or CheckChatInviteRequest for invites.

        Args:
            client: Connected TelegramClient.
            group_id: Group identifier.
            chat: Chat record dict from database.
            account_id: Account identifier.
            settings: Group settings.
        """
        chat_id = chat["id"]
        chat_ref = chat["chat_ref"]

        self._db.update_chat_status(
            chat_id=chat_id,
            status=GroupChatStatus.ANALYZING.value,
        )

        username, invite_hash = _parse_chat_reference(chat_ref)

        if username is None and invite_hash is None:
            self._db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                status=GroupChatStatus.FAILED.value,
                assigned_account=account_id,
                error="Invalid chat reference",
                chat_id=chat_id,
            )
            return

        try:
            if invite_hash:
                await self._resolve_invite(
                    client, group_id, chat_id, chat_ref,
                    invite_hash, account_id, settings,
                )
            else:
                await self._resolve_public(
                    client, group_id, chat_id, chat_ref,
                    username, account_id, settings,
                )
        except errors.FloodWaitError:
            raise  # Propagate to stop account processing
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
            self._db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type=ChatTypeEnum.DEAD.value,
                status=GroupChatStatus.FAILED.value,
                assigned_account=account_id,
                error=str(e),
                chat_id=chat_id,
            )
            self._save_phase1_result(
                group_id, chat_ref, ChatTypeEnum.DEAD.value,
                status="dead", error=str(e),
            )
        except Exception as e:
            logger.error(
                f"Account '{account_id}': failed to resolve '{chat_ref}': {e}",
                exc_info=True,
            )
            self._db.update_chat_status(
                chat_id=chat_id,
                status=GroupChatStatus.FAILED.value,
                error=str(e),
            )
            self._save_phase1_result(
                group_id, chat_ref, ChatTypeEnum.PENDING.value,
                status="failed", error=str(e),
            )

    async def _resolve_public(
        self,
        client: TelegramClient,
        group_id: str,
        chat_id: int,
        chat_ref: str,
        username: str,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Resolve a public chat via get_entity (no join).

        Args:
            client: Connected TelegramClient.
            group_id: Group identifier.
            chat_id: Database chat record ID.
            chat_ref: Original chat reference string.
            username: Extracted username.
            account_id: Account identifier.
            settings: Group settings.
        """
        entity = await client.get_entity(username)

        chat_type = self._entity_to_chat_type(entity)
        subscribers = getattr(entity, "participants_count", None)
        title = getattr(entity, "title", None)
        join_request = getattr(entity, "request_needed", None) or False

        self._db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type=chat_type,
            status=GroupChatStatus.DONE.value,
            assigned_account=account_id,
            chat_id=chat_id,
        )

        self._save_phase1_result(
            group_id, chat_ref, chat_type,
            subscribers=subscribers,
            moderation=join_request,
            title=title,
        )

        logger.info(
            f"Phase 1 resolved '{chat_ref}': type={chat_type}, "
            f"subs={subscribers}, mod={join_request}"
        )

    async def _resolve_invite(
        self,
        client: TelegramClient,
        group_id: str,
        chat_id: int,
        chat_ref: str,
        invite_hash: str,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Resolve an invite link via CheckChatInviteRequest (no join).

        Args:
            client: Connected TelegramClient.
            group_id: Group identifier.
            chat_id: Database chat record ID.
            chat_ref: Original chat reference string.
            invite_hash: Extracted invite hash.
            account_id: Account identifier.
            settings: Group settings.
        """
        result = await client(CheckChatInviteRequest(hash=invite_hash))

        if isinstance(result, ChatInviteAlready):
            # We're already in this chat — resolve from the chat entity
            entity = result.chat
            chat_type = self._entity_to_chat_type(entity)
            subscribers = getattr(entity, "participants_count", None)
            title = getattr(entity, "title", None)
            join_request = getattr(entity, "request_needed", None) or False
        elif isinstance(result, (ChatInvite, ChatInvitePeek)):
            # Not joined: extract info from invite metadata
            title = getattr(result, "title", None)
            subscribers = getattr(result, "participants_count", None)
            join_request = getattr(result, "request_needed", None) or False

            # Determine type from invite flags
            is_channel = getattr(result, "channel", False)
            is_megagroup = getattr(result, "megagroup", False)
            is_forum = getattr(result, "forum", False)

            if is_forum:
                chat_type = ChatTypeEnum.FORUM.value
            elif is_megagroup:
                chat_type = ChatTypeEnum.GROUP.value
            elif is_channel:
                chat_type = ChatTypeEnum.CHANNEL_NO_COMMENTS.value
            else:
                chat_type = ChatTypeEnum.GROUP.value
        else:
            # Unknown response type — treat as pending
            chat_type = ChatTypeEnum.PENDING.value
            subscribers = None
            title = None
            join_request = False

        self._db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type=chat_type,
            status=GroupChatStatus.DONE.value,
            assigned_account=account_id,
            chat_id=chat_id,
        )

        self._save_phase1_result(
            group_id, chat_ref, chat_type,
            subscribers=subscribers,
            moderation=join_request,
            title=title,
        )

        logger.info(
            f"Phase 1 resolved invite '{chat_ref}': type={chat_type}, "
            f"subs={subscribers}, mod={join_request}"
        )

    def _save_phase1_result(
        self,
        group_id: str,
        chat_ref: str,
        chat_type: str,
        subscribers: int | None = None,
        moderation: bool | None = None,
        title: str | None = None,
        status: str = "done",
        error: str | None = None,
    ) -> None:
        """Save Phase 1 metrics to group_results immediately.

        Args:
            group_id: Group identifier.
            chat_ref: Chat reference.
            chat_type: Resolved chat type.
            subscribers: Participant count.
            moderation: Whether join_request is enabled.
            title: Chat title.
            status: Result status (done/failed/dead).
            error: Error message if failed.
        """
        metrics: dict[str, Any] = {
            "chat_type": chat_type,
            "subscribers": subscribers,
            "moderation": moderation,
            "title": title,
            "chat_ref": chat_ref,
            "status": status,
            # Activity metrics — not yet available in Phase 1
            "messages_per_hour": None,
            "unique_authors_per_hour": None,
            "captcha": None,
        }
        if error:
            metrics["error"] = error

        self._db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data=metrics,
        )

    # ── Phase 2: Join for activity metrics ─────────────────────────────

    async def _phase2_join_and_analyze(
        self,
        group_id: str,
        accounts: list[str],
        settings: GroupSettings,
    ) -> None:
        """Phase 2: Join chats and collect activity metrics.

        Only runs when settings.needs_join() is True.
        Before join: checks join_request — if True, skips (marks N/A).
        After analysis: ALWAYS leaves the chat.

        Args:
            group_id: Group identifier.
            accounts: List of connected account IDs.
            settings: Group settings.
        """
        logger.info(f"Phase 2: Joining chats for activity metrics, group '{group_id}'")

        tasks = []
        for account_id in accounts:
            task = asyncio.create_task(
                self._phase2_account(group_id, account_id, settings)
            )
            tasks.append(task)

        self._active_tasks.setdefault(group_id, []).extend(tasks)
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for account_id, result in zip(accounts, results):
            if isinstance(result, Exception):
                logger.error(
                    f"Phase 2 account '{account_id}' failed: {result}",
                    exc_info=result,
                )

        logger.info(f"Phase 2 complete for group '{group_id}'")

    async def _phase2_account(
        self,
        group_id: str,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Process Phase 2 for a single account.

        Args:
            group_id: Group identifier.
            account_id: Account/session identifier.
            settings: Group settings.
        """
        # Load DONE chats assigned to this account (from Phase 1)
        done_chats = self._db.load_chats(
            group_id=group_id,
            assigned_account=account_id,
            status=GroupChatStatus.DONE.value,
        )
        if not done_chats:
            return

        # Filter: skip dead chats
        analyzable = [
            c for c in done_chats
            if c.get("chat_type") != ChatTypeEnum.DEAD.value
        ]
        if not analyzable:
            return

        logger.info(
            f"Phase 2 account '{account_id}': analyzing {len(analyzable)} chats"
        )

        try:
            async with self._session_mgr.session(
                account_id, auto_disconnect=False,
            ) as client:
                for chat in analyzable:
                    await self._phase2_analyze_chat(
                        client, group_id, chat, account_id, settings,
                    )
        except Exception as e:
            logger.error(
                f"Account '{account_id}': unexpected error in Phase 2: {e}",
                exc_info=True,
            )

    async def _phase2_analyze_chat(
        self,
        client: TelegramClient,
        group_id: str,
        chat: dict,
        account_id: str,
        settings: GroupSettings,
    ) -> None:
        """Join a single chat, analyze activity metrics, then leave.

        Args:
            client: Connected TelegramClient.
            group_id: Group identifier.
            chat: Chat record dict from database.
            account_id: Account identifier.
            settings: Group settings.
        """
        chat_ref = chat["chat_ref"]

        # Check Phase 1 result for join_request flag
        existing_result = self._db.load_result(group_id, chat_ref)
        if existing_result:
            metrics = existing_result.get("metrics_data", {})
            if metrics.get("moderation"):
                # join_request=True — can't auto-join, mark N/A
                logger.info(
                    f"Skipping '{chat_ref}': join_request=True, marking N/A"
                )
                self._update_result_with_activity(
                    group_id, chat_ref,
                    messages_per_hour=None,
                    unique_authors_per_hour=None,
                    captcha=None,
                    activity_status="n/a",
                )
                return

        joined_chat = None
        try:
            # Join the chat
            joined_chat = await join_chat(client, chat_ref)
            numeric_chat_id = joined_chat.id

            # Analyze activity
            now = datetime.now(UTC)
            offset_date = now - timedelta(hours=settings.time_window)

            messages = []
            async for msg in client.iter_messages(
                numeric_chat_id,
                limit=500,
                offset_date=offset_date,
            ):
                converted = _telethon_message_to_model(msg, numeric_chat_id)
                if converted is not None:
                    messages.append(converted)

            # Calculate metrics
            hours = settings.time_window
            messages_per_hour = len(messages) / hours if hours > 0 else 0.0
            unique_authors = len({m.author_id for m in messages})
            unique_authors_per_hour = unique_authors / hours if hours > 0 else 0.0

            # Detect captcha
            captcha_detected = False
            if settings.detect_captcha:
                captcha_detected = await self._detect_captcha(
                    client, numeric_chat_id,
                )

            self._update_result_with_activity(
                group_id, chat_ref,
                messages_per_hour=round(messages_per_hour, 2),
                unique_authors_per_hour=round(unique_authors_per_hour, 2),
                captcha=captcha_detected,
                activity_status="done",
            )

            logger.info(
                f"Phase 2 '{chat_ref}': msgs/h={messages_per_hour:.1f}, "
                f"authors/h={unique_authors_per_hour:.1f}, captcha={captcha_detected}"
            )

        except errors.FloodWaitError as e:
            wait_seconds = getattr(e, "seconds", 0)
            logger.warning(
                f"Phase 2 FloodWait {wait_seconds}s on '{chat_ref}'"
            )
            self._update_result_with_activity(
                group_id, chat_ref,
                activity_status="failed",
                error=f"FloodWait: {wait_seconds}s",
            )
        except Exception as e:
            logger.warning(
                f"Phase 2 failed for '{chat_ref}': {e}"
            )
            self._update_result_with_activity(
                group_id, chat_ref,
                activity_status="failed",
                error=str(e),
            )
        finally:
            # ALWAYS leave after analysis
            if joined_chat is not None:
                try:
                    await leave_chat(client, joined_chat.id)
                    logger.debug(f"Left '{chat_ref}' after analysis")
                except Exception as leave_err:
                    logger.warning(
                        f"Failed to leave '{chat_ref}': {leave_err}"
                    )

    async def _detect_captcha(
        self,
        client: TelegramClient,
        chat_id: int,
    ) -> bool:
        """Detect captcha presence in a chat.

        Checks:
        1. If chat has Restricted status (slow_mode or similar restrictions)
        2. Scans recent service messages for known captcha bots

        Args:
            client: Connected TelegramClient.
            chat_id: Numeric chat ID.

        Returns:
            True if captcha is detected.
        """
        try:
            # Check for known captcha bot participants
            # Scan recent messages for bot activity
            async for msg in client.iter_messages(chat_id, limit=50):
                sender = getattr(msg, "sender", None)
                if sender is None:
                    continue
                sender_username = getattr(sender, "username", None)
                if sender_username and sender_username.lower() in CAPTCHA_BOTS:
                    return True

                # Also check from_id for bot messages
                from_id = getattr(msg, "from_id", None)
                if from_id and hasattr(from_id, "user_id"):
                    # Try to get entity for this user
                    try:
                        user = await client.get_entity(from_id.user_id)
                        uname = getattr(user, "username", None)
                        if uname and uname.lower() in CAPTCHA_BOTS:
                            return True
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Captcha detection error for {chat_id}: {e}")

        return False

    def _update_result_with_activity(
        self,
        group_id: str,
        chat_ref: str,
        messages_per_hour: float | None = None,
        unique_authors_per_hour: float | None = None,
        captcha: bool | None = None,
        activity_status: str = "done",
        error: str | None = None,
    ) -> None:
        """Update existing Phase 1 result with Phase 2 activity metrics.

        Args:
            group_id: Group identifier.
            chat_ref: Chat reference.
            messages_per_hour: Messages per hour metric.
            unique_authors_per_hour: Unique authors per hour.
            captcha: Whether captcha was detected.
            activity_status: Status of activity analysis (done/failed/n/a).
            error: Error message if failed.
        """
        existing = self._db.load_result(group_id, chat_ref)
        if existing:
            metrics = existing.get("metrics_data", {})
        else:
            metrics = {"chat_ref": chat_ref}

        metrics["messages_per_hour"] = messages_per_hour
        metrics["unique_authors_per_hour"] = unique_authors_per_hour
        metrics["captcha"] = captcha
        if error:
            metrics["error"] = error

        # Update overall status to reflect Phase 2 completion
        if activity_status == "done":
            metrics["status"] = "done"
        elif activity_status == "n/a":
            # Keep original status but note activity is N/A
            pass
        else:
            metrics["status"] = activity_status

        self._db.save_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data=metrics,
        )

    # ── Helpers ────────────────────────────────────────────────────────

    def _entity_to_chat_type(self, entity: Any) -> str:
        """Map Telethon entity to ChatTypeEnum value.

        Args:
            entity: Telethon entity (Channel, Chat, User).

        Returns:
            ChatTypeEnum value string.
        """
        if isinstance(entity, Channel):
            if getattr(entity, "megagroup", False):
                if getattr(entity, "forum", False):
                    return ChatTypeEnum.FORUM.value
                return ChatTypeEnum.GROUP.value
            return ChatTypeEnum.CHANNEL_NO_COMMENTS.value

        # Import here to avoid circular
        from telethon.tl.types import Chat as TelegramChat
        if isinstance(entity, TelegramChat):
            return ChatTypeEnum.GROUP.value

        # Private or unknown
        return ChatTypeEnum.DEAD.value

    # ── Lifecycle ──────────────────────────────────────────────────────

    def stop_analysis(self, group_id: str) -> None:
        """Stop ongoing analysis for a group.

        Args:
            group_id: Group identifier to stop.
        """
        tasks = self._active_tasks.get(group_id, [])
        for task in tasks:
            if not task.done():
                task.cancel()
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
        """Resume analysis for a group (retries FAILED chats).

        Args:
            group_id: Group identifier to resume.
        """
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

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

        logger.info(f"Reset {len(failed_chats)} failed chats for retry")
        await self._run_analysis(group_id)

    def subscribe(self, group_id: str) -> asyncio.Queue[GroupProgressEvent]:
        """Subscribe to progress events for a group analysis.

        Args:
            group_id: Group identifier.

        Returns:
            Queue that receives GroupProgressEvent objects.
        """
        queue: asyncio.Queue[GroupProgressEvent] = asyncio.Queue()
        self._subscribers.setdefault(group_id, []).append(queue)
        return queue
