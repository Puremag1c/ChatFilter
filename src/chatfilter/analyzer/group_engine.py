"""GroupAnalysisEngine: orchestrates group chat analysis workflow.

Phase 1 (Resolve): Determine chat metadata without joining.
Phase 2 (Activity): Join chats only when activity metrics are needed.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections import deque
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
    AnalysisMode,
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
    status: str  # "done" | "dead" | "failed"
    linked_chat_id: int | None = None  # For broadcast channels with discussion group
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

    def check_increment_needed(
        self,
        group_id: str,
        settings: GroupSettings,
    ) -> bool:
        """Check if INCREMENT analysis would have work to do.

        Examines all chats in the group and determines if any are missing
        enabled metrics or have failed status.

        Args:
            group_id: Group identifier to check.
            settings: Group settings defining which metrics are enabled.

        Returns:
            True if INCREMENT would do work (missing metrics or failed chats).
            False if all chats have all enabled metrics and none are failed.
        """
        # Load all chats for this group
        all_chats = self._db.load_chats(group_id=group_id)
        if not all_chats:
            # No chats = nothing to analyze
            return False

        # Check for any FAILED chats (retry is always useful)
        has_failed = any(
            chat["status"] == GroupChatStatus.FAILED.value
            for chat in all_chats
        )
        if has_failed:
            # FAILED chats exist → retry is useful
            return True

        # Define which metrics are needed based on settings
        required_metrics = ["chat_type"]  # Always required
        if settings.detect_subscribers:
            required_metrics.append("subscribers")
        if settings.detect_activity:
            required_metrics.append("messages_per_hour")
        if settings.detect_unique_authors:
            required_metrics.append("unique_authors_per_hour")
        if settings.detect_moderation:
            required_metrics.append("moderation")
        if settings.detect_captcha:
            required_metrics.append("captcha")

        # Check each chat for missing metrics
        for chat in all_chats:
            result = self._db.load_result(group_id, chat["chat_ref"])

            # No result at all → needs analysis
            if not result:
                return True

            metrics_data = result.get("metrics_data", {})

            # Check if any required metric is missing or None
            for metric in required_metrics:
                value = metrics_data.get(metric)
                if value is None:
                    # Missing metric → needs analysis
                    return True

        # All chats have all required metrics, no failed chats
        return False

    async def start_analysis(
        self,
        group_id: str,
        mode: AnalysisMode = AnalysisMode.FRESH,
    ) -> None:
        """Start two-phase analysis for a group.

        1. Load group and validate
        2. Check PENDING chats:
           - If 0 PENDING but FAILED exist → reset FAILED to PENDING (auto-retry)
           - If 0 PENDING and all DONE → mark COMPLETED and return
           - If 0 PENDING and neither FAILED nor all DONE → return
        3. Clear old results before starting work (mode-dependent)
        4. Distribute PENDING chats across connected accounts
        5. Phase 1: Resolve metadata without joining
        6. Phase 2: Join for activity metrics (only if needed)

        Args:
            group_id: Group identifier to analyze.
            mode: Analysis mode ('fresh', 'increment', 'overwrite').

        Raises:
            GroupNotFoundError: If group doesn't exist.
            NoConnectedAccountsError: If no accounts are connected.
        """
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

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

        # Handle case when no PENDING chats found
        if not pending_chats:
            all_chats = self._db.load_chats(group_id=group_id)
            failed_chats = [
                c for c in all_chats
                if c["status"] == GroupChatStatus.FAILED.value
            ]
            done_chats = [
                c for c in all_chats
                if c["status"] == GroupChatStatus.DONE.value
            ]

            # If FAILED chats exist → reset them to PENDING and continue (auto-retry)
            if failed_chats:
                logger.info(
                    f"No PENDING chats, but {len(failed_chats)} FAILED found. "
                    f"Resetting to PENDING for auto-retry..."
                )
                for chat in failed_chats:
                    self._db.update_chat_status(
                        chat_id=chat["id"],
                        status=GroupChatStatus.PENDING.value,
                        error=None,
                    )
                # Reload pending_chats after reset
                pending_chats = self._db.load_chats(
                    group_id=group_id,
                    status=GroupChatStatus.PENDING.value,
                )
            # If ALL chats are DONE → publish 'complete' event, set COMPLETED, return
            elif done_chats and len(done_chats) == len(all_chats):
                logger.info(
                    f"All {len(all_chats)} chats already DONE for group '{group_id}'. "
                    f"Marking as COMPLETED."
                )
                self._db.save_group(
                    group_id=group_id,
                    name=group_data["name"],
                    settings=group_data["settings"],
                    status=GroupStatus.COMPLETED.value,
                    created_at=group_data["created_at"],
                    updated_at=datetime.now(UTC),
                )
                # Publish completion event
                event = GroupProgressEvent(
                    group_id=group_id,
                    status=GroupStatus.COMPLETED.value,
                    current=len(done_chats),
                    total=len(all_chats),
                    message="Analysis already completed",
                )
                self._publish_event(event)
                return
            else:
                # No PENDING, no FAILED, not all DONE → something is wrong
                logger.warning(
                    f"No pending chats found for group '{group_id}', "
                    f"and no FAILED chats to retry. Current state unclear."
                )
                return

        # Handle mode-specific logic for results clearing
        if mode == AnalysisMode.OVERWRITE:
            # OVERWRITE: clear results + reset ALL chats to PENDING
            self._db.clear_results(group_id)
            logger.info(f"[OVERWRITE mode] Cleared old results for group '{group_id}'")

            # Reset ALL chats to PENDING (not just FAILED)
            all_chats = self._db.load_chats(group_id=group_id)
            for chat in all_chats:
                self._db.update_chat_status(
                    chat_id=chat["id"],
                    status=GroupChatStatus.PENDING.value,
                    error=None,
                )
            logger.info(f"[OVERWRITE mode] Reset {len(all_chats)} chats to PENDING")

            # Reload pending_chats after reset
            pending_chats = self._db.load_chats(
                group_id=group_id,
                status=GroupChatStatus.PENDING.value,
            )
        elif mode == AnalysisMode.FRESH:
            # FRESH (default): clear old results before starting
            self._db.clear_results(group_id)
            logger.info(f"[FRESH mode] Cleared old results for group '{group_id}'")
        elif mode == AnalysisMode.INCREMENT:
            # INCREMENT: do NOT clear results, skip logic will handle it
            logger.info(f"[INCREMENT mode] Keeping existing results for group '{group_id}'")

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
                self._phase1_resolve_account(group_id, account_id, settings, mode)
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
                # Safety net: save dead results for orphan chats
                # (in case outer exception handler in _phase1_resolve_account also failed)
                orphan_chats = self._db.load_chats(
                    group_id=group_id,
                    assigned_account=account_id,
                )
                for chat in orphan_chats:
                    # Check if result already exists (outer handler may have saved it)
                    existing = self._db.load_result(
                        group_id=group_id,
                        chat_ref=chat["chat_ref"],
                    )
                    if existing is None:
                        # No result saved — save dead record
                        dead_resolved = _ResolvedChat(
                            db_chat_id=chat["id"],
                            chat_ref=chat["chat_ref"],
                            chat_type=ChatTypeEnum.DEAD.value,
                            title=None,
                            subscribers=None,
                            moderation=None,
                            numeric_id=None,
                            status="dead",
                            linked_chat_id=None,
                            error=f"Account task exception: {result}",
                        )
                        self._save_phase1_result(
                            group_id, chat, dead_resolved, account_id, settings, mode,
                        )

        # Final safety net: verify all chats have group_results after Phase 1
        all_chats = self._db.load_chats(group_id=group_id)
        all_results = self._db.load_results(group_id=group_id)

        # Build set of chat_refs that have results
        result_chat_refs = {result["chat_ref"] for result in all_results}

        # Find orphans: chats without results
        orphans = [chat for chat in all_chats if chat["chat_ref"] not in result_chat_refs]

        if orphans:
            logger.warning(
                f"Phase 1 orphan safety net triggered: {len(orphans)} chats missing results in group '{group_id}'"
            )

            # Save dead record for each orphan
            for chat in orphans:
                # Use assigned_account if available, otherwise use first connected account
                fallback_account = chat.get("assigned_account") or (
                    connected_accounts[0] if connected_accounts else "unknown"
                )

                dead_resolved = _ResolvedChat(
                    db_chat_id=chat["id"],
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.DEAD.value,
                    title=None,
                    subscribers=None,
                    moderation=None,
                    numeric_id=None,
                    status="dead",
                    linked_chat_id=None,
                    error="Orphan safety net: no result after Phase 1",
                )
                self._save_phase1_result(
                    group_id, chat, dead_resolved, fallback_account, settings, mode,
                )

            logger.info(
                f"Orphan safety net: saved {len(orphans)} dead records for missing results"
            )

        # Log subscriber detection stats if enabled
        if settings.detect_subscribers:
            completed_chats = self._db.load_chats(
                group_id=group_id,
                status=GroupChatStatus.DONE.value,
            )
            if completed_chats:
                with_subscribers = sum(
                    1 for chat in completed_chats
                    if chat.get("subscribers") is not None
                )
                without_subscribers = len(completed_chats) - with_subscribers
                logger.info(
                    f"Phase 1 subscriber stats: {with_subscribers} chats with subscribers, "
                    f"{without_subscribers} without (may be groups/forums or API failures)"
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
                    self._phase2_activity_account(group_id, account_id, settings, mode)
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
        mode: AnalysisMode,
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

        # Get total chat count for progress calculation (THIS account's work)
        total_chats = len(account_chats)

        # Initialize progress counter (start from zero for THIS run)
        current_count = 0

        # Initialize retry queue with (chat, retry_count) tuples
        MAX_RETRIES = 3
        MAX_FLOODWAIT_SECONDS = 300
        MAX_CHAT_TIMEOUT = 600  # 10 minutes cumulative wait per chat
        chat_queue = deque([(chat, 0) for chat in account_chats])
        chat_cumulative_wait: dict[int, float] = {}  # Track total wait time per chat_id

        try:
            async with self._session_mgr.session(
                account_id,
                auto_disconnect=False,
            ) as client:
                while chat_queue:
                    chat, retry_count = chat_queue.popleft()

                    try:
                        # INCREMENT mode: skip if Phase 1 metrics already exist
                        if mode == AnalysisMode.INCREMENT:
                            existing = self._db.load_result(group_id, chat["chat_ref"])
                            if existing:
                                em = existing.get("metrics_data", {})
                                has_type = em.get("chat_type") is not None
                                has_subs = not settings.detect_subscribers or em.get("subscribers") is not None
                                has_mod = not settings.detect_moderation or em.get("moderation") is not None
                                if has_type and has_subs and has_mod:
                                    # Mark chat as DONE and skip
                                    self._db.update_chat_status(
                                        chat_id=chat["id"],
                                        status=GroupChatStatus.DONE.value,
                                    )
                                    current_count += 1
                                    event = GroupProgressEvent(
                                        group_id=group_id,
                                        status=GroupStatus.IN_PROGRESS.value,
                                        current=current_count,
                                        total=total_chats,
                                        chat_title=em.get("title") or chat["chat_ref"],
                                        message=f"Skipped @{chat['chat_ref']} (already analyzed)",
                                    )
                                    self._publish_event(event)
                                    continue

                        resolved = await self._resolve_chat(
                            client, chat, account_id,
                        )
                        self._save_phase1_result(
                            group_id, chat, resolved, account_id, settings, mode,
                        )

                        # Increment counter after processing
                        current_count += 1

                        event = GroupProgressEvent(
                            group_id=group_id,
                            status=GroupStatus.IN_PROGRESS.value,
                            current=current_count,
                            total=total_chats,
                            chat_title=resolved.title or resolved.chat_ref,
                            message=f"Phase 1: Resolved {current_count}/{total_chats}",
                            error=resolved.error,
                        )
                        self._publish_event(event)

                        # Rate limiting: 1-2s delay between successful calls
                        if chat_queue:
                            delay = 1.0 + random.random()
                            await asyncio.sleep(delay)

                    except errors.FloodWaitError as e:
                        wait_seconds = getattr(e, "seconds", 0)

                        # FloodWait > 300s: skip this chat for now (don't block queue)
                        if wait_seconds > MAX_FLOODWAIT_SECONDS:
                            logger.warning(
                                f"Account '{account_id}': FloodWait {wait_seconds}s "
                                f"on '{chat['chat_ref']}' exceeds limit. Skipping chat."
                            )
                            # Mark as failed but count it
                            self._db.update_chat_status(
                                chat_id=chat["id"],
                                status=GroupChatStatus.FAILED.value,
                                error=f"FloodWait too long: {wait_seconds}s",
                            )

                            # Save dead result
                            dead_resolved = _ResolvedChat(
                                db_chat_id=chat["id"],
                                chat_ref=chat["chat_ref"],
                                chat_type=ChatTypeEnum.DEAD.value,
                                title=None,
                                subscribers=None,
                                moderation=None,
                                numeric_id=None,
                                status="dead",
                                linked_chat_id=None,
                                error=f"FloodWait too long: {wait_seconds}s",
                            )
                            self._save_phase1_result(
                                group_id, chat, dead_resolved, account_id, settings, mode,
                            )

                            current_count += 1
                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                error=f"FloodWait too long: {wait_seconds}s",
                            )
                            self._publish_event(event)
                            continue

                        # FloodWait <= 300s: check cumulative timeout before waiting
                        buffer = int(wait_seconds * 0.1)
                        total_wait = wait_seconds + buffer

                        # Track cumulative wait time for this chat
                        chat_id = chat["id"]
                        cumulative_wait = chat_cumulative_wait.get(chat_id, 0.0)
                        new_cumulative = cumulative_wait + total_wait

                        # Check if cumulative wait exceeds MAX_CHAT_TIMEOUT
                        if new_cumulative > MAX_CHAT_TIMEOUT:
                            timeout_msg = f"Chat @{chat['chat_ref']} timed out after {int(cumulative_wait)}s, marked as dead"
                            logger.warning(
                                f"Account '{account_id}': {timeout_msg} "
                                f"(would exceed {MAX_CHAT_TIMEOUT}s with next FloodWait {total_wait}s)"
                            )

                            # Mark as failed
                            self._db.update_chat_status(
                                chat_id=chat_id,
                                status=GroupChatStatus.FAILED.value,
                                error=f"Timeout exceeded: {int(cumulative_wait)}s cumulative FloodWait",
                            )

                            # Save dead result
                            dead_resolved = _ResolvedChat(
                                db_chat_id=chat_id,
                                chat_ref=chat["chat_ref"],
                                chat_type=ChatTypeEnum.DEAD.value,
                                title=None,
                                subscribers=None,
                                moderation=None,
                                numeric_id=None,
                                status="dead",
                                linked_chat_id=None,
                                error=f"Timeout exceeded: {int(cumulative_wait)}s cumulative FloodWait",
                            )
                            self._save_phase1_result(
                                group_id, chat, dead_resolved, account_id, settings, mode,
                            )

                            current_count += 1
                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                message=timeout_msg,
                                error=f"Timeout exceeded after {int(cumulative_wait)}s",
                            )
                            self._publish_event(event)
                            continue

                        # Update cumulative wait and proceed
                        chat_cumulative_wait[chat_id] = new_cumulative

                        logger.warning(
                            f"Account '{account_id}': FloodWait {wait_seconds}s "
                            f"on '{chat['chat_ref']}'. Waiting {total_wait}s... "
                            f"(cumulative: {int(new_cumulative)}s/{MAX_CHAT_TIMEOUT}s)"
                        )

                        event = GroupProgressEvent(
                            group_id=group_id,
                            status=GroupStatus.IN_PROGRESS.value,
                            current=current_count,
                            total=total_chats,
                            chat_title=chat["chat_ref"],
                            message=f"Waiting for FloodWait cooldown ({total_wait}s remaining)...",
                        )
                        self._publish_event(event)

                        await asyncio.sleep(total_wait)

                        # Re-enqueue chat at front (process immediately after wait)
                        chat_queue.appendleft((chat, retry_count))

                    except Exception as e:
                        # Any other error: retry up to MAX_RETRIES
                        error_type = type(e).__name__
                        error_msg = f"{type(e).__name__}: {e}"
                        logger.warning(
                            f"Account '{account_id}': Error on '{chat['chat_ref']}' "
                            f"(attempt {retry_count + 1}/{MAX_RETRIES}): {error_msg}"
                        )

                        if retry_count + 1 < MAX_RETRIES:
                            # Retry: re-enqueue at end
                            chat_queue.append((chat, retry_count + 1))

                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                message=f"Retry {retry_count + 2}/{MAX_RETRIES} for @{chat['chat_ref']} ({error_type})",
                            )
                            self._publish_event(event)
                        else:
                            # Max retries exhausted: mark as dead and save result
                            logger.error(
                                f"Account '{account_id}': Chat '{chat['chat_ref']}' "
                                f"failed after {MAX_RETRIES} retries: {error_msg}"
                            )

                            self._db.update_chat_status(
                                chat_id=chat["id"],
                                status=GroupChatStatus.FAILED.value,
                                error=f"Failed after {MAX_RETRIES} retries: {error_msg}",
                            )

                            # Save dead result
                            dead_resolved = _ResolvedChat(
                                db_chat_id=chat["id"],
                                chat_ref=chat["chat_ref"],
                                chat_type=ChatTypeEnum.DEAD.value,
                                title=None,
                                subscribers=None,
                                moderation=None,
                                numeric_id=None,
                                status="dead",
                                linked_chat_id=None,
                                error=f"Failed after {MAX_RETRIES} retries: {error_msg}",
                            )
                            self._save_phase1_result(
                                group_id, chat, dead_resolved, account_id, settings, mode,
                            )

                            current_count += 1
                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                message=f"Chat @{chat['chat_ref']} failed after {MAX_RETRIES} retries: {error_type}",
                                error=error_msg,
                            )
                            self._publish_event(event)

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
                # Save dead result to group_results (same pattern as max retries handler)
                dead_resolved = _ResolvedChat(
                    db_chat_id=chat["id"],
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.DEAD.value,
                    title=None,
                    subscribers=None,
                    moderation=None,
                    numeric_id=None,
                    status="dead",
                    linked_chat_id=None,
                    error=f"Account error: {e}",
                )
                self._save_phase1_result(
                    group_id, chat, dead_resolved, account_id, settings, mode,
                )

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
                title = entity.title
                subscribers = getattr(entity, "participants_count", None)
                linked_chat_id = None
                is_megagroup = getattr(entity, "megagroup", False)

                # For broadcast channels, ALWAYS call GetFullChannelRequest to get linked_chat_id
                # For other channels, call only if subscribers not available
                if (not is_megagroup) or (subscribers is None):
                    try:
                        full_channel = await client(GetFullChannelRequest(entity))
                        if subscribers is None:
                            subscribers = getattr(full_channel.full_chat, "participants_count", None)
                        # Extract linked_chat_id for broadcast channels
                        if not is_megagroup:
                            linked_chat_id = getattr(full_channel.full_chat, "linked_chat_id", None)
                    except errors.FloodWaitError:
                        raise  # Let caller handle
                    except Exception as e:
                        logger.warning(
                            f"Failed to fetch subscriber count for '{chat_ref}': {type(e).__name__} - this chat will have null subscribers"
                        )

                chat_type = self._channel_to_chat_type(entity, linked_chat_id)
                moderation = getattr(entity, "join_request", None) or False
                numeric_id = abs(entity.id)
            elif isinstance(entity, TelegramChat):
                chat_type = ChatTypeEnum.GROUP.value
                title = entity.title
                subscribers = getattr(entity, "participants_count", None)
                moderation = False
                numeric_id = abs(entity.id)
                linked_chat_id = None  # Groups don't have linked discussion chats
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
                linked_chat_id=linked_chat_id,
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
                            logger.warning(
                                f"Failed to fetch subscriber count for '{chat_ref}': {type(e).__name__} - this chat will have null subscribers"
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
                            logger.warning(
                                f"Failed to fetch subscriber count for '{chat_ref}': {type(e).__name__} - this chat will have null subscribers"
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
        mode: AnalysisMode,
    ) -> None:
        """Save Phase 1 resolution results to database.

        Updates chat status and saves metrics_data to group_results.
        Uses upsert for INCREMENT mode to merge with existing data.
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
            subscribers=resolved.subscribers,
        )

        # Build metrics_data for non-join metrics
        metrics: dict = {
            "chat_type": resolved.chat_type,
            "title": resolved.title,
            "chat_ref": resolved.chat_ref,
            "status": resolved.status,
        }

        # Include error_reason for dead/failed chats
        if resolved.status in ("dead", "failed") and resolved.error:
            metrics["error_reason"] = resolved.error

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

        # Save result (use upsert for INCREMENT mode to merge with existing)
        if mode == AnalysisMode.INCREMENT:
            self._db.upsert_result(
                group_id=group_id,
                chat_ref=resolved.chat_ref,
                metrics_data=metrics,
            )
        else:
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
        mode: AnalysisMode,
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

        # Get total chat count for progress calculation (THIS account's work)
        total_chats = len(analyzable)

        # Initialize progress counter (start from zero for THIS run)
        current_count = 0

        # Initialize retry queue with (chat, retry_count) tuples
        MAX_RETRIES = 3
        MAX_FLOODWAIT_SECONDS = 300
        chat_queue = deque([(chat, 0) for chat in analyzable])

        try:
            async with self._session_mgr.session(
                account_id,
                auto_disconnect=False,
            ) as client:
                while chat_queue:
                    chat, retry_count = chat_queue.popleft()

                    try:
                        # INCREMENT mode: skip if Phase 2 metrics already exist
                        if mode == AnalysisMode.INCREMENT:
                            existing = self._db.load_result(group_id, chat["chat_ref"])
                            if existing:
                                em = existing.get("metrics_data", {})
                                has_activity = not settings.detect_activity or em.get("messages_per_hour") is not None
                                has_authors = not settings.detect_unique_authors or em.get("unique_authors_per_hour") is not None
                                has_captcha = not settings.detect_captcha or em.get("captcha") is not None
                                if has_activity and has_authors and has_captcha:
                                    current_count += 1
                                    event = GroupProgressEvent(
                                        group_id=group_id,
                                        status=GroupStatus.IN_PROGRESS.value,
                                        current=current_count,
                                        total=total_chats,
                                        chat_title=em.get("title") or chat["chat_ref"],
                                        message=f"Skipped @{chat['chat_ref']} (already analyzed)",
                                    )
                                    self._publish_event(event)
                                    continue

                        await self._analyze_chat_activity(
                            client, group_id, chat, account_id, settings,
                        )

                        # Success — increment counter and publish event
                        current_count += 1

                        # Load result to get title
                        result = self._db.load_result(group_id, chat["chat_ref"])
                        chat_title = None
                        if result:
                            metrics = result.get("metrics_data", {})
                            chat_title = metrics.get("title") or chat["chat_ref"]
                        else:
                            chat_title = chat["chat_ref"]

                        event = GroupProgressEvent(
                            group_id=group_id,
                            status=GroupStatus.IN_PROGRESS.value,
                            current=current_count,
                            total=total_chats,
                            chat_title=chat_title,
                            message=f"Phase 2: Analyzed {current_count}/{total_chats}",
                        )
                        self._publish_event(event)

                        # Rate limiting between successful calls
                        if chat_queue:
                            delay = 1.0 + random.random()
                            await asyncio.sleep(delay)

                    except errors.FloodWaitError as e:
                        wait_seconds = getattr(e, "seconds", 0)

                        # FloodWait > 300s: skip this chat (don't retry)
                        if wait_seconds > MAX_FLOODWAIT_SECONDS:
                            logger.warning(
                                f"Account '{account_id}': Phase 2 FloodWait {wait_seconds}s "
                                f"on '{chat['chat_ref']}' exceeds limit. Skipping chat."
                            )
                            # Keep DONE status from Phase 1, just note the error
                            self._db.update_chat_status(
                                chat_id=chat["id"],
                                status=GroupChatStatus.DONE.value,
                                error=f"Phase 2 FloodWait too long: {wait_seconds}s",
                            )

                            # Update existing result with error_reason (preserve Phase 1 data)
                            self._db.upsert_result(
                                group_id=group_id,
                                chat_ref=chat["chat_ref"],
                                metrics_data={"error_reason": f"Phase 2 FloodWait too long: {wait_seconds}s"},
                            )

                            current_count += 1
                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                error=f"Phase 2 FloodWait too long: {wait_seconds}s",
                            )
                            self._publish_event(event)
                            continue

                        # FloodWait <= 300s: wait with 10% buffer and retry
                        buffer = int(wait_seconds * 0.1)
                        total_wait = wait_seconds + buffer
                        logger.warning(
                            f"Account '{account_id}': Phase 2 FloodWait {wait_seconds}s "
                            f"on '{chat['chat_ref']}'. Waiting {total_wait}s..."
                        )

                        event = GroupProgressEvent(
                            group_id=group_id,
                            status=GroupStatus.IN_PROGRESS.value,
                            current=current_count,
                            total=total_chats,
                            chat_title=chat["chat_ref"],
                            message=f"Waiting for FloodWait cooldown ({total_wait}s remaining)...",
                        )
                        self._publish_event(event)

                        await asyncio.sleep(total_wait)

                        # Re-enqueue chat at front (process immediately after wait)
                        chat_queue.appendleft((chat, retry_count))

                    except Exception as e:
                        # Any other error: retry up to MAX_RETRIES
                        error_type = type(e).__name__
                        error_msg = f"{error_type}: {e}"
                        logger.warning(
                            f"Account '{account_id}': Phase 2 error on '{chat['chat_ref']}' "
                            f"(attempt {retry_count + 1}/{MAX_RETRIES}): {error_msg}"
                        )

                        if retry_count + 1 < MAX_RETRIES:
                            # Retry: re-enqueue at end
                            chat_queue.append((chat, retry_count + 1))

                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                message=f"Retry {retry_count + 2}/{MAX_RETRIES} for @{chat['chat_ref']} ({error_type})",
                            )
                            self._publish_event(event)
                        else:
                            # Max retries exhausted: keep DONE status from Phase 1, log error
                            logger.error(
                                f"Account '{account_id}': Phase 2 for '{chat['chat_ref']}' "
                                f"failed after {MAX_RETRIES} retries: {error_msg}"
                            )

                            self._db.update_chat_status(
                                chat_id=chat["id"],
                                status=GroupChatStatus.DONE.value,
                                error=f"Phase 2 failed after {MAX_RETRIES} retries: {error_msg}",
                            )

                            # Update existing result with error_reason (preserve Phase 1 data)
                            self._db.upsert_result(
                                group_id=group_id,
                                chat_ref=chat["chat_ref"],
                                metrics_data={"error_reason": f"Phase 2 failed after {MAX_RETRIES} retries: {error_msg}"},
                            )

                            current_count += 1
                            event = GroupProgressEvent(
                                group_id=group_id,
                                status=GroupStatus.IN_PROGRESS.value,
                                current=current_count,
                                total=total_chats,
                                chat_title=chat["chat_ref"],
                                message=f"Chat @{chat['chat_ref']} Phase 2 failed after {MAX_RETRIES} retries: {error_type}",
                                error=error_msg,
                            )
                            self._publish_event(event)

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

        except errors.FloodWaitError:
            # FloodWaitError is handled in _phase2_activity_account loop
            # Re-raise to let the caller handle retry logic
            raise

        except Exception:
            # All exceptions are handled in _phase2_activity_account loop
            # Re-raise to let the caller handle retry logic
            raise

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
        Uses upsert to safely merge with existing data.
        """
        # Build partial metrics with only Phase 2 data
        partial_metrics = {}

        if settings.detect_activity:
            partial_metrics["messages_per_hour"] = messages_per_hour
        if settings.detect_unique_authors:
            partial_metrics["unique_authors_per_hour"] = unique_authors_per_hour
        if settings.detect_captcha:
            partial_metrics["captcha"] = captcha

        # Use upsert to merge with existing Phase 1 data
        self._db.upsert_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data=partial_metrics,
        )

    def _check_and_complete_if_done(self, group_id: str) -> None:
        """Check if all chats processed and mark group COMPLETED or FAILED.

        Counts DONE + FAILED chats vs total. If all processed:
        - If ALL chats are FAILED → sets group status to FAILED
        - Otherwise → sets group status to COMPLETED

        Args:
            group_id: Group identifier to check.
        """
        all_chats = self._db.load_chats(group_id=group_id)
        if not all_chats:
            return

        total = len(all_chats)
        done_count = sum(
            1 for c in all_chats
            if c["status"] == GroupChatStatus.DONE.value
        )
        failed_count = sum(
            1 for c in all_chats
            if c["status"] == GroupChatStatus.FAILED.value
        )
        processed = done_count + failed_count

        if processed >= total:
            # Determine final status: FAILED if ALL chats failed, COMPLETED otherwise
            if failed_count == total:
                final_status = GroupStatus.FAILED.value
                message = "Analysis failed: all chats failed"
                logger.warning(
                    f"Group '{group_id}': all {total} chats FAILED "
                    f"— marking group as FAILED"
                )
            else:
                final_status = GroupStatus.COMPLETED.value
                message = "Analysis completed"
                logger.info(
                    f"Group '{group_id}': all {total} chats processed "
                    f"({done_count} DONE, {failed_count} FAILED) — marking COMPLETED"
                )

            group_data = self._db.load_group(group_id)
            if group_data:
                self._db.save_group(
                    group_id=group_id,
                    name=group_data["name"],
                    settings=group_data["settings"],
                    status=final_status,
                    created_at=group_data["created_at"],
                    updated_at=datetime.now(UTC),
                )

                # Publish completion event to SSE subscribers
                event = GroupProgressEvent(
                    group_id=group_id,
                    status=final_status,
                    current=processed,
                    total=total,
                    message=message,
                )
                self._publish_event(event)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _channel_to_chat_type(self, entity: Channel, linked_chat_id: int | None = None) -> str:
        """Map a Telethon Channel entity to ChatTypeEnum value.

        Args:
            entity: Telethon Channel entity
            linked_chat_id: ID of linked discussion group (if any)
        """
        if getattr(entity, "megagroup", False):
            if getattr(entity, "forum", False):
                return ChatTypeEnum.FORUM.value
            return ChatTypeEnum.GROUP.value
        # Broadcast channel: check if has discussion group
        if linked_chat_id is not None:
            return ChatTypeEnum.CHANNEL_COMMENTS.value
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

        Cancels all active tasks, resets ANALYZING chats to PENDING,
        and sets group status back to PENDING.

        Args:
            group_id: Group identifier to stop.
        """
        active = self._active_tasks.get(group_id, [])
        for task in active:
            if not task.done():
                task.cancel()
                logger.info(f"Cancelled task for group '{group_id}'")

        self._active_tasks.pop(group_id, None)

        # Reset ANALYZING chats to PENDING (they were interrupted mid-work)
        analyzing_chats = self._db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.ANALYZING.value,
        )
        for chat in analyzing_chats:
            self._db.update_chat_status(
                chat_id=chat["id"],
                status=GroupChatStatus.PENDING.value,
                error=None,
            )

        if analyzing_chats:
            logger.info(
                f"Reset {len(analyzing_chats)} ANALYZING chats to PENDING "
                f"for group '{group_id}'"
            )

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
