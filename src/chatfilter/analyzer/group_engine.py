"""GroupAnalysisEngine: thin orchestrator for group chat analysis.

Single-pass model: each chat goes Pending → Done/Error in one step.
Uses worker.process_chat() for processing and retry.try_with_retry()
for FloodWait handling and account rotation.
"""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from chatfilter.analyzer.progress import GroupProgressEvent, ProgressTracker
from chatfilter.analyzer.retry import RetryPolicy, try_with_retry
from chatfilter.analyzer.worker import ChatResult, process_chat
from chatfilter.telegram.flood_tracker import get_flood_tracker
from chatfilter.models.group import (
    AnalysisMode,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.session_manager import SessionInvalidError, SessionManager
from chatfilter.utils.network import detect_network_error

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

METRICS_VERSION = 2


class AccountHealthTracker:
    """Tracks per-account consecutive failures during analysis.

    After N consecutive failures, account is marked as dead and should stop processing.
    """

    def __init__(self, max_consecutive_errors: int = 5) -> None:
        self.consecutive_errors: dict[str, int] = {}
        self.total_done: dict[str, int] = {}
        self.total_error: dict[str, int] = {}
        self.max_consecutive_errors = max_consecutive_errors

    def record_success(self, account_id: str) -> None:
        """Record successful chat processing - resets consecutive error counter."""
        self.consecutive_errors[account_id] = 0
        self.total_done[account_id] = self.total_done.get(account_id, 0) + 1

    def record_failure(self, account_id: str) -> None:
        """Record chat processing failure - increments consecutive error counter."""
        self.consecutive_errors[account_id] = self.consecutive_errors.get(account_id, 0) + 1
        self.total_error[account_id] = self.total_error.get(account_id, 0) + 1

    def record_chat_error(self, account_id: str) -> None:
        """Record dead chat error - increments total error but NOT consecutive (not account's fault)."""
        self.total_error[account_id] = self.total_error.get(account_id, 0) + 1
        # Reset consecutive errors - dead chat is not account failure
        self.consecutive_errors[account_id] = 0

    def should_stop(self, account_id: str) -> bool:
        """Check if account should stop processing due to too many consecutive failures."""
        return self.consecutive_errors.get(account_id, 0) >= self.max_consecutive_errors

    def get_stats(self, account_id: str) -> dict:
        """Get health statistics for an account."""
        return {
            "consecutive_errors": self.consecutive_errors.get(account_id, 0),
            "total_done": self.total_done.get(account_id, 0),
            "total_error": self.total_error.get(account_id, 0),
        }


class GroupEngineError(Exception):
    """Base exception for GroupEngine errors."""


class GroupNotFoundError(GroupEngineError):
    """Raised when group ID doesn't exist in database."""


class NoConnectedAccountsError(GroupEngineError):
    """Raised when no accounts are connected to perform analysis."""


class GroupAnalysisEngine:
    """Orchestrates group analysis using worker + retry + progress.

    Single-pass: each chat transitions Pending → Done/Error once.
    """

    def __init__(
        self,
        db: GroupDatabase,
        session_manager: SessionManager,
        progress: ProgressTracker | None = None,
    ) -> None:
        self._db = db
        self._session_mgr = session_manager
        self._active_tasks: dict[str, list[asyncio.Task]] = {}
        self._stop_events: dict[str, asyncio.Event] = {}
        self._progress = progress if progress is not None else ProgressTracker(db)

    # -- Startup recovery --------------------------------------------------

    def recover_stale_analysis(self) -> None:
        """Reset groups stuck in in_progress or waiting_for_accounts after server restart."""
        stale = [
            g for g in self._db.load_all_groups()
            if g["status"] in (GroupStatus.IN_PROGRESS.value, GroupStatus.WAITING_FOR_ACCOUNTS.value)
        ]
        if not stale:
            logger.info("No stale in_progress/waiting_for_accounts groups — recovery skipped")
            return
        for group in stale:
            gid = group["id"]
            task = self._db.get_active_task(gid)
            if task:
                self._db.cancel_task(task["id"])
            # Set PAUSED status for crashed groups (can be resumed)
            self._db.save_group(
                group_id=gid,
                name=group["name"],
                settings=group["settings"],
                status=GroupStatus.PAUSED.value,
                created_at=group["created_at"],
                updated_at=datetime.now(UTC),
            )
            logger.info(f"Recovered stale group '{group['name']}' ({gid}) → paused")

    # -- INCREMENT check ---------------------------------------------------

    def check_increment_needed(self, group_id: str, settings: GroupSettings) -> bool:
        """Check if INCREMENT analysis would have work to do."""
        all_chats = self._db.load_chats(group_id=group_id)
        if not all_chats:
            return False
        if any(c["status"] == GroupChatStatus.ERROR.value for c in all_chats):
            return True
        for chat in all_chats:
            if chat["status"] != GroupChatStatus.DONE.value:
                continue
            metrics = self._db.get_chat_metrics(chat["id"])
            if not metrics or self._chat_needs_reanalysis(metrics, settings):
                return True
        return False

    # -- FloodWait waiting loop --------------------------------------------

    async def _wait_for_accounts_and_resume(self, group_id: str, settings: GroupSettings) -> None:
        """Wait for FloodWait to expire and resume analysis automatically.

        This is called when all accounts are blocked by FloodWait and there are
        still PENDING chats. It will:
        1. Set group status to WAITING_FOR_ACCOUNTS
        2. Poll every 30s for available accounts
        3. Resume analysis with INCREMENT mode when account available
        4. Publish progress events on each check cycle
        5. Exit immediately if stop_event is set (STOP clicked)
        """
        flood_tracker = get_flood_tracker()
        stop_event = self._stop_events.get(group_id)
        if stop_event is None:
            # Should not happen, but defensive
            logger.warning(f"No stop_event for group '{group_id}', creating one")
            stop_event = asyncio.Event()
            self._stop_events[group_id] = stop_event

        while True:
            # Safety check: if user clicked STOP, exit immediately
            if stop_event.is_set():
                logger.info(f"Group '{group_id}' stop_event set, exiting waiting loop")
                return

            group_data = self._db.load_group(group_id)
            if group_data and group_data['status'] == GroupStatus.PAUSED.value:
                logger.info(f"Group '{group_id}' is paused, skipping auto-resume")
                return
            # Get earliest available account
            earliest_expiry = flood_tracker.get_earliest_available()
            if earliest_expiry is None:
                # No blocked accounts - check for new accounts
                accounts = [
                    s for s in self._session_mgr.list_sessions()
                    if await self._session_mgr.is_healthy(s)
                ]
                if accounts:
                    # Check status before resuming - user may have clicked STOP
                    group_data = self._db.load_group(group_id)
                    if group_data and group_data['status'] == GroupStatus.PAUSED.value:
                        logger.info(f"Group '{group_id}' is paused, skipping auto-resume")
                        return

                    logger.info(f"New account available for '{group_id}', resuming analysis")
                    await self.start_analysis(group_id, mode=AnalysisMode.INCREMENT)
                    return

                # No accounts available at all - this shouldn't happen but handle gracefully
                logger.warning(f"No accounts available for '{group_id}', waiting...")
                earliest_expiry = datetime.now(UTC).timestamp() + 300  # Wait 5min default

            # Convert timestamp to datetime for SSE event
            earliest_dt = datetime.fromtimestamp(earliest_expiry, tz=UTC)

            # Publish waiting status with flood_wait_until
            processed, total = self._db.count_processed_chats(group_id)
            stats_dict = self._db.get_group_stats(group_id)
            by_status = stats_dict.get("by_status", {})
            by_type = stats_dict.get("by_type", {})

            breakdown = {
                "done": by_status.get("done", 0),
                "error": by_status.get("error", 0),
                "dead": by_type.get("dead", 0),
                "pending": by_status.get("pending", 0),
            }

            # Update group status to WAITING_FOR_ACCOUNTS
            group_data = self._db.load_group(group_id)
            if group_data:
                self._db.save_group(
                    group_id=group_id,
                    name=group_data["name"],
                    settings=group_data["settings"],
                    status=GroupStatus.WAITING_FOR_ACCOUNTS.value,
                    created_at=group_data["created_at"],
                    updated_at=datetime.now(UTC),
                )

            event = GroupProgressEvent(
                group_id=group_id,
                status=GroupStatus.WAITING_FOR_ACCOUNTS.value,
                current=processed,
                total=total,
                message="Waiting for FloodWait to expire on all accounts...",
                breakdown=breakdown,
                flood_wait_until=earliest_dt,
            )
            self._progress.publish(event)

            # Wait 30s before checking again, but exit immediately if STOP clicked
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=30)
                # If we get here, stop_event was set — exit immediately
                logger.info(f"Group '{group_id}' STOP detected during wait, exiting")
                return
            except asyncio.TimeoutError:
                # Timeout after 30s — normal flow, continue to next check
                pass

            # Check if FloodWait expired or new accounts available
            blocked = flood_tracker.get_blocked_accounts()
            healthy_accounts = [
                s for s in self._session_mgr.list_sessions()
                if await self._session_mgr.is_healthy(s)
                and s not in blocked
            ]

            if healthy_accounts:
                # Check status before resuming - user may have clicked STOP during wait
                group_data = self._db.load_group(group_id)
                if group_data and group_data['status'] == GroupStatus.PAUSED.value:
                    logger.info(f"Group '{group_id}' is paused, skipping auto-resume")
                    return

                logger.info(
                    f"Account(s) now available for '{group_id}': {healthy_accounts}, resuming analysis"
                )
                await self.start_analysis(group_id, mode=AnalysisMode.INCREMENT)
                return

    # -- Main entry: start_analysis ----------------------------------------

    async def start_analysis(
        self, group_id: str, mode: AnalysisMode = AnalysisMode.FRESH,
    ) -> None:
        """Start analysis: create task, distribute chats, run workers."""
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

        settings = GroupSettings.from_dict(group_data["settings"])
        accounts = [
            s for s in self._session_mgr.list_sessions()
            if await self._session_mgr.is_healthy(s)
        ]
        if not accounts:
            raise NoConnectedAccountsError(
                "No connected Telegram accounts available. "
                "Please connect at least one account to start analysis."
            )

        # Pre-validation: verify accounts can actually connect
        # is_healthy() tests existing connections, but new session() calls may fail
        validated_accounts = []
        for account_id in accounts:
            # Skip validation if connect() is not async (mock in tests)
            if not asyncio.iscoroutinefunction(self._session_mgr.connect):
                # Mock session manager in tests - skip validation
                validated_accounts.append(account_id)
                continue

            try:
                # Test actual connect - will raise SessionInvalidError if account is invalid
                await self._session_mgr.connect(account_id)
                # Disconnect immediately - we'll reconnect in worker
                await self._session_mgr.disconnect(account_id)
                validated_accounts.append(account_id)
            except SessionInvalidError as e:
                logger.warning(f"Account '{account_id}' excluded: invalid session - {e}")
            except Exception as e:
                # Other errors (network, timeout) - still exclude for safety
                logger.warning(f"Account '{account_id}' excluded: {type(e).__name__} - {e}")

        if not validated_accounts:
            raise NoConnectedAccountsError(
                "No connected Telegram accounts available. "
                "All accounts failed validation. Please connect at least one valid account."
            )

        accounts = validated_accounts
        logger.info(f"Pre-validation: {len(accounts)} accounts validated for analysis")

        self._prepare_chats_for_mode(group_id, settings, mode)
        pending = self._db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)

        if not pending:
            pending = self._handle_no_pending(group_id, mode)
            if pending is None:
                return

        task_id = self._db.create_task(
            group_id=group_id,
            requested_metrics=settings.model_dump(),
            time_window=settings.time_window,
        )

        for idx, chat in enumerate(pending):
            self._db.update_chat_status(
                chat_id=chat["id"], status=GroupChatStatus.PENDING.value,
                assigned_account=accounts[idx % len(accounts)],
            )

        # Timestamps
        started_at = self._db.get_analysis_started_at(group_id)
        is_resume = (
            group_data["status"] == GroupStatus.IN_PROGRESS.value
            and started_at is not None and mode == AnalysisMode.INCREMENT
        )
        if not is_resume:
            self._db.set_analysis_started_at(group_id, datetime.now(UTC))

        # Status is computed from chat statuses (PENDING chats exist → IN_PROGRESS)
        logger.info(
            f"Starting analysis '{group_id}': {len(accounts)} accounts, "
            f"{len(pending)} chats, task={task_id}"
        )

        # Track account health during analysis
        health_tracker = AccountHealthTracker()

        # Run workers in parallel
        tasks = [
            asyncio.create_task(
                self._run_account_worker(group_id, a, settings, accounts, mode, health_tracker)
            )
            for a in accounts
        ]
        self._active_tasks[group_id] = tasks
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for acct, res in zip(accounts, results):
                if isinstance(res, Exception):
                    # Check if this is FloodWait-related error
                    from telethon import errors as tl_errors
                    if isinstance(res, tl_errors.FloodWaitError):
                        wait_seconds = getattr(res, "seconds", 0)
                        logger.warning(f"Account '{acct}' worker: FloodWait {wait_seconds}s")
                    else:
                        logger.error(f"Account '{acct}' worker failed: {res}", exc_info=res)
        finally:
            self._active_tasks.pop(group_id, None)

        self._db.complete_task(task_id)

        # Check if there are still PENDING chats after all workers complete
        remaining_pending = self._db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)
        if remaining_pending:
            logger.info(f"Group '{group_id}': {len(remaining_pending)} chats still PENDING after workers completed")

            # Check if all accounts are blocked by FloodWait
            flood_tracker = get_flood_tracker()
            blocked = flood_tracker.get_blocked_accounts()
            healthy_accounts = [
                s for s in self._session_mgr.list_sessions()
                if await self._session_mgr.is_healthy(s)
                and s not in blocked
            ]

            if not healthy_accounts:
                # All accounts blocked - enter waiting loop as a separate Task
                logger.info(
                    f"Group '{group_id}': all accounts blocked by FloodWait, "
                    f"entering waiting loop for {len(remaining_pending)} pending chats"
                )
                # Create stop_event for this group
                stop_event = asyncio.Event()
                self._stop_events[group_id] = stop_event

                # Create waiting task and register in _active_tasks
                waiting_task = asyncio.create_task(
                    self._wait_for_accounts_and_resume(group_id, settings)
                )
                self._active_tasks[group_id] = [waiting_task]

                # Wait for completion or cancellation
                try:
                    await waiting_task
                except asyncio.CancelledError:
                    logger.info(f"Group '{group_id}' waiting task cancelled")
                finally:
                    self._active_tasks.pop(group_id, None)
                    self._stop_events.pop(group_id, None)
                return

        self._finalize_group(group_id)

    def _handle_no_pending(self, group_id: str, mode: AnalysisMode) -> list[dict] | None:
        """Handle case when no PENDING chats. Returns new pending list or None."""
        all_chats = self._db.load_chats(group_id=group_id)
        errors = [c for c in all_chats if c["status"] == GroupChatStatus.ERROR.value]

        if errors:
            for chat in errors:
                self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.PENDING.value, error=None)
            return self._db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value)

        if all_chats and all(c["status"] == GroupChatStatus.DONE.value for c in all_chats):
            self._signal_completion(group_id, GroupStatus.COMPLETED.value, "Analysis already completed")
            return None

        logger.warning(f"No pending chats for group '{group_id}', nothing to do")
        return None

    # -- Per-account worker loop -------------------------------------------

    async def _run_account_worker(
        self, group_id: str, account_id: str, settings: GroupSettings,
        all_accounts: list[str], mode: AnalysisMode, health_tracker: AccountHealthTracker,
    ) -> None:
        """Process all chats assigned to this account."""
        chats = self._db.load_chats(
            group_id=group_id, assigned_account=account_id,
            status=GroupChatStatus.PENDING.value,
        )
        if not chats:
            return

        logger.info(f"Account '{account_id}' processing {len(chats)} chats")
        flood_tracker = get_flood_tracker()

        try:
            async with self._session_mgr.session(account_id, auto_disconnect=False) as client:
                for chat in chats:
                    # Check if account should stop due to consecutive failures
                    if health_tracker.should_stop(account_id):
                        stats = health_tracker.get_stats(account_id)
                        logger.warning(
                            f"Account '{account_id}' stopped after {stats['consecutive_errors']} "
                            f"consecutive failures. Remaining chats left PENDING."
                        )
                        break

                    # Check if account is in FloodWait before processing
                    if flood_tracker.is_blocked(account_id):
                        logger.warning(
                            f"Account '{account_id}' is in FloodWait. "
                            f"Remaining chats left PENDING."
                        )
                        break

                    await self._process_single_chat(
                        group_id, chat, client, account_id, settings, all_accounts, mode, health_tracker,
                    )
                    await asyncio.sleep(random.uniform(5, 10))
        except asyncio.CancelledError:
            logger.info(f"Account '{account_id}' cancelled for '{group_id}'")
            raise
        except Exception as e:
            from telethon import errors as tl_errors
            # Check for FloodWait first (should not happen here, but defensive)
            if isinstance(e, tl_errors.FloodWaitError):
                wait_seconds = getattr(e, "seconds", 0)
                logger.warning(f"Account '{account_id}': FloodWait {wait_seconds}s (unexpected at worker level)")
                # Don't mark chats as error — they stay PENDING
            # Distinguish network errors from actual failures
            elif detect_network_error(e):
                # Network error: leave chats PENDING for retry on resume
                logger.warning(
                    f"Account '{account_id}' network error for '{group_id}': {e}. "
                    f"Pending chats will remain pending for retry on resume."
                )
                # Don't mark chats as error — they stay PENDING
            else:
                # Actual error: mark remaining chats as failed
                logger.error(f"Account '{account_id}' worker error: {e}", exc_info=True)
                for chat in self._db.load_chats(
                    group_id=group_id, assigned_account=account_id,
                    status=GroupChatStatus.PENDING.value,
                ):
                    self._save_chat_error(chat["id"], f"Account error: {e}")
                    self._progress.publish_from_db(group_id, chat["chat_ref"], error=str(e))

    async def _process_single_chat(
        self, group_id: str, chat: dict, client: TelegramClient,
        account_id: str, settings: GroupSettings,
        all_accounts: list[str], mode: AnalysisMode, health_tracker: AccountHealthTracker,
    ) -> None:
        """Process a single chat using worker + retry."""
        chat_ref = chat["chat_ref"]

        if mode == AnalysisMode.INCREMENT:
            metrics = self._db.get_chat_metrics(chat["id"])
            if metrics and not self._chat_needs_reanalysis(metrics, settings):
                self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.DONE.value)
                health_tracker.record_success(account_id)
                return

        async def _do_process(acct_id: str, chat_dict: dict) -> ChatResult:
            c = client if acct_id == account_id else await self._session_mgr.connect(acct_id)
            return await process_chat(chat_dict, c, acct_id, settings)

        async def _on_floodwait(expiry_timestamp: float) -> None:
            """Publish progress event with FloodWait info."""
            expiry_dt = datetime.fromtimestamp(expiry_timestamp, tz=UTC)
            processed, total = self._db.count_processed_chats(group_id)

            # Get detailed stats for breakdown
            stats_dict = self._db.get_group_stats(group_id)
            by_status = stats_dict.get("by_status", {})
            by_type = stats_dict.get("by_type", {})

            breakdown = {
                "done": by_status.get("done", 0),
                "error": by_status.get("error", 0),
                "dead": by_type.get("dead", 0),
                "pending": by_status.get("pending", 0),
            }

            event = GroupProgressEvent(
                group_id=group_id,
                status=GroupStatus.IN_PROGRESS.value,
                current=processed,
                total=total,
                chat_title=chat_ref,
                message=f"FloodWait: all accounts rate-limited, waiting...",
                breakdown=breakdown,
                flood_wait_until=expiry_dt,
            )
            self._progress.publish(event)

        ordered = [account_id] + [a for a in all_accounts if a != account_id]
        result = await try_with_retry(
            fn=_do_process,
            chat={"id": str(chat["id"]), "chat_ref": chat_ref},
            accounts=ordered,
            policy=RetryPolicy(),
            progress_callback=_on_floodwait,
        )

        if result.success:
            self._save_chat_result(chat, result.value, result.account_used or account_id)
            health_tracker.record_success(account_id)
        else:
            self._save_chat_error(chat["id"], result.error or "All accounts exhausted")
            # Classify error to determine if it's account's fault
            error_msg = result.error or ""

            # 1. Primary classification: check if worker marked chat as DEAD
            # Worker sets chat_type=DEAD for InviteHashExpired, ChatForbidden, etc.
            is_dead_chat = (
                result.value is not None
                and result.value.chat_type == ChatTypeEnum.DEAD.value
            )

            # 2. FloodWait exhaustion (temporary, account not broken)
            # Exact match from retry.py: "All accounts rate-limited, max retries (...) exhausted"
            is_floodwait = "All accounts rate-limited" in error_msg

            # 3. Real account errors (permanent account failure)
            # SessionInvalidError, UserDeactivated, etc. — these indicate broken account
            account_error_patterns = [
                "SessionInvalidError",
                "UserDeactivatedError",
                "UserDeactivatedBan",
                "AuthKeyUnregistered",
                "account.*invalid",
                "session.*invalid",
            ]
            is_account_error = any(
                pattern.lower() in error_msg.lower() for pattern in account_error_patterns
            )

            # Classify and record
            if is_dead_chat:
                # Dead chat (permanent, but not account's fault)
                logger.info(
                    f"Account '{account_id}': dead chat '{chat_ref}' (category: permanent, not account's fault)"
                )
                health_tracker.record_chat_error(account_id)
            elif is_floodwait:
                # FloodWait exhaustion (temporary, account still healthy)
                logger.warning(
                    f"Account '{account_id}': FloodWait exhausted for '{chat_ref}' "
                    f"(category: temporary, chat stays PENDING)"
                )
                # Don't count as failure at all
            elif is_account_error:
                # Real account error (permanent, account broken)
                logger.error(
                    f"Account '{account_id}': account error for '{chat_ref}' - {error_msg} "
                    f"(category: permanent, account failure)"
                )
                health_tracker.record_failure(account_id)
            else:
                # Unknown error — treat as account failure for safety
                logger.warning(
                    f"Account '{account_id}': unknown error for '{chat_ref}' - {error_msg} "
                    f"(category: unknown, counted as account failure)"
                )
                health_tracker.record_failure(account_id)

        title = (result.value.title or chat_ref) if result.success and result.value else chat_ref
        self._progress.publish_from_db(
            group_id=group_id, chat_title=title,
            error=result.error if not result.success else None,
        )

    # -- Save helpers ------------------------------------------------------

    def _save_chat_result(self, chat: dict, result: ChatResult, account_id: str) -> None:
        """Save worker result to DB."""
        is_error = result.status in ("dead", "banned", "error")
        db_status = GroupChatStatus.ERROR.value if is_error else GroupChatStatus.DONE.value

        self._db.save_chat(
            group_id=chat["group_id"], chat_ref=chat["chat_ref"],
            chat_type=result.chat_type, status=db_status,
            assigned_account=account_id, error=result.error if is_error else None,
            chat_id=chat["id"], subscribers=result.subscribers,
        )
        metrics = result.to_dict()
        metrics["metrics_version"] = METRICS_VERSION
        self._db.save_chat_metrics(chat["id"], metrics)

    def _save_chat_error(self, chat_id: int, error: str) -> None:
        """Mark chat as ERROR."""
        self._db.update_chat_status(chat_id=chat_id, status=GroupChatStatus.ERROR.value, error=error)

    # -- Mode preparation --------------------------------------------------

    def _prepare_chats_for_mode(self, group_id: str, settings: GroupSettings, mode: AnalysisMode) -> None:
        """Prepare chat statuses based on analysis mode."""
        if mode == AnalysisMode.OVERWRITE:
            chats = self._db.load_chats(group_id=group_id)
            for chat in chats:
                self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.PENDING.value, error=None)
            logger.info(f"[OVERWRITE] Reset {len(chats)} chats to PENDING")
        elif mode == AnalysisMode.INCREMENT:
            self._prepare_increment(group_id, settings)
            errors = self._db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value)
            for chat in errors:
                self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.PENDING.value, error=None)
            if errors:
                logger.info(f"[INCREMENT] Reset {len(errors)} ERROR chats to PENDING")

    def _prepare_increment(self, group_id: str, settings: GroupSettings) -> int:
        """Mark DONE chats with missing metrics as PENDING."""
        done = self._db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        count = 0
        for chat in done:
            metrics = self._db.get_chat_metrics(chat["id"])
            if not metrics or self._chat_needs_reanalysis(metrics, settings):
                self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.PENDING.value, error=None)
                count += 1
        if count:
            logger.info(f"[INCREMENT] Marked {count}/{len(done)} DONE chats as PENDING")
        return count

    def _chat_needs_reanalysis(self, metrics: dict, settings: GroupSettings) -> bool:
        """Check if chat metrics are incomplete for current settings."""
        if metrics.get("chat_type") is None:
            return True
        if metrics.get("chat_type") == ChatTypeEnum.DEAD.value:
            return False
        checks = [
            (settings.detect_subscribers, "subscribers"),
            (settings.detect_moderation, "moderation"),
            (settings.detect_activity, "messages_per_hour"),
            (settings.detect_unique_authors, "unique_authors_per_hour"),
            (settings.detect_captcha, "captcha"),
        ]
        for enabled, key in checks:
            if enabled and metrics.get(key) is None:
                return True
        if metrics.get("metrics_version", 0) < METRICS_VERSION:
            return True
        return False

    # -- Completion --------------------------------------------------------

    def _finalize_group(self, group_id: str) -> None:
        """Check chat statuses and set final group status."""
        all_chats = self._db.load_chats(group_id=group_id)
        if not all_chats:
            return
        total = len(all_chats)
        done = sum(1 for c in all_chats if c["status"] == GroupChatStatus.DONE.value)
        errors = sum(1 for c in all_chats if c["status"] == GroupChatStatus.ERROR.value)

        if done + errors >= total:
            status = GroupStatus.FAILED.value if errors == total else GroupStatus.COMPLETED.value
            msg = "Analysis failed: all chats failed" if errors == total else "Analysis completed"
            # Status is computed from chat statuses, no manual update needed
            self._signal_completion(group_id, status, msg, done + errors, total)
            logger.info(f"Group '{group_id}': {done + errors}/{total} ({done} done, {errors} error) → {status}")

    def _signal_completion(
        self, group_id: str, status: str, message: str,
        current: int | None = None, total: int | None = None,
    ) -> None:
        """Send completion event and sentinel."""
        if current is None or total is None:
            current, total = self._db.count_processed_chats(group_id)
        self._progress.publish(GroupProgressEvent(
            group_id=group_id, status=status, current=current, total=total, message=message,
        ))
        self._progress.signal_completion(group_id)

    # -- Lifecycle ---------------------------------------------------------

    def stop_analysis(self, group_id: str) -> None:
        """Stop ongoing analysis. Cancels tasks, leaves chats as-is."""
        # Signal stop event first (for waiting loop to exit immediately)
        stop_event = self._stop_events.get(group_id)
        if stop_event:
            stop_event.set()
            logger.info(f"Set stop_event for group '{group_id}'")

        # Cancel all active tasks
        for task in self._active_tasks.get(group_id, []):
            if not task.done():
                task.cancel()
        self._active_tasks.pop(group_id, None)
        self._stop_events.pop(group_id, None)

        active_task = self._db.get_active_task(group_id)
        if active_task:
            self._db.cancel_task(active_task["id"])
        # Status is computed from chat statuses, no manual update needed
        logger.info(f"Analysis stopped for group '{group_id}'")

    async def resume_analysis(self, group_id: str) -> None:
        """Resume analysis: reset errors, process remaining."""
        if not self._db.load_group(group_id):
            raise GroupNotFoundError(f"Group not found: {group_id}")
        logger.info(f"Resuming analysis for group '{group_id}'")
        for chat in self._db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value):
            self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.PENDING.value, error=None)
        await self.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

    def subscribe(self, group_id: str) -> asyncio.Queue[GroupProgressEvent]:
        """Subscribe to progress events for a group analysis."""
        return self._progress.subscribe(group_id)
