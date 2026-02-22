"""GroupAnalysisEngine: thin orchestrator for group chat analysis.

Single-pass model: each chat goes Pending → Done/Error in one step.
Uses worker.process_chat() for processing and retry.try_with_retry()
for FloodWait handling and account rotation.
"""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from chatfilter.analyzer.progress import GroupProgressEvent, ProgressTracker
from chatfilter.analyzer.retry import RetryPolicy, try_with_retry
from chatfilter.analyzer.worker import ChatResult, process_chat
from chatfilter.models.group import (
    AnalysisMode,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.session_manager import SessionManager
from chatfilter.utils.network import detect_network_error

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

METRICS_VERSION = 2


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
        self._progress = progress if progress is not None else ProgressTracker(db)

    # -- Startup recovery --------------------------------------------------

    def recover_stale_analysis(self) -> None:
        """Reset groups stuck in in_progress after server restart."""
        stale = [
            g for g in self._db.load_all_groups()
            if g["status"] == GroupStatus.IN_PROGRESS.value
        ]
        if not stale:
            logger.info("No stale in_progress groups — recovery skipped")
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

        # Run workers in parallel
        tasks = [
            asyncio.create_task(
                self._run_account_worker(group_id, a, settings, accounts, mode)
            )
            for a in accounts
        ]
        self._active_tasks[group_id] = tasks
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for acct, res in zip(accounts, results):
                if isinstance(res, Exception):
                    logger.error(f"Account '{acct}' worker failed: {res}", exc_info=res)
        finally:
            self._active_tasks.pop(group_id, None)

        self._db.complete_task(task_id)
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
        all_accounts: list[str], mode: AnalysisMode,
    ) -> None:
        """Process all chats assigned to this account."""
        chats = self._db.load_chats(
            group_id=group_id, assigned_account=account_id,
            status=GroupChatStatus.PENDING.value,
        )
        if not chats:
            return

        logger.info(f"Account '{account_id}' processing {len(chats)} chats")
        try:
            async with self._session_mgr.session(account_id, auto_disconnect=False) as client:
                for chat in chats:
                    await self._process_single_chat(
                        group_id, chat, client, account_id, settings, all_accounts, mode,
                    )
                    await asyncio.sleep(5.0 + random.random() * 2)
        except asyncio.CancelledError:
            logger.info(f"Account '{account_id}' cancelled for '{group_id}'")
            raise
        except Exception as e:
            # Distinguish network errors from actual failures
            if detect_network_error(e):
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
        all_accounts: list[str], mode: AnalysisMode,
    ) -> None:
        """Process a single chat using worker + retry."""
        chat_ref = chat["chat_ref"]

        if mode == AnalysisMode.INCREMENT:
            metrics = self._db.get_chat_metrics(chat["id"])
            if metrics and not self._chat_needs_reanalysis(metrics, settings):
                self._db.update_chat_status(chat_id=chat["id"], status=GroupChatStatus.DONE.value)
                return

        async def _do_process(acct_id: str, chat_dict: dict) -> ChatResult:
            c = client if acct_id == account_id else await self._session_mgr.connect(acct_id)
            return await process_chat(chat_dict, c, acct_id, settings)

        ordered = [account_id] + [a for a in all_accounts if a != account_id]
        result = await try_with_retry(
            fn=_do_process,
            chat={"id": str(chat["id"]), "chat_ref": chat_ref},
            accounts=ordered,
            policy=RetryPolicy(),
        )

        if result.success:
            self._save_chat_result(chat, result.value, result.account_used or account_id)
        else:
            self._save_chat_error(chat["id"], result.error or "All accounts exhausted")

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
        for task in self._active_tasks.get(group_id, []):
            if not task.done():
                task.cancel()
        self._active_tasks.pop(group_id, None)
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
