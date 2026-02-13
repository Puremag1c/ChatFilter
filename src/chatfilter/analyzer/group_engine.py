"""GroupAnalysisEngine: orchestrates group chat analysis workflow.

Phase 1: Join chats and resolve chat types.
Phase 2: Run analysis tasks via TaskQueue.
Phase 3: Cleanup and completion.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from telethon import errors

from chatfilter.analyzer.task_queue import ProgressEvent, TaskStatus
from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupStatus
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.client import join_chat
from chatfilter.telegram.session_manager import SessionManager

if TYPE_CHECKING:
    from telethon import TelegramClient

    from chatfilter.analyzer.task_queue import AnalysisExecutor, TaskQueue

logger = logging.getLogger(__name__)


@dataclass
class GroupProgressEvent:
    """Progress event for group analysis workflow.

    Similar to TaskQueue.ProgressEvent but group-scoped.
    Proxies TaskQueue progress and adds group context.

    Attributes:
        group_id: Group identifier
        status: Current status (maps from TaskStatus)
        current: Current chat index
        total: Total number of chats
        chat_title: Currently processing chat title
        message: Status message
        error: Error message if failed
        task_id: Optional underlying TaskQueue task_id
    """

    group_id: str
    status: str  # GroupStatus or TaskStatus value
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

    Phase 1: Join chats and resolve chat types per-account.
    Phase 2: Run analysis via TaskQueue.
    Phase 3: Cleanup and completion (implemented in separate task).

    Attributes:
        db: GroupDatabase for persistence.
        session_manager: SessionManager for Telegram client access.
        task_queue: TaskQueue for analysis execution.
        executor: AnalysisExecutor implementation.

    Example:
        >>> db = GroupDatabase("groups.db")
        >>> session_mgr = SessionManager()
        >>> task_queue = get_task_queue()
        >>> executor = RealAnalysisExecutor()
        >>> engine = GroupAnalysisEngine(db, session_mgr, task_queue, executor)
        >>> await engine.start_analysis("group-abc123")
    """

    def __init__(
        self,
        db: GroupDatabase,
        session_manager: SessionManager,
        task_queue: TaskQueue,
        executor: AnalysisExecutor,
    ) -> None:
        """Initialize GroupAnalysisEngine.

        Args:
            db: GroupDatabase instance.
            session_manager: SessionManager for client access.
            task_queue: TaskQueue for analysis execution.
            executor: AnalysisExecutor implementation.
        """
        self._db = db
        self._session_mgr = session_manager
        self._task_queue = task_queue
        self._executor = executor

    async def start_analysis(self, group_id: str) -> None:
        """Phase 1: Join chats and resolve chat types.

        This method:
        1. Loads group from database
        2. Gets connected accounts from SessionManager
        3. Distributes PENDING chats round-robin across accounts
        4. Sets group status to IN_PROGRESS
        5. For each account: joins chats and resolves chat_type
        6. Updates database per-chat with status and chat_type
        7. Handles errors (FloodWait, ChatNotFound, etc.)

        Args:
            group_id: Group identifier to analyze.

        Raises:
            GroupNotFoundError: If group doesn't exist.
            NoConnectedAccountsError: If no accounts are connected.
            GroupEngineError: For other analysis errors.

        Example:
            >>> await engine.start_analysis("group-abc123")
        """
        # 1. Load group and validate
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

        # 2. Get connected accounts
        connected_accounts = [
            sid for sid in self._session_mgr.list_sessions()
            if await self._session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
            raise NoConnectedAccountsError(
                "No connected Telegram accounts available. "
                "Please connect at least one account to start analysis."
            )

        logger.info(
            f"Starting analysis for group '{group_id}' with "
            f"{len(connected_accounts)} connected accounts"
        )

        # 3. Load PENDING chats and distribute round-robin
        pending_chats = self._db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.PENDING.value,
        )

        if not pending_chats:
            logger.warning(f"No pending chats found for group '{group_id}'")
            return

        # Distribute chats round-robin
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

        # 4. Set group status to IN_PROGRESS
        self._db.save_group(
            group_id=group_id,
            name=group_data["name"],
            settings=group_data["settings"],
            status=GroupStatus.IN_PROGRESS.value,
            created_at=group_data["created_at"],
            updated_at=datetime.now(UTC),
        )

        # 5. Process chats per-account in parallel
        tasks = []
        for account_id in connected_accounts:
            task = asyncio.create_task(
                self._process_account_chats(group_id, account_id)
            )
            tasks.append(task)

        # Wait for all accounts to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log errors from any failed account tasks
        for account_id, result in zip(connected_accounts, results):
            if isinstance(result, Exception):
                logger.error(
                    f"Account '{account_id}' failed: {result}",
                    exc_info=result,
                )

    async def _process_account_chats(
        self,
        group_id: str,
        account_id: str,
    ) -> None:
        """Process chats assigned to a specific account.

        Joins each chat, resolves chat_type via get_entity(),
        and updates database. Handles FloodWait by pausing and
        marking chats as FAILED for redistribution.

        Args:
            group_id: Group identifier.
            account_id: Account/session identifier.
        """
        # Load chats assigned to this account
        account_chats = self._db.load_chats(
            group_id=group_id,
            assigned_account=account_id,
            status=GroupChatStatus.PENDING.value,
        )

        if not account_chats:
            logger.debug(f"No chats assigned to account '{account_id}'")
            return

        logger.info(
            f"Account '{account_id}': processing {len(account_chats)} chats"
        )

        try:
            async with self._session_mgr.session(
                account_id,
                auto_disconnect=False,
            ) as client:
                for chat in account_chats:
                    try:
                        await self._join_and_resolve_chat(
                            client=client,
                            group_id=group_id,
                            chat=chat,
                            account_id=account_id,
                        )
                    except errors.FloodWaitError as e:
                        wait_seconds = getattr(e, "seconds", 0)
                        logger.warning(
                            f"Account '{account_id}': FloodWait {wait_seconds}s "
                            f"on chat '{chat['chat_ref']}'. Stopping account."
                        )
                        self._db.update_chat_status(
                            chat_id=chat["id"],
                            status=GroupChatStatus.FAILED.value,
                            error=f"FloodWait: {wait_seconds}s",
                        )
                        break
        except Exception as e:
            logger.error(
                f"Account '{account_id}': unexpected error: {e}",
                exc_info=True,
            )
            # Only mark chats still PENDING as FAILED (not already-DONE ones)
            remaining = self._db.load_chats(
                group_id=group_id,
                assigned_account=account_id,
                status=GroupChatStatus.PENDING.value,
            )
            for chat in remaining:
                self._db.update_chat_status(
                    chat_id=chat["id"],
                    status=GroupChatStatus.FAILED.value,
                    error=f"Account error: {str(e)}",
                )

    async def _join_and_resolve_chat(
        self,
        client: TelegramClient,
        group_id: str,
        chat: dict,
        account_id: str,
    ) -> None:
        """Join a single chat and resolve its type.

        Args:
            client: Connected TelegramClient.
            group_id: Group identifier.
            chat: Chat record dict from database.
            account_id: Account identifier (for logging).
        """
        chat_id = chat["id"]
        chat_ref = chat["chat_ref"]

        # Update status to JOINING
        self._db.update_chat_status(
            chat_id=chat_id,
            status=GroupChatStatus.JOINING.value,
        )

        try:
            # Join chat
            logger.debug(f"Account '{account_id}': joining chat '{chat_ref}'")
            joined_chat = await join_chat(client, chat_ref)

            # Resolve chat type based on Telegram entity type
            chat_type = self._map_chat_type_to_enum(joined_chat.chat_type.value)

            # Update database with resolved chat_type
            self._db.save_chat(
                group_id=group_id,
                chat_ref=chat_ref,
                chat_type=chat_type,
                status=GroupChatStatus.DONE.value,
                assigned_account=account_id,
                chat_id=chat_id,
            )

            logger.info(
                f"Account '{account_id}': joined '{chat_ref}' "
                f"(type={chat_type})"
            )

        except errors.FloodWaitError:
            # Re-raise to be caught by _process_account_chats loop
            raise

        except (
            errors.ChatForbiddenError,
            errors.ChannelPrivateError,
            errors.ChatRestrictedError,
            errors.ChannelBannedError,
            errors.UserBannedInChannelError,
        ) as e:
            # Chat is inaccessible - mark as DEAD
            logger.info(
                f"Account '{account_id}': chat '{chat_ref}' is inaccessible "
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

        except Exception as e:
            # Unknown error - mark as FAILED
            logger.error(
                f"Account '{account_id}': failed to join '{chat_ref}': {e}",
                exc_info=True,
            )

            self._db.update_chat_status(
                chat_id=chat_id,
                status=GroupChatStatus.FAILED.value,
                error=str(e),
            )

    def _map_chat_type_to_enum(self, chat_type_str: str) -> str:
        """Map ChatType from models.chat to ChatTypeEnum for groups.

        Args:
            chat_type_str: ChatType value string from models.chat.

        Returns:
            Mapped ChatTypeEnum value string.
        """
        # Map ChatType to ChatTypeEnum
        # ChatType: private, group, supergroup, channel, forum
        # ChatTypeEnum: pending, group, forum, channel_comments, channel_no_comments, dead

        mapping = {
            "group": ChatTypeEnum.GROUP.value,
            "supergroup": ChatTypeEnum.GROUP.value,  # Treat supergroup as group
            "forum": ChatTypeEnum.FORUM.value,
            "channel": ChatTypeEnum.CHANNEL_NO_COMMENTS.value,  # Default to no comments
            "private": ChatTypeEnum.DEAD.value,  # Private chats are not analyzable
        }

        return mapping.get(chat_type_str, ChatTypeEnum.PENDING.value)

    async def _phase2_analyze(self, group_id: str) -> None:
        """Phase 2: Run analysis tasks via TaskQueue.

        This method:
        1. Loads all DONE chats from Phase 1 (joined and type-resolved)
        2. Groups chats by assigned_account
        3. For each account: creates TaskQueue task and runs it
        4. Proxies TaskQueue ProgressEvent as GroupProgressEvent
        5. On task completion: copies results from TaskDatabase to GroupDatabase
        6. Updates chat statuses from ANALYZING to DONE

        Args:
            group_id: Group identifier to analyze.

        Raises:
            GroupNotFoundError: If group doesn't exist.
            GroupEngineError: For other analysis errors.

        Example:
            >>> await engine._phase2_analyze("group-abc123")
        """
        # 1. Load group and validate
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise GroupNotFoundError(f"Group not found: {group_id}")

        # 2. Load all DONE chats from Phase 1 (successfully joined)
        done_chats = self._db.load_chats(
            group_id=group_id,
            status=GroupChatStatus.DONE.value,
        )

        if not done_chats:
            logger.warning(f"No DONE chats found for group '{group_id}' - Phase 1 incomplete?")
            return

        logger.info(f"Phase 2: Analyzing {len(done_chats)} chats for group '{group_id}'")

        # 3. Group chats by assigned_account
        chats_by_account: dict[str, list[dict]] = {}
        for chat in done_chats:
            account_id = chat.get("assigned_account")
            if not account_id:
                logger.warning(f"Chat {chat['id']} has no assigned_account, skipping")
                continue
            chats_by_account.setdefault(account_id, []).append(chat)

        # 4. Process each account's chats via TaskQueue
        tasks = []
        for account_id, account_chats in chats_by_account.items():
            task = asyncio.create_task(
                self._analyze_account_chats(group_id, account_id, account_chats)
            )
            tasks.append(task)

        # Wait for all accounts to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log errors from any failed account tasks
        for account_id, result in zip(chats_by_account.keys(), results):
            if isinstance(result, Exception):
                logger.error(
                    f"Account '{account_id}' analysis failed: {result}",
                    exc_info=result,
                )

    async def _analyze_account_chats(
        self,
        group_id: str,
        account_id: str,
        account_chats: list[dict],
    ) -> None:
        """Run analysis for chats assigned to a specific account.

        Creates a TaskQueue task, runs it, proxies progress events,
        and copies results to GroupDatabase on completion.

        Args:
            group_id: Group identifier.
            account_id: Account/session identifier.
            account_chats: List of chat records assigned to this account.
        """
        # Extract chat_ids from chat_ref (assume chat_ref contains numeric ID or parse from link)
        # For now, we need to resolve chat_ref to numeric chat_id
        # This requires joining first (already done in Phase 1)
        # We need to store numeric chat_id in Phase 1 or re-join here

        # TODO: Phase 1 should store resolved numeric chat_id in database
        # For now, we'll need to get it from joined_chat entity

        # Actually, looking at join_chat implementation, it returns JoinedChat
        # which has .chat_id field. We need to extract this during Phase 1.

        # WORKAROUND: Re-join to get chat_id (inefficient but works)
        chat_ids: list[int] = []
        chat_id_to_db_id: dict[int, int] = {}  # Map numeric chat_id -> db chat record id

        async with self._session_mgr.session(
            account_id,
            auto_disconnect=False,
        ) as client:
            for chat in account_chats:
                try:
                    # Re-join to get numeric chat_id
                    joined_chat = await join_chat(client, chat["chat_ref"])
                    chat_ids.append(joined_chat.chat_id)
                    chat_id_to_db_id[joined_chat.chat_id] = chat["id"]
                except Exception as e:
                    logger.warning(
                        f"Failed to resolve chat_id for '{chat['chat_ref']}': {e}"
                    )
                    continue

        if not chat_ids:
            logger.warning(f"No valid chat_ids for account '{account_id}'")
            return

        logger.info(
            f"Account '{account_id}': creating TaskQueue task for {len(chat_ids)} chats"
        )

        # Create TaskQueue task
        group_settings = group_data["settings"]
        message_limit = group_settings.get("message_limit", 1000)

        task = self._task_queue.create_task(
            session_id=account_id,
            chat_ids=chat_ids,
            message_limit=message_limit,
        )

        # Subscribe to progress events
        progress_queue = await self._task_queue.subscribe(task.task_id)

        # Run task in background and proxy progress events
        async def run_and_proxy() -> None:
            """Run task and proxy progress events to group subscribers."""
            try:
                # Start task execution
                asyncio.create_task(
                    self._task_queue.run_task(task.task_id, self._executor)
                )

                # Proxy progress events
                async for event in self._iter_progress_queue(progress_queue):
                    if event is None:
                        break  # Task completed

                    # Proxy to group progress event
                    # (In full implementation, this would publish to group subscribers)
                    logger.debug(
                        f"Group '{group_id}' progress: {event.current}/{event.total} "
                        f"({event.message})"
                    )

                    # Update chat status to ANALYZING if in progress
                    if event.status == TaskStatus.IN_PROGRESS and event.current < len(chat_ids):
                        db_chat_id = chat_id_to_db_id.get(chat_ids[event.current])
                        if db_chat_id:
                            self._db.update_chat_status(
                                chat_id=db_chat_id,
                                status=GroupChatStatus.ANALYZING.value,
                            )

            finally:
                await self._task_queue.unsubscribe(task.task_id, progress_queue)

        await run_and_proxy()

        # Task completed - copy results to GroupDatabase
        completed_task = self._task_queue.get_task(task.task_id)
        if not completed_task:
            logger.error(f"Task {task.task_id} not found after completion")
            return

        if completed_task.status == TaskStatus.COMPLETED:
            logger.info(
                f"Account '{account_id}': copying {len(completed_task.results)} results to GroupDatabase"
            )

            for result in completed_task.results:
                # Find chat_ref by matching result.chat.id to our chat_id_to_db_id map
                numeric_chat_id = result.chat.id
                db_chat_id = chat_id_to_db_id.get(numeric_chat_id)

                if not db_chat_id:
                    logger.warning(f"No db_chat_id found for numeric chat_id {numeric_chat_id}")
                    continue

                # Load chat record to get chat_ref
                chat_record = next(
                    (c for c in account_chats if c["id"] == db_chat_id),
                    None,
                )
                if not chat_record:
                    logger.warning(f"Chat record not found for db_chat_id {db_chat_id}")
                    continue

                chat_ref = chat_record["chat_ref"]

                # Save result to GroupDatabase
                self._db.save_result(
                    group_id=group_id,
                    chat_ref=chat_ref,
                    metrics_data=result.metrics.model_dump(),
                    analyzed_at=result.analyzed_at,
                )

                # Update chat status to DONE
                self._db.update_chat_status(
                    chat_id=db_chat_id,
                    status=GroupChatStatus.DONE.value,
                )

            logger.info(f"Account '{account_id}': Phase 2 complete")
        else:
            logger.error(
                f"Account '{account_id}': Task {task.task_id} failed with status {completed_task.status}"
            )

    async def _iter_progress_queue(
        self,
        queue: asyncio.Queue[ProgressEvent | None],
    ) -> asyncio.AsyncIterator[ProgressEvent | None]:
        """Async iterator for progress queue.

        Args:
            queue: Progress event queue from TaskQueue.subscribe()

        Yields:
            ProgressEvent or None (signals completion)
        """
        while True:
            event = await queue.get()
            yield event
            if event is None:
                break
