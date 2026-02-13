"""GroupAnalysisEngine: orchestrates group chat analysis workflow.

Phase 1: Join chats and resolve chat types.
Phase 2: Run analysis tasks via TaskQueue.
Phase 3: Cleanup and completion.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from telethon import errors

from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupStatus
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.telegram.client import join_chat
from chatfilter.telegram.session_manager import SessionManager

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)


class GroupEngineError(Exception):
    """Base exception for GroupEngine errors."""


class GroupNotFoundError(GroupEngineError):
    """Raised when group ID doesn't exist in database."""


class NoConnectedAccountsError(GroupEngineError):
    """Raised when no accounts are connected to perform analysis."""


class GroupAnalysisEngine:
    """Orchestrates multi-account group analysis workflow.

    Phase 1: Join chats and resolve chat types per-account.
    Phase 2: Run analysis via TaskQueue (implemented in separate task).
    Phase 3: Cleanup and completion (implemented in separate task).

    Attributes:
        db: GroupDatabase for persistence.
        session_manager: SessionManager for Telegram client access.

    Example:
        >>> db = GroupDatabase("groups.db")
        >>> session_mgr = SessionManager()
        >>> engine = GroupAnalysisEngine(db, session_mgr)
        >>> await engine.start_analysis("group-abc123")
    """

    def __init__(
        self,
        db: GroupDatabase,
        session_manager: SessionManager,
    ) -> None:
        """Initialize GroupAnalysisEngine.

        Args:
            db: GroupDatabase instance.
            session_manager: SessionManager for client access.
        """
        self._db = db
        self._session_mgr = session_manager

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
                    await self._join_and_resolve_chat(
                        client=client,
                        group_id=group_id,
                        chat=chat,
                        account_id=account_id,
                    )
        except Exception as e:
            logger.error(
                f"Account '{account_id}': unexpected error: {e}",
                exc_info=True,
            )
            # Mark all pending chats for this account as FAILED
            for chat in account_chats:
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

        except errors.FloodWaitError as e:
            # Rate limited - pause this account and mark chat as FAILED
            wait_seconds = getattr(e, "seconds", 0)
            logger.warning(
                f"Account '{account_id}': FloodWait {wait_seconds}s "
                f"on chat '{chat_ref}'. Pausing account."
            )

            # Mark chat as FAILED with error message
            self._db.update_chat_status(
                chat_id=chat_id,
                status=GroupChatStatus.FAILED.value,
                error=f"FloodWait: {wait_seconds}s",
            )

            # Raise to stop processing more chats for this account
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
