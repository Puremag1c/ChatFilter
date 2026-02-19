"""Business logic for chat group operations."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from chatfilter.importer.parser import _classify_entry
from chatfilter.models.group import (
    ChatGroup,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStats,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase


class GroupService:
    """Orchestrates chat group operations.

    This service provides business logic for creating, managing, and analyzing
    chat groups. It delegates persistence to GroupDatabase and uses the parser
    module for chat reference parsing.

    Attributes:
        _db: GroupDatabase instance for persistence.

    Example:
        >>> db = GroupDatabase("groups.db")
        >>> service = GroupService(db)
        >>> group = service.create_group("My Group", ["@channel1", "t.me/channel2"])
        >>> group.chat_count
        2
    """

    def __init__(self, db: GroupDatabase) -> None:
        """Initialize GroupService.

        Args:
            db: GroupDatabase instance for persistence.
        """
        self._db = db

    def create_group(
        self,
        name: str,
        chat_refs: list[str],
        settings: GroupSettings | None = None,
    ) -> ChatGroup:
        """Create a new chat group.

        Parses chat references and saves group to database.

        Args:
            name: Human-readable group name.
            chat_refs: List of chat references (usernames, links, IDs).
            settings: Optional group settings (default: GroupSettings()).

        Returns:
            Created ChatGroup instance.

        Raises:
            ValueError: If name is empty or chat_refs is empty.

        Example:
            >>> group = service.create_group(
            ...     "Test Group",
            ...     ["@channel1", "https://t.me/channel2"]
            ... )
            >>> group.chat_count
            2
        """
        if not name or not name.strip():
            raise ValueError("Group name cannot be empty")

        if not chat_refs:
            raise ValueError("chat_refs cannot be empty")

        # Generate unique group ID using UUID
        group_id = f"group-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

        # Use provided settings or default
        group_settings = settings or GroupSettings()

        # Save group to database
        self._db.save_group(
            group_id=group_id,
            name=name.strip(),
            settings=group_settings.model_dump(),
            status=GroupStatus.PENDING.value,
            created_at=now,
            updated_at=now,
        )

        # Parse and save chat references
        chat_count = 0
        for raw_ref in chat_refs:
            entry = _classify_entry(raw_ref)
            if entry:
                self._db.save_chat(
                    group_id=group_id,
                    chat_ref=entry.value,
                    chat_type=ChatTypeEnum.PENDING.value,
                    status=GroupChatStatus.PENDING.value,
                )
                chat_count += 1

        # Return ChatGroup instance
        return ChatGroup(
            id=group_id,
            name=name.strip(),
            settings=group_settings,
            status=GroupStatus.PENDING,
            chat_count=chat_count,
            created_at=now,
            updated_at=now,
        )

    def get_group(self, group_id: str) -> ChatGroup | None:
        """Get a chat group by ID.

        Args:
            group_id: Group identifier.

        Returns:
            ChatGroup instance or None if not found.

        Example:
            >>> group = service.get_group("group-123")
            >>> if group:
            ...     print(group.name)
        """
        group_data = self._db.load_group(group_id)
        if not group_data:
            return None

        # Get chat count from stats
        stats_data = self._db.get_group_stats(group_id)
        chat_count = stats_data["total"]

        # Handle legacy data where settings might be None or invalid
        settings_dict = group_data["settings"]
        if settings_dict is None or not isinstance(settings_dict, dict):
            settings_dict = {}

        return ChatGroup(
            id=group_data["id"],
            name=group_data["name"],
            settings=GroupSettings.from_dict(settings_dict),
            status=GroupStatus(group_data["status"]),
            chat_count=chat_count,
            created_at=group_data["created_at"],
            updated_at=group_data["updated_at"],
        )

    def list_groups(self) -> list[ChatGroup]:
        """List all chat groups.

        Returns:
            List of ChatGroup instances, sorted by creation time (newest first).

        Example:
            >>> groups = service.list_groups()
            >>> for group in groups:
            ...     print(f"{group.name}: {group.chat_count} chats")
        """
        # Use optimized query that fetches groups with counts in single DB roundtrip
        groups_data = self._db.load_all_groups_with_stats()

        groups = []
        for group_data in groups_data:
            # Handle legacy data where settings might be None or invalid
            settings_dict = group_data["settings"]
            if settings_dict is None or not isinstance(settings_dict, dict):
                settings_dict = {}

            groups.append(
                ChatGroup(
                    id=group_data["id"],
                    name=group_data["name"],
                    settings=GroupSettings.from_dict(settings_dict),
                    status=GroupStatus(group_data["status"]),
                    chat_count=group_data["chat_count"],
                    created_at=group_data["created_at"],
                    updated_at=group_data["updated_at"],
                )
            )

        return groups

    def update_settings(
        self,
        group_id: str,
        settings: GroupSettings,
    ) -> GroupSettings:
        """Update group settings.

        Args:
            group_id: Group identifier.
            settings: New group settings.

        Returns:
            Updated GroupSettings instance.

        Raises:
            ValueError: If group not found.

        Example:
            >>> new_settings = GroupSettings(message_limit=500, leave_after_analysis=True)
            >>> updated = service.update_settings("group-123", new_settings)
        """
        group_data = self._db.load_group(group_id)
        if not group_data:
            raise ValueError(f"Group not found: {group_id}")

        # Update group with new settings
        self._db.save_group(
            group_id=group_id,
            name=group_data["name"],
            settings=settings.model_dump(),
            status=group_data["status"],
            created_at=group_data["created_at"],
            updated_at=datetime.now(UTC),
        )

        return settings

    def get_group_stats(self, group_id: str) -> GroupStats:
        """Get statistics for a group.

        Counts chats by type and status.

        Args:
            group_id: Group identifier.

        Returns:
            GroupStats instance with counts.

        Example:
            >>> stats = service.get_group_stats("group-123")
            >>> print(f"Total: {stats.total}, Analyzed: {stats.analyzed}")
        """
        stats_data = self._db.get_group_stats(group_id)

        by_type = stats_data["by_type"]
        by_status = stats_data["by_status"]

        return GroupStats(
            total=stats_data["total"],
            pending=by_type.get(ChatTypeEnum.PENDING.value, 0),
            dead=by_type.get(ChatTypeEnum.DEAD.value, 0),
            groups=by_type.get(ChatTypeEnum.GROUP.value, 0),
            forums=by_type.get(ChatTypeEnum.FORUM.value, 0),
            channels_with_comments=by_type.get(ChatTypeEnum.CHANNEL_COMMENTS.value, 0),
            channels_no_comments=by_type.get(ChatTypeEnum.CHANNEL_NO_COMMENTS.value, 0),
            analyzed=by_status.get(GroupChatStatus.DONE.value, 0),
            failed=by_status.get(GroupChatStatus.FAILED.value, 0),
            skipped_moderation=stats_data.get("skipped_moderation", 0),
            status_pending=by_status.get(GroupChatStatus.PENDING.value, 0),
            status_joining=by_status.get(GroupChatStatus.JOINING.value, 0),
            status_analyzing=by_status.get(GroupChatStatus.ANALYZING.value, 0),
        )

    def update_group_name(self, group_id: str, new_name: str) -> ChatGroup | None:
        """Update a chat group's name.

        Args:
            group_id: Group identifier.
            new_name: New group name.

        Returns:
            Updated ChatGroup or None if group not found.

        Example:
            >>> group = service.update_group_name("group-123", "New Name")
            >>> group.name
            'New Name'
        """
        # Load existing group
        group = self.get_group(group_id)
        if not group:
            return None

        # Save with new name (save_group handles upsert)
        self._db.save_group(
            group_id=group.id,
            name=new_name.strip(),
            settings=group.settings.model_dump(),
            status=group.status.value,
            created_at=group.created_at,
            updated_at=datetime.now(UTC),
        )

        # Reload and return updated group
        return self.get_group(group_id)

    def update_status(self, group_id: str, new_status: GroupStatus) -> ChatGroup | None:
        """Update a chat group's status.

        Args:
            group_id: Group identifier.
            new_status: New group status.

        Returns:
            Updated ChatGroup or None if group not found.

        Example:
            >>> group = service.update_status("group-123", GroupStatus.IN_PROGRESS)
            >>> group.status
            <GroupStatus.IN_PROGRESS: 'in_progress'>
        """
        # Load existing group
        group = self.get_group(group_id)
        if not group:
            return None

        # Save with new status (save_group handles upsert)
        self._db.save_group(
            group_id=group.id,
            name=group.name,
            settings=group.settings.model_dump(),
            status=new_status.value,
            created_at=group.created_at,
            updated_at=datetime.now(UTC),
        )

        # Reload and return updated group
        return self.get_group(group_id)

    def delete_group(self, group_id: str) -> None:
        """Delete a chat group.

        Removes group and all associated chats and results (CASCADE).

        Args:
            group_id: Group identifier.

        Example:
            >>> service.delete_group("group-123")
        """
        self._db.delete_group(group_id)
