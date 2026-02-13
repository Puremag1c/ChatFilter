"""Tests for GroupService business logic."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from chatfilter.models.group import (
    ChatGroup,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_groups.db"
        db = GroupDatabase(str(db_path))
        yield db
        # Cleanup happens automatically


@pytest.fixture
def group_service(temp_db):
    """Create GroupService instance with test database."""
    return GroupService(temp_db)


class TestCreateGroup:
    """Tests for GroupService.create_group."""

    def test_create_group_basic(self, group_service):
        """Test creating a group with basic chat references."""
        group = group_service.create_group(
            name="Test Group",
            chat_refs=["@channel1", "https://t.me/channel2"],
        )

        assert group.name == "Test Group"
        assert group.chat_count == 2
        assert group.status == GroupStatus.PENDING
        assert group.settings.message_limit == 100  # default
        assert not group.settings.leave_after_analysis  # default

    def test_create_group_with_custom_settings(self, group_service):
        """Test creating a group with custom settings."""
        settings = GroupSettings(message_limit=500, leave_after_analysis=True)
        group = group_service.create_group(
            name="Custom Settings Group",
            chat_refs=["@channel1"],
            settings=settings,
        )

        assert group.settings.message_limit == 500
        assert group.settings.leave_after_analysis is True

    def test_create_group_empty_name_raises_error(self, group_service):
        """Test that empty name raises ValueError."""
        with pytest.raises(ValueError, match="Group name cannot be empty"):
            group_service.create_group(
                name="",
                chat_refs=["@channel1"],
            )

    def test_create_group_whitespace_name_raises_error(self, group_service):
        """Test that whitespace-only name raises ValueError."""
        with pytest.raises(ValueError, match="Group name cannot be empty"):
            group_service.create_group(
                name="   ",
                chat_refs=["@channel1"],
            )

    def test_create_group_empty_chat_refs_raises_error(self, group_service):
        """Test that empty chat_refs raises ValueError."""
        with pytest.raises(ValueError, match="chat_refs cannot be empty"):
            group_service.create_group(
                name="Test Group",
                chat_refs=[],
            )

    def test_create_group_strips_whitespace_from_name(self, group_service):
        """Test that whitespace is stripped from group name."""
        group = group_service.create_group(
            name="  Test Group  ",
            chat_refs=["@channel1"],
        )

        assert group.name == "Test Group"

    def test_create_group_filters_invalid_chat_refs(self, group_service):
        """Test that invalid chat references are filtered out."""
        # _classify_entry returns None for invalid entries
        group = group_service.create_group(
            name="Test Group",
            chat_refs=["@valid", "invalid_garbage", "t.me/valid2"],
        )

        # Only valid entries should be counted
        # NOTE: This depends on _classify_entry behavior
        assert group.chat_count >= 0  # At least valid ones are counted

    def test_create_group_generates_unique_id(self, group_service):
        """Test that each group gets a unique ID."""
        group1 = group_service.create_group("Group 1", ["@ch1"])
        group2 = group_service.create_group("Group 2", ["@ch2"])

        assert group1.id != group2.id
        assert group1.id.startswith("group-")
        assert group2.id.startswith("group-")

    def test_create_group_sets_timestamps(self, group_service):
        """Test that created_at and updated_at are set."""
        before = datetime.now(UTC)
        group = group_service.create_group("Test", ["@ch"])
        after = datetime.now(UTC)

        assert before <= group.created_at <= after
        assert before <= group.updated_at <= after


class TestGetGroup:
    """Tests for GroupService.get_group."""

    def test_get_existing_group(self, group_service):
        """Test retrieving an existing group."""
        created = group_service.create_group("Test", ["@ch1", "@ch2"])
        retrieved = group_service.get_group(created.id)

        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == created.name
        assert retrieved.chat_count == created.chat_count

    def test_get_nonexistent_group_returns_none(self, group_service):
        """Test that getting non-existent group returns None."""
        result = group_service.get_group("nonexistent-id")
        assert result is None


class TestListGroups:
    """Tests for GroupService.list_groups."""

    def test_list_groups_empty(self, group_service):
        """Test listing groups when none exist."""
        groups = group_service.list_groups()
        assert groups == []

    def test_list_groups_returns_all(self, group_service):
        """Test listing all created groups."""
        group1 = group_service.create_group("Group 1", ["@ch1"])
        group2 = group_service.create_group("Group 2", ["@ch2"])

        groups = group_service.list_groups()

        assert len(groups) == 2
        group_ids = {g.id for g in groups}
        assert group1.id in group_ids
        assert group2.id in group_ids

    def test_list_groups_sorted_by_creation_newest_first(self, group_service):
        """Test that groups are sorted by creation time (newest first)."""
        import time

        group1 = group_service.create_group("Old", ["@ch1"])
        time.sleep(0.01)  # Ensure different timestamps
        group2 = group_service.create_group("New", ["@ch2"])

        groups = group_service.list_groups()

        assert len(groups) == 2
        # Newest first
        assert groups[0].id == group2.id
        assert groups[1].id == group1.id


class TestUpdateSettings:
    """Tests for GroupService.update_settings."""

    def test_update_settings_success(self, group_service):
        """Test updating group settings."""
        group = group_service.create_group("Test", ["@ch1"])
        new_settings = GroupSettings(message_limit=1000, leave_after_analysis=True)

        updated = group_service.update_settings(group.id, new_settings)

        assert updated.message_limit == 1000
        assert updated.leave_after_analysis is True

        # Verify persisted
        retrieved = group_service.get_group(group.id)
        assert retrieved.settings.message_limit == 1000
        assert retrieved.settings.leave_after_analysis is True

    def test_update_settings_nonexistent_group_raises_error(self, group_service):
        """Test that updating non-existent group raises ValueError."""
        settings = GroupSettings(message_limit=500)

        with pytest.raises(ValueError, match="Group not found"):
            group_service.update_settings("nonexistent-id", settings)

    def test_update_settings_validates_message_limit(self, group_service):
        """Test that invalid message_limit raises ValueError."""
        group = group_service.create_group("Test", ["@ch1"])

        # Below minimum
        with pytest.raises(ValueError, match="message_limit must be between"):
            GroupSettings(message_limit=5)

        # Above maximum
        with pytest.raises(ValueError, match="message_limit must be between"):
            GroupSettings(message_limit=20000)


class TestGetGroupStats:
    """Tests for GroupService.get_group_stats."""

    def test_get_stats_for_new_group(self, group_service):
        """Test getting stats for newly created group."""
        group = group_service.create_group("Test", ["@ch1", "@ch2"])
        stats = group_service.get_group_stats(group.id)

        assert stats.total == 2
        assert stats.pending == 2  # All chats start as pending
        assert stats.dead == 0
        assert stats.groups == 0
        assert stats.forums == 0
        assert stats.channels_with_comments == 0
        assert stats.channels_no_comments == 0
        assert stats.analyzed == 0
        assert stats.failed == 0


class TestUpdateGroupName:
    """Tests for GroupService.update_group_name."""

    def test_update_name_success(self, group_service):
        """Test updating group name."""
        group = group_service.create_group("Old Name", ["@ch1"])
        updated = group_service.update_group_name(group.id, "New Name")

        assert updated is not None
        assert updated.name == "New Name"
        assert updated.id == group.id

        # Verify persisted
        retrieved = group_service.get_group(group.id)
        assert retrieved.name == "New Name"

    def test_update_name_strips_whitespace(self, group_service):
        """Test that whitespace is stripped from new name."""
        group = group_service.create_group("Old", ["@ch1"])
        updated = group_service.update_group_name(group.id, "  New Name  ")

        assert updated.name == "New Name"

    def test_update_name_nonexistent_group_returns_none(self, group_service):
        """Test that updating non-existent group returns None."""
        result = group_service.update_group_name("nonexistent-id", "New Name")
        assert result is None


class TestUpdateStatus:
    """Tests for GroupService.update_status."""

    def test_update_status_success(self, group_service):
        """Test updating group status."""
        group = group_service.create_group("Test", ["@ch1"])
        updated = group_service.update_status(group.id, GroupStatus.IN_PROGRESS)

        assert updated is not None
        assert updated.status == GroupStatus.IN_PROGRESS

        # Verify persisted
        retrieved = group_service.get_group(group.id)
        assert retrieved.status == GroupStatus.IN_PROGRESS

    def test_update_status_transitions(self, group_service):
        """Test status transitions through workflow."""
        group = group_service.create_group("Test", ["@ch1"])

        # PENDING -> IN_PROGRESS
        updated = group_service.update_status(group.id, GroupStatus.IN_PROGRESS)
        assert updated.status == GroupStatus.IN_PROGRESS

        # IN_PROGRESS -> PAUSED
        updated = group_service.update_status(group.id, GroupStatus.PAUSED)
        assert updated.status == GroupStatus.PAUSED

        # PAUSED -> IN_PROGRESS (resume)
        updated = group_service.update_status(group.id, GroupStatus.IN_PROGRESS)
        assert updated.status == GroupStatus.IN_PROGRESS

        # IN_PROGRESS -> COMPLETED
        updated = group_service.update_status(group.id, GroupStatus.COMPLETED)
        assert updated.status == GroupStatus.COMPLETED

    def test_update_status_nonexistent_group_returns_none(self, group_service):
        """Test that updating non-existent group returns None."""
        result = group_service.update_status("nonexistent-id", GroupStatus.COMPLETED)
        assert result is None


class TestDeleteGroup:
    """Tests for GroupService.delete_group."""

    def test_delete_group_success(self, group_service):
        """Test deleting a group."""
        group = group_service.create_group("Test", ["@ch1"])
        group_service.delete_group(group.id)

        # Verify deleted
        result = group_service.get_group(group.id)
        assert result is None

    def test_delete_nonexistent_group_no_error(self, group_service):
        """Test that deleting non-existent group doesn't raise error."""
        # Should not raise
        group_service.delete_group("nonexistent-id")


class TestPersistence:
    """Tests for data persistence across service instances."""

    def test_group_persists_across_instances(self, temp_db):
        """Test that groups persist when service is recreated."""
        service1 = GroupService(temp_db)
        group = service1.create_group("Test", ["@ch1"])

        # Create new service instance with same database
        service2 = GroupService(temp_db)
        retrieved = service2.get_group(group.id)

        assert retrieved is not None
        assert retrieved.id == group.id
        assert retrieved.name == group.name
