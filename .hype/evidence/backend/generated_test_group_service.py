"""Generated tests for GroupService business logic."""

import pytest
import tempfile
from pathlib import Path

from chatfilter.storage.group_database import GroupDatabase
from chatfilter.service.group_service import GroupService
from chatfilter.models.group import GroupSettings


class TestGroupServiceBusinessLogic:
    """Tests for critical GroupService business logic."""

    @pytest.fixture
    def db(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        db = GroupDatabase(db_path)
        yield db
        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    def service(self, db):
        """Create GroupService instance."""
        return GroupService(db)

    def test_create_group_with_valid_inputs(self, service):
        """Test creating a group with valid inputs."""
        chat_refs = ["@telegram", "t.me/durov", "https://t.me/+hash123"]
        group = service.create_group("Test Group", chat_refs)
        
        assert group.name == "Test Group"
        assert group.chat_count == 3
        assert group.id.startswith("group-")

    def test_create_group_with_empty_name_raises_error(self, service):
        """Test that empty name raises ValueError."""
        with pytest.raises(ValueError, match="Group name cannot be empty"):
            service.create_group("", ["@telegram"])

    def test_create_group_with_whitespace_name_raises_error(self, service):
        """Test that whitespace-only name raises ValueError."""
        with pytest.raises(ValueError, match="Group name cannot be empty"):
            service.create_group("   ", ["@telegram"])

    def test_create_group_with_empty_chat_refs_raises_error(self, service):
        """Test that empty chat_refs raises ValueError."""
        with pytest.raises(ValueError, match="chat_refs cannot be empty"):
            service.create_group("Test Group", [])

    def test_create_group_parses_all_link_formats(self, service):
        """Test that all supported link formats are parsed correctly."""
        chat_refs = [
            "@username",                    # username
            "t.me/channel",                 # public link
            "https://t.me/+hash",           # invite link
            "-1001234567890",               # numeric ID
            "Text with t.me/embedded link", # embedded link
        ]
        group = service.create_group("Multi-format", chat_refs)
        
        assert group.chat_count == 5

    def test_get_group_returns_existing_group(self, service):
        """Test retrieving an existing group."""
        created = service.create_group("Get Test", ["@telegram"])
        retrieved = service.get_group(created.id)
        
        assert retrieved is not None
        assert retrieved.id == created.id
        assert retrieved.name == "Get Test"

    def test_get_group_returns_none_for_nonexistent(self, service):
        """Test that getting nonexistent group returns None."""
        result = service.get_group("group-nonexistent123")
        assert result is None

    def test_list_all_groups_returns_all(self, service):
        """Test listing all groups."""
        service.create_group("Group 1", ["@channel1"])
        service.create_group("Group 2", ["@channel2"])
        
        groups = service.list_all_groups()
        assert len(groups) == 2
        assert {g.name for g in groups} == {"Group 1", "Group 2"}

    def test_update_settings_persists_changes(self, service):
        """Test updating group settings."""
        group = service.create_group("Settings Test", ["@telegram"])
        
        new_settings = GroupSettings(
            message_limit=5000,
            leave_after_analysis=True
        )
        service.update_settings(group.id, new_settings)
        
        updated = service.get_group(group.id)
        assert updated.settings.message_limit == 5000
        assert updated.settings.leave_after_analysis is True

    def test_delete_group_removes_group(self, service):
        """Test deleting a group."""
        group = service.create_group("Delete Test", ["@telegram"])
        service.delete_group(group.id)
        
        result = service.get_group(group.id)
        assert result is None

    def test_get_group_stats_returns_correct_counts(self, service, db):
        """Test getting group statistics."""
        group = service.create_group("Stats Test", ["@chan1", "@chan2", "@chan3"])
        
        # Initially all chats should be pending
        stats = service.get_stats(group.id)
        assert stats.total == 3
        assert stats.pending == 3
        assert stats.completed == 0

    def test_unicode_in_group_name(self, service):
        """Test creating group with unicode characters."""
        group = service.create_group("Группа тест 测试 🚀", ["@telegram"])
        assert group.name == "Группа тест 测试 🚀"

    def test_unicode_in_chat_references(self, service):
        """Test parsing chat references with unicode."""
        chat_refs = ["@канал", "t.me/频道"]
        group = service.create_group("Unicode Refs", chat_refs)
        assert group.chat_count == 2
