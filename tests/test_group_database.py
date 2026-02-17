"""Tests for group database persistence."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from chatfilter.models.group import GroupSettings
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_groups.db"
        yield GroupDatabase(db_path)


@pytest.fixture
def sample_group_data():
    """Create sample group data for testing."""
    return {
        "id": "group_123",
        "name": "Test Group",
        "settings": {
            "detect_chat_type": True,
            "detect_subscribers": True,
            "detect_activity": True,
            "detect_unique_authors": True,
            "detect_moderation": True,
            "detect_captcha": True,
            "time_window": 24,
        },
        "status": "pending",
    }


@pytest.fixture
def sample_chat_data():
    """Create sample chat data for testing."""
    return {
        "group_id": "group_123",
        "chat_ref": "@test_channel",
        "chat_type": "channel",
        "status": "pending",
    }


@pytest.fixture
def sample_result_data():
    """Create sample result data for testing."""
    return {
        "group_id": "group_123",
        "chat_ref": "@test_channel",
        "metrics_data": {
            "message_count": 1000,
            "unique_authors": 50,
            "history_hours": 720.0,
        },
    }


def test_database_initialization(temp_db):
    """Test that database initializes with correct schema."""
    with temp_db._connection() as conn:
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]

    assert "chat_groups" in tables
    assert "group_chats" in tables
    assert "group_results" in tables


def test_save_and_load_group(temp_db, sample_group_data):
    """Test saving and loading a group."""
    # Save group
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Load group
    loaded = temp_db.load_group(sample_group_data["id"])

    assert loaded is not None
    assert loaded["id"] == sample_group_data["id"]
    assert loaded["name"] == sample_group_data["name"]
    assert loaded["settings"] == sample_group_data["settings"]
    assert loaded["status"] == sample_group_data["status"]
    assert loaded["created_at"] is not None
    assert loaded["updated_at"] is not None


def test_load_nonexistent_group(temp_db):
    """Test loading a group that doesn't exist."""
    result = temp_db.load_group("nonexistent_id")
    assert result is None


def test_update_group(temp_db, sample_group_data):
    """Test updating an existing group."""
    # Save initial group
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Update group
    new_settings = {
        "detect_chat_type": False,
        "detect_subscribers": True,
        "detect_activity": False,
        "detect_unique_authors": True,
        "detect_moderation": False,
        "detect_captcha": True,
        "time_window": 48,
    }
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name="Updated Name",
        settings=new_settings,
        status="in_progress",
    )

    # Verify update
    loaded = temp_db.load_group(sample_group_data["id"])
    assert loaded["name"] == "Updated Name"
    assert loaded["settings"] == new_settings
    assert loaded["status"] == "in_progress"


def test_load_all_groups(temp_db):
    """Test loading all groups."""
    # Save multiple groups
    for i in range(3):
        temp_db.save_group(
            group_id=f"group_{i}",
            name=f"Group {i}",
            settings={
                "detect_chat_type": True,
                "detect_subscribers": True,
                "detect_activity": True,
                "detect_unique_authors": True,
                "detect_moderation": True,
                "detect_captcha": True,
                "time_window": 24,
            },
            status="pending",
        )

    # Load all
    groups = temp_db.load_all_groups()

    assert len(groups) == 3
    assert all(g["id"] in ["group_0", "group_1", "group_2"] for g in groups)


def test_save_chat(temp_db, sample_group_data, sample_chat_data):
    """Test saving a chat within a group."""
    # First create the group
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Save chat
    chat_id = temp_db.save_chat(
        group_id=sample_chat_data["group_id"],
        chat_ref=sample_chat_data["chat_ref"],
        chat_type=sample_chat_data["chat_type"],
        status=sample_chat_data["status"],
    )

    assert chat_id > 0


def test_update_chat_status(temp_db, sample_group_data, sample_chat_data):
    """Test updating chat status."""
    # Setup
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    chat_id = temp_db.save_chat(
        group_id=sample_chat_data["group_id"],
        chat_ref=sample_chat_data["chat_ref"],
        chat_type=sample_chat_data["chat_type"],
        status="pending",
    )

    # Update status
    temp_db.update_chat_status(
        chat_id=chat_id,
        status="done",
        assigned_account="account_1",
    )

    # Verify update
    with temp_db._connection() as conn:
        cursor = conn.execute("SELECT * FROM group_chats WHERE id = ?", (chat_id,))
        row = cursor.fetchone()

    assert row["status"] == "done"
    assert row["assigned_account"] == "account_1"


def test_update_chat_status_with_error(temp_db, sample_group_data, sample_chat_data):
    """Test updating chat status with error message."""
    # Setup
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    chat_id = temp_db.save_chat(
        group_id=sample_chat_data["group_id"],
        chat_ref=sample_chat_data["chat_ref"],
        chat_type=sample_chat_data["chat_type"],
        status="pending",
    )

    # Update with error
    temp_db.update_chat_status(
        chat_id=chat_id,
        status="failed",
        error="Connection timeout",
    )

    # Verify
    with temp_db._connection() as conn:
        cursor = conn.execute("SELECT * FROM group_chats WHERE id = ?", (chat_id,))
        row = cursor.fetchone()

    assert row["status"] == "failed"
    assert row["error"] == "Connection timeout"


def test_save_and_load_result(temp_db, sample_group_data, sample_result_data):
    """Test saving and loading analysis results."""
    # Setup
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Save result
    temp_db.save_result(
        group_id=sample_result_data["group_id"],
        chat_ref=sample_result_data["chat_ref"],
        metrics_data=sample_result_data["metrics_data"],
    )

    # Load results
    results = temp_db.load_results(sample_result_data["group_id"])

    assert len(results) == 1
    assert results[0]["group_id"] == sample_result_data["group_id"]
    assert results[0]["chat_ref"] == sample_result_data["chat_ref"]
    assert results[0]["metrics_data"] == sample_result_data["metrics_data"]
    assert results[0]["analyzed_at"] is not None


def test_load_results_with_limit(temp_db, sample_group_data):
    """Test loading results with limit."""
    # Setup
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Save multiple results
    for i in range(5):
        temp_db.save_result(
            group_id=sample_group_data["id"],
            chat_ref=f"@chat_{i}",
            metrics_data={"message_count": i * 100},
        )

    # Load with limit
    results = temp_db.load_results(sample_group_data["id"], limit=3)

    assert len(results) == 3


def test_get_group_stats_empty(temp_db, sample_group_data):
    """Test getting stats for a group with no chats."""
    # Setup
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Get stats
    stats = temp_db.get_group_stats(sample_group_data["id"])

    assert stats["total"] == 0
    assert stats["by_type"] == {}
    assert stats["by_status"] == {}


def test_get_group_stats(temp_db, sample_group_data):
    """Test getting stats for a group with chats."""
    # Setup
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Add chats with different types and statuses
    chats = [
        ("@channel1", "channel", "done"),
        ("@channel2", "channel", "done"),
        ("@group1", "group", "pending"),
        ("@forum1", "forum", "failed"),
        ("@channel3", "channel", "pending"),
    ]

    for chat_ref, chat_type, status in chats:
        temp_db.save_chat(
            group_id=sample_group_data["id"],
            chat_ref=chat_ref,
            chat_type=chat_type,
            status=status,
        )

    # Get stats
    stats = temp_db.get_group_stats(sample_group_data["id"])

    assert stats["total"] == 5
    assert stats["by_type"]["channel"] == 3
    assert stats["by_type"]["group"] == 1
    assert stats["by_type"]["forum"] == 1
    assert stats["by_status"]["done"] == 2
    assert stats["by_status"]["pending"] == 2
    assert stats["by_status"]["failed"] == 1


def test_cascade_delete(temp_db, sample_group_data):
    """Test that deleting a group cascades to chats and results."""
    # Setup group, chat, and result
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    temp_db.save_chat(
        group_id=sample_group_data["id"],
        chat_ref="@test",
        chat_type="channel",
        status="done",
    )

    temp_db.save_result(
        group_id=sample_group_data["id"],
        chat_ref="@test",
        metrics_data={"message_count": 100},
    )

    # Delete group
    with temp_db._connection() as conn:
        conn.execute("DELETE FROM chat_groups WHERE id = ?", (sample_group_data["id"],))

    # Verify cascading delete
    with temp_db._connection() as conn:
        # Check chats deleted
        cursor = conn.execute(
            "SELECT COUNT(*) as count FROM group_chats WHERE group_id = ?",
            (sample_group_data["id"],),
        )
        assert cursor.fetchone()["count"] == 0

        # Check results deleted
        cursor = conn.execute(
            "SELECT COUNT(*) as count FROM group_results WHERE group_id = ?",
            (sample_group_data["id"],),
        )
        assert cursor.fetchone()["count"] == 0


def test_foreign_key_constraint(temp_db):
    """Test that foreign key constraint is enforced."""
    # Try to save a chat without creating the group first
    # This should fail because we enable PRAGMA foreign_keys = ON
    with pytest.raises(Exception):  # sqlite3.IntegrityError
        temp_db.save_chat(
            group_id="nonexistent_group",
            chat_ref="@test",
            chat_type="channel",
            status="pending",
        )


def test_unique_constraint_on_group_results(temp_db, sample_group_data):
    """Test that UNIQUE constraint on (group_id, chat_ref) prevents duplicates."""
    # Setup group
    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
    )

    # Save first result
    temp_db.save_result(
        group_id=sample_group_data["id"],
        chat_ref="@test_channel",
        metrics_data={"message_count": 100},
    )

    # Try to save duplicate (same group_id + chat_ref) - should fail
    with pytest.raises(Exception):  # sqlite3.IntegrityError
        temp_db.save_result(
            group_id=sample_group_data["id"],
            chat_ref="@test_channel",
            metrics_data={"message_count": 200},
        )


def test_migration_removes_duplicates():
    """Test that migration to v1 removes duplicate rows and keeps newest."""
    import sqlite3

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_migration.db"

        # Create old schema (without unique constraint) directly
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("""
            CREATE TABLE chat_groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                settings TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE group_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id TEXT NOT NULL,
                chat_ref TEXT NOT NULL,
                metrics_data TEXT NOT NULL,
                analyzed_at TIMESTAMP NOT NULL,
                FOREIGN KEY (group_id) REFERENCES chat_groups (id)
                    ON DELETE CASCADE
            )
        """)

        # Insert test group
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("group_123", "Test", '{}', "pending", now, now),
        )

        # Insert duplicates (older first, then newer)
        old_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC).isoformat()
        new_time = datetime(2024, 1, 2, 12, 0, 0, tzinfo=UTC).isoformat()

        conn.execute(
            "INSERT INTO group_results (group_id, chat_ref, metrics_data, analyzed_at) VALUES (?, ?, ?, ?)",
            ("group_123", "@chat1", '{"count": 100}', old_time),
        )
        conn.execute(
            "INSERT INTO group_results (group_id, chat_ref, metrics_data, analyzed_at) VALUES (?, ?, ?, ?)",
            ("group_123", "@chat1", '{"count": 200}', new_time),
        )
        conn.execute(
            "INSERT INTO group_results (group_id, chat_ref, metrics_data, analyzed_at) VALUES (?, ?, ?, ?)",
            ("group_123", "@chat2", '{"count": 300}', new_time),
        )
        conn.commit()

        # Verify we have duplicates
        cursor = conn.execute("SELECT COUNT(*) as count FROM group_results WHERE group_id = 'group_123' AND chat_ref = '@chat1'")
        assert cursor.fetchone()[0] == 2
        conn.close()

        # Now initialize GroupDatabase - this should run migration
        db = GroupDatabase(db_path)

        # Verify migration ran
        with db._connection() as conn:
            # Check schema version updated
            cursor = conn.execute("PRAGMA user_version")
            assert cursor.fetchone()[0] == 1

            # Check unique index exists
            cursor = conn.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name='idx_group_results_unique_group_chat'
            """)
            assert cursor.fetchone() is not None

            # Check duplicates removed (only 1 row for @chat1 remains)
            cursor = conn.execute("SELECT COUNT(*) as count FROM group_results WHERE group_id = 'group_123' AND chat_ref = '@chat1'")
            assert cursor.fetchone()[0] == 1

            # Check we kept the NEWEST row (analyzed_at = new_time, count = 200)
            cursor = conn.execute("SELECT metrics_data FROM group_results WHERE group_id = 'group_123' AND chat_ref = '@chat1'")
            row = cursor.fetchone()
            import json
            assert json.loads(row[0])["count"] == 200

            # Check other rows untouched
            cursor = conn.execute("SELECT COUNT(*) as count FROM group_results")
            assert cursor.fetchone()[0] == 2


def test_timestamps(temp_db, sample_group_data):
    """Test that timestamps are properly stored and retrieved."""
    now = datetime.now(UTC)

    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=sample_group_data["settings"],
        status=sample_group_data["status"],
        created_at=now,
        updated_at=now,
    )

    loaded = temp_db.load_group(sample_group_data["id"])

    assert loaded["created_at"] is not None
    assert loaded["updated_at"] is not None
    # Should be within 1 second (accounting for microsecond precision loss)
    assert abs((loaded["created_at"] - now).total_seconds()) < 1
    assert abs((loaded["updated_at"] - now).total_seconds()) < 1


def test_json_serialization(temp_db, sample_group_data):
    """Test that complex JSON structures are properly serialized."""
    complex_settings = {
        "detect_chat_type": True,
        "detect_subscribers": False,
        "detect_activity": True,
        "detect_unique_authors": False,
        "detect_moderation": True,
        "detect_captcha": False,
        "time_window": 6,
        "filters": {
            "min_members": 100,
            "max_members": 10000,
            "keywords": ["test", "demo"],
        },
        "nested": {"deep": {"value": 42}},
    }

    temp_db.save_group(
        group_id=sample_group_data["id"],
        name=sample_group_data["name"],
        settings=complex_settings,
        status=sample_group_data["status"],
    )

    loaded = temp_db.load_group(sample_group_data["id"])

    assert loaded["settings"] == complex_settings
    assert loaded["settings"]["filters"]["keywords"] == ["test", "demo"]
    assert loaded["settings"]["nested"]["deep"]["value"] == 42


class TestGroupSettings:
    """Test GroupSettings model validation and behavior."""

    def test_default_settings(self):
        """Test that default settings have all metrics enabled."""
        settings = GroupSettings()
        assert settings.detect_chat_type is True
        assert settings.detect_subscribers is True
        assert settings.detect_activity is True
        assert settings.detect_unique_authors is True
        assert settings.detect_moderation is True
        assert settings.detect_captcha is True
        assert settings.time_window == 24

    def test_needs_join_all_disabled(self):
        """Test needs_join returns False when all join-required metrics are disabled."""
        settings = GroupSettings(
            detect_activity=False,
            detect_unique_authors=False,
            detect_captcha=False,
        )
        assert settings.needs_join() is False

    def test_needs_join_activity_enabled(self):
        """Test needs_join returns True when detect_activity is enabled."""
        settings = GroupSettings(
            detect_activity=True,
            detect_unique_authors=False,
            detect_captcha=False,
        )
        assert settings.needs_join() is True

    def test_needs_join_unique_authors_enabled(self):
        """Test needs_join returns True when detect_unique_authors is enabled."""
        settings = GroupSettings(
            detect_activity=False,
            detect_unique_authors=True,
            detect_captcha=False,
        )
        assert settings.needs_join() is True

    def test_needs_join_captcha_enabled(self):
        """Test needs_join returns True when detect_captcha is enabled."""
        settings = GroupSettings(
            detect_activity=False,
            detect_unique_authors=False,
            detect_captcha=True,
        )
        assert settings.needs_join() is True

    def test_needs_join_multiple_enabled(self):
        """Test needs_join returns True when multiple join-required metrics are enabled."""
        settings = GroupSettings(
            detect_activity=True,
            detect_unique_authors=True,
            detect_captcha=True,
        )
        assert settings.needs_join() is True

    def test_time_window_valid_values(self):
        """Test that valid time_window values are accepted."""
        for value in [1, 6, 24, 48]:
            settings = GroupSettings(time_window=value)
            assert settings.time_window == value

    def test_time_window_invalid_value(self):
        """Test that invalid time_window values are rejected."""
        with pytest.raises(ValidationError, match="time_window must be one of"):
            GroupSettings(time_window=12)

    def test_time_window_negative(self):
        """Test that negative time_window values are rejected."""
        with pytest.raises(ValidationError, match="time_window must be one of"):
            GroupSettings(time_window=-1)

    def test_fake_method_defaults(self):
        """Test that fake() method creates settings with default values."""
        settings = GroupSettings.fake()
        assert settings.detect_chat_type is True
        assert settings.detect_subscribers is True
        assert settings.detect_activity is True
        assert settings.detect_unique_authors is True
        assert settings.detect_moderation is True
        assert settings.detect_captcha is True
        assert settings.time_window == 24

    def test_fake_method_custom_values(self):
        """Test that fake() method accepts custom values."""
        settings = GroupSettings.fake(
            detect_chat_type=False,
            detect_subscribers=False,
            detect_activity=False,
            detect_unique_authors=False,
            detect_moderation=False,
            detect_captcha=False,
            time_window=6,
        )
        assert settings.detect_chat_type is False
        assert settings.detect_subscribers is False
        assert settings.detect_activity is False
        assert settings.detect_unique_authors is False
        assert settings.detect_moderation is False
        assert settings.detect_captcha is False
        assert settings.time_window == 6

    def test_model_is_frozen(self):
        """Test that GroupSettings is frozen (immutable)."""
        settings = GroupSettings()
        with pytest.raises(ValidationError):
            settings.detect_chat_type = False

    def test_extra_fields_forbidden(self):
        """Test that extra fields are forbidden."""
        with pytest.raises(ValidationError):
            GroupSettings(unknown_field="value")

    def test_from_dict_old_format_migration(self):
        """Test migration from old settings format to new format."""
        # Old format with message_limit and leave_after_analysis
        old_data = {
            "message_limit": 100,
            "leave_after_analysis": True,
        }

        settings = GroupSettings.from_dict(old_data)

        # Should get default values for all new fields
        assert settings.detect_chat_type is True
        assert settings.detect_subscribers is True
        assert settings.detect_activity is True
        assert settings.detect_unique_authors is True
        assert settings.detect_moderation is True
        assert settings.detect_captcha is True
        assert settings.time_window == 24

    def test_from_dict_new_format(self):
        """Test that from_dict works with new format."""
        new_data = {
            "detect_chat_type": False,
            "detect_subscribers": True,
            "detect_activity": False,
            "detect_unique_authors": True,
            "detect_moderation": False,
            "detect_captcha": True,
            "time_window": 48,
        }

        settings = GroupSettings.from_dict(new_data)

        assert settings.detect_chat_type is False
        assert settings.detect_subscribers is True
        assert settings.detect_activity is False
        assert settings.detect_unique_authors is True
        assert settings.detect_moderation is False
        assert settings.detect_captcha is True
        assert settings.time_window == 48

    def test_from_dict_mixed_format(self):
        """Test from_dict with mix of old and new fields."""
        # Mix of old (ignored) and new (used) fields
        mixed_data = {
            "message_limit": 100,  # Old - ignored
            "leave_after_analysis": True,  # Old - ignored
            "detect_chat_type": False,  # New - used
            "time_window": 6,  # New - used
        }

        settings = GroupSettings.from_dict(mixed_data)

        # Should use provided new fields
        assert settings.detect_chat_type is False
        assert settings.time_window == 6

        # Should use defaults for unprovided new fields
        assert settings.detect_subscribers is True
        assert settings.detect_activity is True

    def test_from_dict_empty_data(self):
        """Test from_dict with empty dict uses all defaults."""
        settings = GroupSettings.from_dict({})

        assert settings.detect_chat_type is True
        assert settings.detect_subscribers is True
        assert settings.detect_activity is True
        assert settings.detect_unique_authors is True
        assert settings.detect_moderation is True
        assert settings.detect_captcha is True
        assert settings.time_window == 24
