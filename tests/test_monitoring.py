"""Tests for monitoring database and service."""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from chatfilter.models.monitoring import (
    ChatMonitorState,
    GrowthMetrics,
    SyncSnapshot,
)
from chatfilter.storage.database import MonitoringDatabase

# === Model Tests ===


class TestChatMonitorState:
    """Tests for ChatMonitorState model."""

    def test_create_monitor_state(self):
        """Test creating a basic monitor state."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        assert state.session_id == "test-session"
        assert state.chat_id == 123456
        assert state.is_enabled is True
        assert state.message_count == 0
        assert state.unique_author_ids == []
        assert state.unique_authors == 0

    def test_computed_unique_authors(self):
        """Test that unique_authors is computed from unique_author_ids."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
            unique_author_ids=[1, 2, 3, 4, 5],
        )
        assert state.unique_authors == 5

    def test_computed_history_hours(self):
        """Test that history_hours is computed from timestamps."""
        now = datetime.now(UTC)
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
            first_message_at=now - timedelta(hours=24),
            last_message_at=now,
        )
        assert abs(state.history_hours - 24.0) < 0.01

    def test_computed_messages_per_hour(self):
        """Test that messages_per_hour is computed correctly."""
        now = datetime.now(UTC)
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
            message_count=240,
            first_message_at=now - timedelta(hours=24),
            last_message_at=now,
        )
        assert abs(state.messages_per_hour - 10.0) < 0.01

    def test_messages_per_hour_zero_history(self):
        """Test messages_per_hour with zero history returns 0."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
            message_count=100,
        )
        assert state.messages_per_hour == 0.0


class TestSyncSnapshot:
    """Tests for SyncSnapshot model."""

    def test_create_snapshot(self):
        """Test creating a sync snapshot."""
        now = datetime.now(UTC)
        snapshot = SyncSnapshot(
            chat_id=123456,
            sync_at=now,
            message_count=500,
            unique_authors=25,
            new_messages=50,
            new_authors=5,
            sync_duration_seconds=2.5,
        )
        assert snapshot.chat_id == 123456
        assert snapshot.message_count == 500
        assert snapshot.new_messages == 50
        assert snapshot.new_authors == 5
        assert snapshot.sync_duration_seconds == 2.5


class TestGrowthMetrics:
    """Tests for GrowthMetrics model."""

    def test_create_growth_metrics(self):
        """Test creating growth metrics."""
        now = datetime.now(UTC)
        metrics = GrowthMetrics(
            chat_id=123456,
            period_start=now - timedelta(hours=24),
            period_end=now,
            period_hours=24.0,
            total_new_messages=240,
            total_new_authors=10,
            messages_per_hour=10.0,
            author_growth_rate=0.42,
        )
        assert metrics.messages_per_hour == 10.0
        assert metrics.author_growth_rate == 0.42


# === Database Tests ===


@pytest.fixture
def temp_monitoring_db():
    """Create a temporary monitoring database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_monitoring.db"
        yield MonitoringDatabase(db_path)


class TestMonitoringDatabase:
    """Tests for MonitoringDatabase."""

    def test_database_initialization(self, temp_monitoring_db):
        """Test that database initializes with correct schema."""
        with temp_monitoring_db._connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]

        assert "chat_monitors" in tables
        assert "sync_snapshots" in tables

    def test_save_and_load_monitor_state(self, temp_monitoring_db):
        """Test saving and loading a monitor state."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
            message_count=100,
            unique_author_ids=[1, 2, 3],
            is_enabled=True,
        )

        temp_monitoring_db.save_monitor_state(state)
        loaded = temp_monitoring_db.load_monitor_state("test-session", 123456)

        assert loaded is not None
        assert loaded.session_id == "test-session"
        assert loaded.chat_id == 123456
        assert loaded.message_count == 100
        assert loaded.unique_author_ids == [1, 2, 3]
        assert loaded.unique_authors == 3

    def test_load_nonexistent_monitor(self, temp_monitoring_db):
        """Test loading a monitor that doesn't exist."""
        result = temp_monitoring_db.load_monitor_state("nonexistent", 999)
        assert result is None

    def test_update_monitor_state(self, temp_monitoring_db):
        """Test updating an existing monitor state."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
            message_count=100,
        )
        temp_monitoring_db.save_monitor_state(state)

        # Update state
        state.message_count = 200
        state.unique_author_ids = [1, 2, 3, 4, 5]
        temp_monitoring_db.save_monitor_state(state)

        loaded = temp_monitoring_db.load_monitor_state("test-session", 123456)
        assert loaded is not None
        assert loaded.message_count == 200
        assert loaded.unique_authors == 5

    def test_load_all_monitors(self, temp_monitoring_db):
        """Test loading all monitors for a session."""
        for i in range(3):
            state = ChatMonitorState(
                session_id="test-session",
                chat_id=100 + i,
            )
            temp_monitoring_db.save_monitor_state(state)

        # Add a monitor for a different session
        other_state = ChatMonitorState(
            session_id="other-session",
            chat_id=999,
        )
        temp_monitoring_db.save_monitor_state(other_state)

        monitors = temp_monitoring_db.load_all_monitors("test-session")
        assert len(monitors) == 3

    def test_load_enabled_monitors(self, temp_monitoring_db):
        """Test loading only enabled monitors."""
        enabled_state = ChatMonitorState(
            session_id="test-session",
            chat_id=100,
            is_enabled=True,
        )
        disabled_state = ChatMonitorState(
            session_id="test-session",
            chat_id=200,
            is_enabled=False,
        )
        temp_monitoring_db.save_monitor_state(enabled_state)
        temp_monitoring_db.save_monitor_state(disabled_state)

        enabled = temp_monitoring_db.load_enabled_monitors("test-session")
        assert len(enabled) == 1
        assert enabled[0].chat_id == 100

    def test_delete_monitor_state(self, temp_monitoring_db):
        """Test deleting a monitor state."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        temp_monitoring_db.save_monitor_state(state)

        result = temp_monitoring_db.delete_monitor_state("test-session", 123456)
        assert result is True

        loaded = temp_monitoring_db.load_monitor_state("test-session", 123456)
        assert loaded is None

    def test_delete_nonexistent_monitor(self, temp_monitoring_db):
        """Test deleting a monitor that doesn't exist."""
        result = temp_monitoring_db.delete_monitor_state("nonexistent", 999)
        assert result is False

    def test_save_and_load_snapshots(self, temp_monitoring_db):
        """Test saving and loading sync snapshots."""
        # Create monitor first (required by foreign key)
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        temp_monitoring_db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(3):
            snapshot = SyncSnapshot(
                chat_id=123456,
                sync_at=now - timedelta(hours=i),
                message_count=100 * (i + 1),
                unique_authors=10 * (i + 1),
                new_messages=10,
                new_authors=2,
            )
            temp_monitoring_db.save_snapshot("test-session", snapshot)

        snapshots = temp_monitoring_db.load_snapshots("test-session", 123456)
        assert len(snapshots) == 3
        # Should be newest first
        assert snapshots[0].message_count == 100  # Most recent

    def test_load_snapshots_with_since(self, temp_monitoring_db):
        """Test loading snapshots since a specific time."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        temp_monitoring_db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(5):
            snapshot = SyncSnapshot(
                chat_id=123456,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            temp_monitoring_db.save_snapshot("test-session", snapshot)

        # Load only snapshots from last 2 hours
        since = now - timedelta(hours=2)
        snapshots = temp_monitoring_db.load_snapshots("test-session", 123456, since=since)
        assert len(snapshots) == 2

    def test_count_snapshots(self, temp_monitoring_db):
        """Test counting snapshots."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        temp_monitoring_db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(5):
            snapshot = SyncSnapshot(
                chat_id=123456,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            temp_monitoring_db.save_snapshot("test-session", snapshot)

        count = temp_monitoring_db.count_snapshots("test-session", 123456)
        assert count == 5

    def test_delete_old_snapshots(self, temp_monitoring_db):
        """Test deleting old snapshots while keeping recent ones."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        temp_monitoring_db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(10):
            snapshot = SyncSnapshot(
                chat_id=123456,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            temp_monitoring_db.save_snapshot("test-session", snapshot)

        deleted = temp_monitoring_db.delete_old_snapshots("test-session", 123456, keep_count=5)
        assert deleted == 5

        remaining = temp_monitoring_db.count_snapshots("test-session", 123456)
        assert remaining == 5

    def test_cascade_delete_snapshots(self, temp_monitoring_db):
        """Test that deleting a monitor cascades to snapshots."""
        state = ChatMonitorState(
            session_id="test-session",
            chat_id=123456,
        )
        temp_monitoring_db.save_monitor_state(state)

        now = datetime.now(UTC)
        snapshot = SyncSnapshot(
            chat_id=123456,
            sync_at=now,
            message_count=100,
            unique_authors=10,
        )
        temp_monitoring_db.save_snapshot("test-session", snapshot)

        # Delete monitor
        temp_monitoring_db.delete_monitor_state("test-session", 123456)

        # Snapshots should be gone
        snapshots = temp_monitoring_db.load_snapshots("test-session", 123456)
        assert len(snapshots) == 0
