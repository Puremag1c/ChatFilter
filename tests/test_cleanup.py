"""Tests for cleanup utilities (SIGKILL recovery)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from chatfilter.utils.cleanup import (
    CleanupStats,
    cleanup_old_session_files,
    cleanup_orphaned_db_journals,
    cleanup_orphaned_resources,
    cleanup_orphaned_temp_files,
)


@pytest.fixture
def temp_data_dir(tmp_path: Path) -> Path:
    """Create a temporary data directory."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def temp_sessions_dir(tmp_path: Path) -> Path:
    """Create a temporary sessions directory."""
    sessions_dir = tmp_path / "sessions"
    sessions_dir.mkdir()
    return sessions_dir


class TestCleanupOrphanedTempFiles:
    """Tests for cleanup_orphaned_temp_files()."""

    def test_removes_temp_files(self, temp_data_dir: Path) -> None:
        """Should remove all .*.tmp files."""
        # Create orphaned temp files
        (temp_data_dir / ".file1.tmp").write_text("orphaned")
        (temp_data_dir / ".file2.tmp").write_text("orphaned")
        (temp_data_dir / "normal.txt").write_text("keep this")

        # Clean up
        cleaned = cleanup_orphaned_temp_files(temp_data_dir)

        # Verify
        assert cleaned == 2
        assert not (temp_data_dir / ".file1.tmp").exists()
        assert not (temp_data_dir / ".file2.tmp").exists()
        assert (temp_data_dir / "normal.txt").exists()

    def test_removes_temp_files_recursively(self, temp_data_dir: Path) -> None:
        """Should remove temp files in subdirectories."""
        subdir = temp_data_dir / "subdir"
        subdir.mkdir()

        (temp_data_dir / ".root.tmp").write_text("orphaned")
        (subdir / ".nested.tmp").write_text("orphaned")

        cleaned = cleanup_orphaned_temp_files(temp_data_dir)

        assert cleaned == 2
        assert not (temp_data_dir / ".root.tmp").exists()
        assert not (subdir / ".nested.tmp").exists()

    def test_handles_no_temp_files(self, temp_data_dir: Path) -> None:
        """Should return 0 when no temp files exist."""
        (temp_data_dir / "normal.txt").write_text("keep this")

        cleaned = cleanup_orphaned_temp_files(temp_data_dir)

        assert cleaned == 0
        assert (temp_data_dir / "normal.txt").exists()

    def test_handles_nonexistent_directory(self) -> None:
        """Should return 0 for nonexistent directory."""
        cleaned = cleanup_orphaned_temp_files(Path("/nonexistent"))
        assert cleaned == 0

    def test_skips_temp_directories(self, temp_data_dir: Path) -> None:
        """Should only remove files, not directories."""
        temp_dir = temp_data_dir / ".tmpdir.tmp"
        temp_dir.mkdir()
        (temp_data_dir / ".file.tmp").write_text("orphaned")

        cleaned = cleanup_orphaned_temp_files(temp_data_dir)

        assert cleaned == 1
        assert temp_dir.exists()  # Directory not removed
        assert not (temp_data_dir / ".file.tmp").exists()


class TestCleanupOrphanedDbJournals:
    """Tests for cleanup_orphaned_db_journals()."""

    def test_removes_journal_files(self, temp_data_dir: Path) -> None:
        """Should remove SQLite journal files."""
        db_path = temp_data_dir / "tasks.db"

        # Create orphaned journal files
        (temp_data_dir / "tasks.db-journal").write_text("journal")
        (temp_data_dir / "tasks.db-wal").write_text("wal")
        (temp_data_dir / "tasks.db-shm").write_text("shm")

        cleaned = cleanup_orphaned_db_journals(db_path)

        assert cleaned == 3
        assert not (temp_data_dir / "tasks.db-journal").exists()
        assert not (temp_data_dir / "tasks.db-wal").exists()
        assert not (temp_data_dir / "tasks.db-shm").exists()

    def test_handles_missing_journal_files(self, temp_data_dir: Path) -> None:
        """Should return 0 when no journal files exist."""
        db_path = temp_data_dir / "tasks.db"
        cleaned = cleanup_orphaned_db_journals(db_path)
        assert cleaned == 0

    def test_removes_only_relevant_journals(self, temp_data_dir: Path) -> None:
        """Should only remove journal files for specified database."""
        db_path = temp_data_dir / "tasks.db"

        # Create journal files for tasks.db
        (temp_data_dir / "tasks.db-journal").write_text("journal")

        # Create journal files for other.db (should not be removed)
        (temp_data_dir / "other.db-journal").write_text("journal")

        cleaned = cleanup_orphaned_db_journals(db_path)

        assert cleaned == 1
        assert not (temp_data_dir / "tasks.db-journal").exists()
        assert (temp_data_dir / "other.db-journal").exists()

    def test_handles_nonexistent_db_path(self, tmp_path: Path) -> None:
        """Should return 0 when database directory doesn't exist."""
        db_path = tmp_path / "nonexistent" / "tasks.db"
        cleaned = cleanup_orphaned_db_journals(db_path)
        assert cleaned == 0

    def test_cleanup_with_real_sqlite_database(self, temp_data_dir: Path) -> None:
        """Integration test with real SQLite database."""
        db_path = temp_data_dir / "test.db"

        # Create database and write data (creates journal)
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.execute("INSERT INTO test VALUES (1)")
        conn.commit()
        conn.close()

        # Manually create orphaned journal files
        (temp_data_dir / "test.db-journal").write_text("orphaned")
        (temp_data_dir / "test.db-wal").write_text("orphaned")

        # Clean up journals
        cleaned = cleanup_orphaned_db_journals(db_path)

        assert cleaned == 2
        assert not (temp_data_dir / "test.db-journal").exists()
        assert not (temp_data_dir / "test.db-wal").exists()

        # Verify database still works
        conn = sqlite3.connect(db_path)
        cursor = conn.execute("SELECT * FROM test")
        assert cursor.fetchone() == (1,)
        conn.close()


class TestCleanupOrphanedResources:
    """Tests for cleanup_orphaned_resources() comprehensive cleanup."""

    def test_comprehensive_cleanup(self, temp_data_dir: Path, temp_sessions_dir: Path) -> None:
        """Should clean all resource types."""
        # Create orphaned resources
        (temp_data_dir / ".temp1.tmp").write_text("orphaned")
        (temp_data_dir / ".temp2.tmp").write_text("orphaned")
        (temp_data_dir / "tasks.db-journal").write_text("journal")
        (temp_data_dir / "tasks.db-wal").write_text("wal")

        # Run comprehensive cleanup
        stats = cleanup_orphaned_resources(
            data_dir=temp_data_dir,
            sessions_dir=temp_sessions_dir,
            session_cleanup_days=None,  # Skip session cleanup for this test
        )

        # Verify statistics
        assert stats.temp_files == 2
        assert stats.db_journals == 2
        assert stats.old_sessions == 0
        assert stats.errors == 0

        # Verify files removed
        assert not (temp_data_dir / ".temp1.tmp").exists()
        assert not (temp_data_dir / ".temp2.tmp").exists()
        assert not (temp_data_dir / "tasks.db-journal").exists()
        assert not (temp_data_dir / "tasks.db-wal").exists()

    def test_handles_no_orphaned_resources(
        self, temp_data_dir: Path, temp_sessions_dir: Path
    ) -> None:
        """Should handle case with no orphaned resources."""
        stats = cleanup_orphaned_resources(
            data_dir=temp_data_dir,
            sessions_dir=temp_sessions_dir,
        )

        assert stats.temp_files == 0
        assert stats.db_journals == 0
        assert stats.old_sessions == 0
        assert stats.errors == 0

    def test_handles_partial_failures_gracefully(
        self, temp_data_dir: Path, temp_sessions_dir: Path
    ) -> None:
        """Should continue cleanup even if some operations fail."""
        # Create temp files that can be cleaned
        (temp_data_dir / ".temp.tmp").write_text("orphaned")

        # Use invalid sessions directory to cause potential error
        invalid_sessions = temp_data_dir / "nonexistent_sessions"

        # Should not raise exception
        stats = cleanup_orphaned_resources(
            data_dir=temp_data_dir,
            sessions_dir=invalid_sessions,
            session_cleanup_days=30.0,
        )

        # Should still clean temp files
        assert stats.temp_files == 1
        assert not (temp_data_dir / ".temp.tmp").exists()

    def test_custom_db_name(self, temp_data_dir: Path, temp_sessions_dir: Path) -> None:
        """Should support custom database names."""
        # Create orphaned journal for custom database
        (temp_data_dir / "custom.db-journal").write_text("journal")

        stats = cleanup_orphaned_resources(
            data_dir=temp_data_dir,
            sessions_dir=temp_sessions_dir,
            db_name="custom.db",
        )

        assert stats.db_journals == 1
        assert not (temp_data_dir / "custom.db-journal").exists()

    def test_cleanup_stats_dataclass(self) -> None:
        """Should create CleanupStats with correct defaults."""
        stats = CleanupStats()

        assert stats.temp_files == 0
        assert stats.db_journals == 0
        assert stats.old_sessions == 0
        assert stats.errors == 0

        # Test with custom values
        stats = CleanupStats(temp_files=5, db_journals=2, errors=1)
        assert stats.temp_files == 5
        assert stats.db_journals == 2
        assert stats.old_sessions == 0
        assert stats.errors == 1


class TestCleanupOldSessionFiles:
    """Tests for cleanup_old_session_files() wrapper."""

    def test_skips_cleanup_when_disabled(self, temp_sessions_dir: Path) -> None:
        """Should return 0 when cleanup_days is None."""
        cleaned = cleanup_old_session_files(temp_sessions_dir, cleanup_days=None)
        assert cleaned == 0

    def test_delegates_to_storage_module(self, temp_sessions_dir: Path) -> None:
        """Should delegate to storage.file.cleanup_old_session_files()."""
        # This test verifies the wrapper correctly calls the actual implementation
        # The detailed session cleanup logic is tested in test_file_storage.py

        # Just verify the function is callable and returns an integer
        cleaned = cleanup_old_session_files(temp_sessions_dir, cleanup_days=30.0)
        assert isinstance(cleaned, int)
        assert cleaned >= 0
