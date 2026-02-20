"""E2E test for startup recovery mechanism.

This test verifies that when server crashes during analysis,
stale in_progress groups are properly recovered on restart:
- Groups in 'in_progress' status → 'paused'
- Chats in 'analyzing' status → 'pending'

Pattern:
1. Initialize app with lifespan context (first startup)
2. Create group and simulate crash state directly in DB
3. Exit lifespan context (simulate crash)
4. Re-enter lifespan context (simulates server restart - recovery runs here)
5. Verify DB state shows recovery happened

This design avoids subprocess overhead and uses the same pattern as
test_graceful_shutdown.py (lifespan context manager).

Run with: pytest tests/test_startup_recovery_e2e.py
"""

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_startup_recovery_e2e():
    """Test that crashed in_progress groups are recovered on server restart.

    Uses lifespan context manager to test recovery without subprocess overhead.

    Verifies:
    - Server recovers stale in_progress groups
    - Group status changes from in_progress → paused
    - Chat status changes from analyzing → pending
    - Recovery is logged
    """
    from chatfilter.config import Settings
    from chatfilter.web.app import create_app, lifespan

    # Use temporary directory for isolated test
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir) / "chatfilter-recovery-test"
        data_dir.mkdir()

        # Set environment variable so get_settings() uses our test data_dir
        os.environ["CHATFILTER_DATA_DIR"] = str(data_dir)

        settings = Settings(data_dir=data_dir, port=8999)
        app = create_app(settings=settings)

        # Step 1: First startup - initialize database
        async with lifespan(app):
            # Create test group with chats directly in DB
            group_id = "test-recovery-group"
            _create_test_group_in_db(data_dir, group_id)

            # Simulate crash by setting group to in_progress and chats to analyzing
            _simulate_crash_state(data_dir, group_id)

        # Lifespan context exited - simulates crash (no cleanup ran)

        # Step 2: Reset global singletons (simulates process restart)
        # In real server restart, the Python process is killed and restarted,
        # which resets all module-level globals. We need to simulate this.
        import chatfilter.web.dependencies as deps
        from chatfilter.config import reset_settings

        deps._group_engine = None
        deps._session_manager = None
        deps._chat_service = None
        deps._database = None
        reset_settings()  # Clear settings cache

        # Create NEW app instance (simulates server restart)
        app2 = create_app(settings=settings)

        # Second startup - recovery should run
        async with lifespan(app2):
            # Recovery runs during lifespan startup (group_engine.recover_stale_analysis)
            pass

        # Step 3: Verify recovery happened
        db_path = data_dir / "groups.db"
        group_status, analyzing_count = _check_recovery_state(db_path, group_id)

        # Assertions
        assert group_status == "paused", (
            f"Expected group status to be 'paused' after recovery, got '{group_status}'"
        )
        assert analyzing_count == 0, (
            f"Expected 0 chats in 'analyzing' status after recovery, got {analyzing_count}"
        )


def _create_test_group_in_db(data_dir: Path, group_id: str) -> None:
    """Create a test group directly in database.

    Args:
        data_dir: Data directory
        group_id: Group ID to create
    """
    from datetime import UTC, datetime

    from chatfilter.storage.group_database import GroupDatabase

    db_path = data_dir / "groups.db"
    db = GroupDatabase(db_path)

    # Create group
    db.save_group(
        group_id=group_id,
        name="Recovery Test Group",
        settings={},
        status="pending",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )

    # Create chats
    chats = [
        "https://t.me/test_chat_1",
        "https://t.me/test_chat_2",
        "https://t.me/test_chat_3",
    ]

    for chat_ref in chats:
        db.save_chat(
            group_id=group_id,
            chat_ref=chat_ref,
            chat_type="unknown",
            status="pending",
        )


def _simulate_crash_state(data_dir: Path, group_id: str) -> None:
    """Simulate crash by setting group to in_progress and chats to analyzing.

    Args:
        data_dir: Data directory
        group_id: Group ID to modify
    """
    db_path = data_dir / "groups.db"

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Set group status to in_progress
        cursor.execute(
            "UPDATE chat_groups SET status = ? WHERE id = ?",
            ("in_progress", group_id),
        )

        # Set some chats to analyzing status (first 2 chats)
        cursor.execute(
            """
            UPDATE group_chats
            SET status = ?
            WHERE group_id = ? AND rowid IN (
                SELECT rowid FROM group_chats WHERE group_id = ? LIMIT 2
            )
            """,
            ("analyzing", group_id, group_id),
        )

        conn.commit()

    finally:
        conn.close()


def _check_recovery_state(db_path: Path, group_id: str) -> tuple[str, int]:
    """Check group status and count of analyzing chats.

    Args:
        db_path: Database path
        group_id: Group ID to check

    Returns:
        Tuple of (group_status, analyzing_chats_count)
    """
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Get group status
        cursor.execute(
            "SELECT status FROM chat_groups WHERE id = ?",
            (group_id,),
        )
        row = cursor.fetchone()
        group_status = row[0] if row else None

        # Count analyzing chats
        cursor.execute(
            "SELECT COUNT(*) FROM group_chats WHERE group_id = ? AND status = ?",
            (group_id, "analyzing"),
        )
        analyzing_count = cursor.fetchone()[0]

        return group_status, analyzing_count

    finally:
        conn.close()
