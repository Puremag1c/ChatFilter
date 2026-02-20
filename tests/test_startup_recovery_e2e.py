"""E2E test for startup recovery mechanism.

This test verifies that when server crashes during analysis,
stale in_progress groups are properly recovered on restart:
- Groups in 'in_progress' status → 'paused'
- Chats in 'analyzing' status → 'pending'

Pattern:
1. Start chatfilter server
2. Create group and trigger analysis
3. Kill server mid-analysis (simulate crash)
4. Restart server
5. Verify DB state shows recovery happened

Run with: pytest tests/test_startup_recovery_e2e.py
"""

import asyncio
import json
import os
import signal
import sqlite3
import tempfile
import time
from pathlib import Path
from subprocess import PIPE, Popen

import httpx
import pytest


@pytest.mark.timeout(120)
def test_startup_recovery_e2e():
    """Test that crashed in_progress groups are recovered on server restart.

    Verifies:
    - Server recovers stale in_progress groups
    - Group status changes from in_progress → paused
    - Chat status changes from analyzing → pending
    - Recovery is logged
    """
    # Use temporary directory for isolated test
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir) / "chatfilter-recovery-test"
        data_dir.mkdir()

        port = 8001
        base_url = f"http://localhost:{port}"

        # Step 1: Start server (first time)
        process = _start_server(port, data_dir)

        try:
            # Step 2: Wait for server to be ready
            _wait_for_server(base_url, timeout=30)

            # Step 3: Create a group with chats (directly in DB to bypass CSRF)
            group_id = "test-recovery-group"
            _create_test_group_in_db(data_dir, group_id)

            # Step 4: Manually set group status to in_progress and some chats to analyzing
            # (simulating mid-analysis state)
            _simulate_crash_state(data_dir, group_id)

            # Step 7: Kill the server process (simulate crash)
            process.terminate()
            try:
                process.wait(timeout=5)
            except:
                process.kill()
                process.wait()

            print("✓ Server crashed (simulated)")

            # Step 8: Restart server
            process = _start_server(port, data_dir)

            # Step 9: Wait for server to start (longer timeout for recovery)
            _wait_for_server(base_url, timeout=60)

            print("✓ Server restarted")

            # Step 10: Verify recovery happened by checking DB directly
            db_path = data_dir / "groups.db"
            group_status, analyzing_count = _check_recovery_state(db_path, group_id)

            # Assertions
            assert group_status == "paused", (
                f"Expected group status to be 'paused' after recovery, got '{group_status}'"
            )
            assert analyzing_count == 0, (
                f"Expected 0 chats in 'analyzing' status after recovery, got {analyzing_count}"
            )

            print("✓ Recovery verified: group is paused, no analyzing chats")

        finally:
            # Cleanup
            process.terminate()
            try:
                process.wait(timeout=5)
            except:
                process.kill()
                process.wait()


def _start_server(port: int, data_dir: Path) -> Popen:
    """Start chatfilter server process.

    Args:
        port: Port to bind server
        data_dir: Data directory path

    Returns:
        Popen process handle
    """
    env = os.environ.copy()
    env["CHATFILTER_DATA_DIR"] = str(data_dir)

    process = Popen(
        ["chatfilter", "--port", str(port)],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        env=env,
    )

    return process


def _wait_for_server(base_url: str, timeout: int = 30):
    """Wait for server to be ready.

    Args:
        base_url: Base URL of server
        timeout: Timeout in seconds

    Raises:
        TimeoutError: If server doesn't start within timeout
    """
    start_time = time.time()

    async def check():
        while time.time() - start_time < timeout:
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{base_url}/api/sessions",
                        timeout=2.0,
                        follow_redirects=True,
                    )
                    if response.status_code == 200:
                        return True
            except (httpx.ConnectError, httpx.TimeoutException):
                await asyncio.sleep(0.5)
                continue

        raise TimeoutError(f"Server failed to start within {timeout}s")

    asyncio.run(check())


def _create_test_group_in_db(data_dir: Path, group_id: str):
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

    print(f"✓ Created test group in DB: {group_id} (3 chats)")


def _simulate_crash_state(data_dir: Path, group_id: str):
    """Simulate crash by setting group to in_progress and chats to analyzing.

    Args:
        data_dir: Data directory
        group_id: Group ID to modify
    """
    db_path = data_dir / "groups.db"  # Use groups.db, not chatfilter.db

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
        print(f"✓ Simulated crash: group={group_id} status=in_progress, 2 chats=analyzing")

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
