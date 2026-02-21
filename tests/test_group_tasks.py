"""Tests for group_tasks CRUD and group status computation."""

import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from chatfilter.models.group import GroupChatStatus, GroupSettings, GroupStatus, TaskStatus
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_group_tasks.db"
        yield GroupDatabase(db_path)


@pytest.fixture
def setup_group(temp_db):
    """Create a test group."""
    group_id = "group-test-123"
    temp_db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.PENDING.value,
    )
    return group_id


class TestGroupTasksCRUD:
    """Test CRUD operations for group_tasks table."""

    def test_create_task(self, temp_db, setup_group):
        """Test creating a new group task."""
        group_id = setup_group
        requested_metrics = GroupSettings(time_window=48).model_dump()

        task_id = temp_db.create_task(
            group_id=group_id,
            requested_metrics=requested_metrics,
            time_window=48,
        )

        assert task_id is not None
        assert task_id.startswith("task-")

        # Verify task was created
        task = temp_db.get_active_task(group_id)
        assert task is not None
        assert task["id"] == task_id
        assert task["group_id"] == group_id
        assert task["requested_metrics"] == requested_metrics
        assert task["time_window"] == 48
        assert task["status"] == TaskStatus.RUNNING.value
        assert task["created_at"] is not None

    def test_get_active_task_none_exists(self, temp_db, setup_group):
        """Test get_active_task returns None when no active task exists."""
        group_id = setup_group

        task = temp_db.get_active_task(group_id)

        assert task is None

    def test_get_active_task_returns_running_task(self, temp_db, setup_group):
        """Test get_active_task returns the running task."""
        group_id = setup_group

        task_id = temp_db.create_task(
            group_id=group_id,
            requested_metrics=GroupSettings().model_dump(),
            time_window=24,
        )

        task = temp_db.get_active_task(group_id)

        assert task is not None
        assert task["id"] == task_id
        assert task["status"] == TaskStatus.RUNNING.value

    def test_complete_task(self, temp_db, setup_group):
        """Test marking a task as completed."""
        group_id = setup_group

        task_id = temp_db.create_task(
            group_id=group_id,
            requested_metrics=GroupSettings().model_dump(),
            time_window=24,
        )

        # Complete the task
        temp_db.complete_task(task_id)

        # Verify task is no longer active
        active_task = temp_db.get_active_task(group_id)
        assert active_task is None

        # Verify task status changed to completed
        with temp_db._connection() as conn:
            cursor = conn.execute(
                "SELECT status FROM group_tasks WHERE id = ?",
                (task_id,),
            )
            row = cursor.fetchone()
            assert row["status"] == TaskStatus.COMPLETED.value

    def test_cancel_task(self, temp_db, setup_group):
        """Test marking a task as cancelled."""
        group_id = setup_group

        task_id = temp_db.create_task(
            group_id=group_id,
            requested_metrics=GroupSettings().model_dump(),
            time_window=24,
        )

        # Cancel the task
        temp_db.cancel_task(task_id)

        # Verify task is no longer active
        active_task = temp_db.get_active_task(group_id)
        assert active_task is None

        # Verify task status changed to cancelled
        with temp_db._connection() as conn:
            cursor = conn.execute(
                "SELECT status FROM group_tasks WHERE id = ?",
                (task_id,),
            )
            row = cursor.fetchone()
            assert row["status"] == TaskStatus.CANCELLED.value

    def test_only_one_active_task_per_group(self, temp_db, setup_group):
        """Test that only one running task can exist per group at a time."""
        group_id = setup_group

        # Create first task
        task_id_1 = temp_db.create_task(
            group_id=group_id,
            requested_metrics=GroupSettings().model_dump(),
            time_window=24,
        )

        # Complete first task
        temp_db.complete_task(task_id_1)

        # Wait 1 second to ensure unique task ID (based on timestamp)
        time.sleep(1)

        # Create second task
        task_id_2 = temp_db.create_task(
            group_id=group_id,
            requested_metrics=GroupSettings().model_dump(),
            time_window=48,
        )

        # get_active_task should return only the running task (task_id_2)
        active_task = temp_db.get_active_task(group_id)
        assert active_task is not None
        assert active_task["id"] == task_id_2
        assert active_task["time_window"] == 48

    def test_multiple_groups_multiple_tasks(self, temp_db):
        """Test that multiple groups can each have their own active task."""
        # Create two groups
        group_id_1 = "group-1"
        group_id_2 = "group-2"

        for group_id in [group_id_1, group_id_2]:
            temp_db.save_group(
                group_id=group_id,
                name=f"Group {group_id}",
                settings=GroupSettings().model_dump(),
                status=GroupStatus.PENDING.value,
            )

        # Create task for each group
        task_id_1 = temp_db.create_task(
            group_id=group_id_1,
            requested_metrics=GroupSettings().model_dump(),
            time_window=24,
        )

        # Wait 1 second to ensure unique task ID (based on timestamp)
        time.sleep(1)

        task_id_2 = temp_db.create_task(
            group_id=group_id_2,
            requested_metrics=GroupSettings().model_dump(),
            time_window=48,
        )

        # Each group should have its own active task
        task_1 = temp_db.get_active_task(group_id_1)
        task_2 = temp_db.get_active_task(group_id_2)

        assert task_1 is not None
        assert task_1["id"] == task_id_1
        assert task_1["time_window"] == 24

        assert task_2 is not None
        assert task_2["id"] == task_id_2
        assert task_2["time_window"] == 48


class TestComputeGroupStatus:
    """Test compute_group_status logic."""

    def test_empty_group_is_pending(self, temp_db, setup_group):
        """Test that a group with no chats is PENDING."""
        group_id = setup_group

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.PENDING.value

    def test_all_pending_is_pending(self, temp_db, setup_group):
        """Test that when all chats are pending, group status is PENDING."""
        group_id = setup_group

        # Add chats with pending status
        for i in range(3):
            temp_db.save_chat(
                group_id=group_id,
                chat_ref=f"@chat{i}",
                chat_type="group",
                status=GroupChatStatus.PENDING.value,
            )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.PENDING.value

    def test_mixed_statuses_is_in_progress(self, temp_db, setup_group):
        """Test that mixed chat statuses result in IN_PROGRESS."""
        group_id = setup_group

        # Add chats with mixed statuses
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat1",
            chat_type="group",
            status=GroupChatStatus.PENDING.value,
        )
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat2",
            chat_type="group",
            status=GroupChatStatus.DONE.value,
        )
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat3",
            chat_type="group",
            status=GroupChatStatus.ERROR.value,
        )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.IN_PROGRESS.value

    def test_all_done_is_completed(self, temp_db, setup_group):
        """Test that when all chats are done, group status is COMPLETED."""
        group_id = setup_group

        # Add chats all with done status
        for i in range(3):
            temp_db.save_chat(
                group_id=group_id,
                chat_ref=f"@chat{i}",
                chat_type="group",
                status=GroupChatStatus.DONE.value,
            )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.COMPLETED.value

    def test_all_error_is_failed(self, temp_db, setup_group):
        """Test that when all chats are error, group status is FAILED."""
        group_id = setup_group

        # Add chats all with error status
        for i in range(3):
            temp_db.save_chat(
                group_id=group_id,
                chat_ref=f"@chat{i}",
                chat_type="group",
                status=GroupChatStatus.ERROR.value,
            )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.FAILED.value

    def test_done_and_error_is_completed(self, temp_db, setup_group):
        """Test that when all chats are done or error (no pending), group status is COMPLETED."""
        group_id = setup_group

        # Add chats with done and error (no pending)
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat1",
            chat_type="group",
            status=GroupChatStatus.DONE.value,
        )
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat2",
            chat_type="group",
            status=GroupChatStatus.DONE.value,
        )
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat3",
            chat_type="group",
            status=GroupChatStatus.ERROR.value,
        )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.COMPLETED.value

    def test_pending_with_done_is_in_progress(self, temp_db, setup_group):
        """Test that pending + done = IN_PROGRESS."""
        group_id = setup_group

        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat1",
            chat_type="group",
            status=GroupChatStatus.PENDING.value,
        )
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat2",
            chat_type="group",
            status=GroupChatStatus.DONE.value,
        )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.IN_PROGRESS.value

    def test_pending_with_error_is_in_progress(self, temp_db, setup_group):
        """Test that pending + error = IN_PROGRESS."""
        group_id = setup_group

        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat1",
            chat_type="group",
            status=GroupChatStatus.PENDING.value,
        )
        temp_db.save_chat(
            group_id=group_id,
            chat_ref="@chat2",
            chat_type="group",
            status=GroupChatStatus.ERROR.value,
        )

        status = temp_db.compute_group_status(group_id)

        assert status == GroupStatus.IN_PROGRESS.value
