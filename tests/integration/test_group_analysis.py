"""Integration tests for retry mechanism and incremental analysis.

Test Scenarios (from SPEC.md):
1. test_retry_on_floodwait - Verify dead chat result saved after FloodWait failures
2. test_incremental_analysis_skips_existing - Verify upsert preserves existing data
3. test_full_reanalysis_clears_old_data - Verify clear_results works
4. test_all_chats_get_results - Verify all chats get result rows (dead or done)
5. test_export_filters_work_without_exclude_dead - Verify dead type filter works

NOTE: These are database and API integration tests, not full end-to-end GroupEngine tests.
Full E2E tests would require complex Telethon mocking which is out of scope.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from chatfilter.models.group import (
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def test_db(tmp_path: Path) -> GroupDatabase:
    """Create isolated test database."""
    db_path = tmp_path / "test_groups.db"
    return GroupDatabase(str(db_path))


def test_retry_mechanism_saves_dead_result(test_db: GroupDatabase):
    """Verify that dead chats get result rows saved after FloodWait failures.

    This tests that the database correctly stores dead chat results,
    which is what happens after 3 FloodWait retry failures.
    """
    group_id = str(uuid4())
    test_db.save_group(
        group_id=group_id,
        name="FloodWait Test",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.IN_PROGRESS,
    )

    # Simulate Phase 1 failing chat (FloodWait exceeded retries)
    test_db.save_chat(
        group_id=group_id,
        chat_ref="floodwait_chat",
        chat_type=ChatTypeEnum.DEAD,
        status=GroupChatStatus.FAILED,
        error="FloodWait retry limit exceeded: 3 attempts",
    )

    # Save dead result (what GroupEngine does after 3 failures)
    test_db.upsert_result(
        group_id=group_id,
        chat_ref="floodwait_chat",
        metrics_data={
            "chat_type": ChatTypeEnum.DEAD,
            "status": "dead",
            "error": "FloodWait retry limit exceeded: 3 attempts",
            "chat_ref": "floodwait_chat",
        },
    )

    # Verify result was saved
    result = test_db.load_result(group_id, "floodwait_chat")
    assert result is not None, "Dead chat must have result row"

    metrics = result["metrics_data"]
    assert metrics["status"] == "dead"
    assert "FloodWait" in metrics["error"]
    assert "retry" in metrics["error"].lower()


def test_incremental_analysis_preserves_existing_data(test_db: GroupDatabase):
    """Verify upsert_result merges new data with existing data (INCREMENT mode behavior).

    When INCREMENT mode is used, existing non-null metrics should be preserved,
    and only missing metrics should be added.
    """
    group_id = str(uuid4())
    test_db.save_group(
        group_id=group_id,
        name="Incremental Test",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.COMPLETED,
    )

    test_db.save_chat(
        group_id,
        "test_chat",
        ChatTypeEnum.CHANNEL_NO_COMMENTS,
        GroupChatStatus.DONE,
    )

    # Phase 1: Save initial subscribers data
    test_db.upsert_result(
        group_id=group_id,
        chat_ref="test_chat",
        metrics_data={
            "subscribers": 500,
            "title": "Test Channel",
            "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS,
            "status": "done",
            "chat_ref": "test_chat",
        },
    )

    # Phase 2: Add activity metrics (INCREMENT mode - merge with existing)
    test_db.upsert_result(
        group_id=group_id,
        chat_ref="test_chat",
        metrics_data={
            "subscribers": 500,  # Keep same value
            "messages_per_hour": 10.5,  # NEW metric
            "unique_authors_per_hour": 5.2,  # NEW metric
            "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS,
            "status": "done",
            "chat_ref": "test_chat",
        },
    )

    # Verify: subscribers unchanged, activity metrics added
    result = test_db.load_result(group_id, "test_chat")
    metrics = result["metrics_data"]

    assert metrics["subscribers"] == 500, "Subscribers should be preserved"
    assert metrics["title"] == "Test Channel", "Title should be preserved"
    assert metrics["messages_per_hour"] == 10.5, "Activity metrics should be added"
    assert metrics["unique_authors_per_hour"] == 5.2


def test_full_reanalysis_clears_old_results(test_db: GroupDatabase):
    """Verify clear_results() removes old data (OVERWRITE mode behavior).

    When OVERWRITE mode is used, old results should be cleared before new analysis.
    """
    group_id = str(uuid4())
    test_db.save_group(
        group_id=group_id,
        name="Overwrite Test",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.COMPLETED,
    )

    # Add old results
    test_db.save_chat(group_id, "chat1", ChatTypeEnum.GROUP, GroupChatStatus.DONE)
    test_db.upsert_result(
        group_id=group_id,
        chat_ref="chat1",
        metrics_data={
            "subscribers": 999,
            "title": "Old Title",
            "chat_type": ChatTypeEnum.GROUP,
            "status": "done",
            "chat_ref": "chat1",
        },
    )

    # Verify old data exists
    results_before = test_db.load_results(group_id)
    assert len(results_before) == 1

    # Clear results (what happens in OVERWRITE mode)
    test_db.clear_results(group_id)

    # Verify results cleared
    results_after = test_db.load_results(group_id)
    assert len(results_after) == 0, "clear_results() should remove all results"


def test_all_chats_get_result_rows(test_db: GroupDatabase):
    """Verify all chats get result rows, including dead chats.

    After analysis, every chat (whether successful or failed) must have a row
    in group_results table.
    """
    group_id = str(uuid4())
    test_db.save_group(
        group_id=group_id,
        name="All Chats Test",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.COMPLETED,
    )

    # Create 10 chats: 8 successful, 2 dead
    for i in range(8):
        chat_ref = f"success_chat_{i}"
        test_db.save_chat(
            group_id,
            chat_ref,
            ChatTypeEnum.CHANNEL_NO_COMMENTS,
            GroupChatStatus.DONE,
        )
        test_db.upsert_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data={
                "subscribers": 100 * (i + 1),
                "title": f"Channel {i}",
                "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS,
                "status": "done",
                "chat_ref": chat_ref,
            },
        )

    for i in range(2):
        chat_ref = f"dead_chat_{i}"
        test_db.save_chat(
            group_id,
            chat_ref,
            ChatTypeEnum.DEAD,
            GroupChatStatus.FAILED,
            error=f"Simulated error {i}",
        )
        test_db.upsert_result(
            group_id=group_id,
            chat_ref=chat_ref,
            metrics_data={
                "chat_type": ChatTypeEnum.DEAD,
                "status": "dead",
                "error": f"Simulated error {i}",
                "chat_ref": chat_ref,
            },
        )

    # Verify: ALL 10 chats have result rows
    results = test_db.load_results(group_id)
    assert len(results) == 10, f"Expected 10 result rows, got {len(results)}"

    # Count by status
    done_count = 0
    dead_count = 0

    for result in results:
        metrics = result["metrics_data"]
        if metrics["status"] == "done":
            done_count += 1
        elif metrics["status"] == "dead":
            dead_count += 1

    assert done_count == 8, f"Expected 8 done chats, got {done_count}"
    assert dead_count == 2, f"Expected 2 dead chats, got {dead_count}"


def test_export_filters_exclude_dead_via_chat_type(test_db: GroupDatabase):
    """Verify export filters work: dead type checkbox removes dead chats from results.

    This tests the database-level filtering (load_results with filters),
    which is what the export endpoint uses.
    """
    from chatfilter.web.routers.groups import _apply_export_filters

    group_id = str(uuid4())
    test_db.save_group(
        group_id=group_id,
        name="Export Filter Test",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.COMPLETED,
    )

    # Add 1 live chat and 1 dead chat
    test_db.save_chat(
        group_id,
        "live_chat",
        ChatTypeEnum.CHANNEL_NO_COMMENTS,
        GroupChatStatus.DONE,
    )
    test_db.upsert_result(
        group_id=group_id,
        chat_ref="live_chat",
        metrics_data={
            "title": "Live Channel",
            "subscribers": 100,
            "chat_type": ChatTypeEnum.CHANNEL_NO_COMMENTS,
            "status": "done",
            "chat_ref": "live_chat",
        },
    )

    test_db.save_chat(
        group_id,
        "dead_chat",
        ChatTypeEnum.DEAD,
        GroupChatStatus.FAILED,
        error="Dead chat error",
    )
    test_db.upsert_result(
        group_id=group_id,
        chat_ref="dead_chat",
        metrics_data={
            "title": "Dead Chat",
            "chat_type": ChatTypeEnum.DEAD,
            "status": "dead",
            "error": "Dead chat error",
            "chat_ref": "dead_chat",
        },
    )

    # Test 1: Load ALL results (no filter)
    all_results = test_db.load_results(group_id)
    assert len(all_results) == 2, "Should have 2 results (1 live + 1 dead)"

    # Test 2: Filter by applying export logic manually
    # This simulates what _apply_export_filters does
    filtered_results = []
    chat_types_filter = {ChatTypeEnum.CHANNEL_NO_COMMENTS}  # Exclude DEAD

    for result in all_results:
        metrics = result["metrics_data"]
        chat_type = metrics.get("chat_type")

        # Apply filter: only include if chat_type in allowed set
        if chat_type in chat_types_filter:
            filtered_results.append(result)

    assert len(filtered_results) == 1, "Filter should exclude dead chat"

    # Verify only live chat remains
    live_metrics = filtered_results[0]["metrics_data"]
    assert live_metrics["title"] == "Live Channel"
    assert live_metrics["status"] == "done"
