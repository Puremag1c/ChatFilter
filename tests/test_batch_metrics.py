"""Test batch metrics loading optimization."""

from pathlib import Path

import pytest

from chatfilter.models.group import GroupSettings
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def test_db(tmp_path: Path) -> GroupDatabase:
    """Create test database instance."""
    db_path = tmp_path / "test_batch_metrics.db"
    return GroupDatabase(db_path)


@pytest.fixture
def service(test_db: GroupDatabase) -> GroupService:
    """Create test service instance."""
    return GroupService(test_db)


def test_get_chat_metrics_batch(test_db: GroupDatabase) -> None:
    """Test batch metrics loading returns same data as individual calls."""
    # Create group with some chats
    group_id = "test-group"
    test_db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=GroupSettings().model_dump(),
        status="pending",
    )

    # Create 5 chats with metrics
    chat_ids = []
    for i in range(5):
        chat_id = test_db.save_chat(
            group_id=group_id,
            chat_ref=f"@chat{i}",
            chat_type="group",
            status="done",
        )
        chat_ids.append(chat_id)

        # Save metrics for each chat
        test_db.save_chat_metrics(
            chat_id=chat_id,
            metrics={
                "title": f"Chat {i}",
                "moderation": i % 2 == 0,
                "messages_per_hour": float(i * 10),
                "unique_authors_per_hour": float(i * 5),
                "captcha": i % 3 == 0,
                "partial_data": False,
                "metrics_version": 1,
            },
        )

    # Test batch method
    batch_results = test_db.get_chat_metrics_batch(chat_ids)

    # Verify we got all 5 chats
    assert len(batch_results) == 5

    # Verify batch results match individual calls
    for chat_id in chat_ids:
        individual = test_db.get_chat_metrics(chat_id)
        batch = batch_results[chat_id]

        assert batch == individual, f"Mismatch for chat_id {chat_id}"


def test_get_results_uses_batch(service: GroupService, test_db: GroupDatabase) -> None:
    """Test that get_results efficiently loads metrics in batch."""
    # Create group with 100 chats
    group = service.create_group(
        name="Large Group",
        chat_refs=[f"@chat{i}" for i in range(100)],
    )

    # Get all chats
    chats = test_db.load_chats(group_id=group.id)

    # Add metrics to some chats
    for i, chat in enumerate(chats[:50]):
        test_db.save_chat_metrics(
            chat_id=chat["id"],
            metrics={
                "title": f"Chat {i}",
                "moderation": i % 2 == 0,
                "messages_per_hour": float(i * 10),
                "unique_authors_per_hour": float(i * 5),
                "captcha": False,
                "partial_data": False,
                "metrics_version": 1,
            },
        )

    # Call get_results (this should use batch internally)
    results = service.get_results(group.id)

    # Verify we got all 100 results
    assert len(results) == 100

    # Verify first 50 have metrics
    with_metrics = [r for r in results if r.get("title")]
    assert len(with_metrics) == 50

    # Verify metric values
    for result in with_metrics:
        assert result["title"].startswith("Chat ")
        assert "moderation" in result
        assert "messages_per_hour" in result


def test_get_chat_metrics_batch_empty_list(test_db: GroupDatabase) -> None:
    """Test batch method handles empty list gracefully."""
    result = test_db.get_chat_metrics_batch([])
    assert result == {}


def test_get_chat_metrics_batch_nonexistent_ids(test_db: GroupDatabase) -> None:
    """Test batch method handles nonexistent IDs."""
    # Request metrics for IDs that don't exist
    result = test_db.get_chat_metrics_batch([9999, 10000, 10001])

    # Should return empty dict (no matches)
    assert result == {}
