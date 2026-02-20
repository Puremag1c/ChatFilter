"""Multi-account concurrency test for ChatFilter.

Tests that concurrent DB updates maintain consistency without race conditions.
This verifies the global counter approach works correctly for multi-account scenario.

Scenario #6: 3 accounts × 50 chats = 150 total
Expected: Counter goes 0 → 1 → 2 → ... → 150 smoothly (monotonically)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from chatfilter.models.group import GroupSettings, GroupStatus
from chatfilter.storage.group_database import GroupDatabase

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


class TestMultiAccountConcurrency:
    """Tests for multi-account concurrency behavior at DB level."""

    @pytest.fixture
    async def temp_db(self) -> AsyncGenerator[Path, None]:
        """Create temporary database for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield db_path

    @pytest.mark.asyncio
    async def test_concurrent_db_updates_no_race(self, temp_db: Path) -> None:
        """Test that concurrent DB updates don't cause race conditions.

        This test verifies the core assumption: that count_processed_chats()
        provides consistent, monotonic counters even under concurrent updates.

        Scenario:
        - 150 chats (simulating 3 accounts × 50 chats)
        - All updated concurrently (simulates parallel processing)
        - Counter should increase monotonically: 0 → 1 → 2 → ... → 150
        - NO backward jumps
        - NO lost updates

        This validates that the global DB-based counter approach (from ChatFilter-56z53)
        works correctly for multi-account scenarios.
        """
        db = GroupDatabase(db_path=temp_db)
        GROUP_ID = "multi_account_test"
        NUM_CHATS = 150  # 3 accounts × 50 chats

        # Create group and chats
        db.save_group(
            group_id=GROUP_ID,
            name="Multi-Account Test",
            settings=GroupSettings().model_dump(),
            status=GroupStatus.PENDING.value,
        )
        chat_ids = []
        for i in range(NUM_CHATS):
            chat_id = db.save_chat(
                group_id=GROUP_ID,
                chat_ref=f"chat_{i:03d}",
                chat_type="group",
                status="pending",
            )
            chat_ids.append(chat_id)

        # Track counter snapshots
        counter_snapshots: list[int] = []
        lock = asyncio.Lock()

        async def update_and_snapshot(chat_idx: int) -> None:
            """Update a chat and capture counter snapshot."""
            chat_id = chat_ids[chat_idx]

            # Simulate real-world delay
            await asyncio.sleep(0.001)

            # Update chat status to 'done' (synchronous DB operation)
            db.update_chat_status(chat_id, "done")

            # Read counter (synchronous DB operation)
            processed, _total = db.count_processed_chats(GROUP_ID)

            # Store snapshot (thread-safe)
            async with lock:
                counter_snapshots.append(processed)

        # Run concurrent updates (simulates 3 accounts processing in parallel)
        tasks = [update_and_snapshot(i) for i in range(NUM_CHATS)]
        await asyncio.gather(*tasks)

        # VERIFICATION 1: All updates completed
        assert len(counter_snapshots) == NUM_CHATS

        # VERIFICATION 2: Final DB state is correct
        processed, total = db.count_processed_chats(GROUP_ID)
        assert processed == NUM_CHATS, f"Final processed count: {processed}/{NUM_CHATS}"
        assert total == NUM_CHATS, f"Final total count: {total}/{NUM_CHATS}"

        # VERIFICATION 3: Counter only increases (monotonic)
        for i in range(1, len(counter_snapshots)):
            prev = counter_snapshots[i - 1]
            curr = counter_snapshots[i]
            # Due to async ordering, we only verify no backward jumps
            # (values can stay same if reads happen before writes complete)
            assert curr >= prev, f"Counter went backward: {prev} → {curr}"

        # VERIFICATION 4: Max counter reached total
        assert max(counter_snapshots) == NUM_CHATS, (
            f"Max counter {max(counter_snapshots)} != total {NUM_CHATS}"
        )
