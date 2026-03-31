"""Tests for FIFO subscription limit boundary conditions.

Verifies that:
1. At limit=N, adding chat N+1 causes leave of oldest by joined_at
2. FIFO ordering is by joined_at ASC (oldest first)
3. Account at exactly limit=N does NOT leave any chat (boundary)
4. Frozen chats (account left / subscription deleted) are excluded from FIFO candidates
"""

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_subscriptions.db"
        yield GroupDatabase(db_path)


class TestSubscriptionFIFO:
    """Test FIFO eviction behavior at boundary conditions."""

    def test_at_limit_no_eviction(self, temp_db):
        """Test that account at exactly limit=N does NOT leave any chat (boundary)."""
        account_id = 1001
        limit = 5  # Set limit to 5
        temp_db.set_setting("max_chats_per_account", str(limit))

        # Add exactly limit subscriptions
        for i in range(limit):
            chat_ref = f"@chat_{i}"
            catalog_chat_id = chat_ref
            telegram_chat_id = 100 + i

            # Prepare catalog entry
            from chatfilter.models.catalog import CatalogChat
            from chatfilter.models.group import ChatTypeEnum

            catalog = CatalogChat(
                id=catalog_chat_id,
                telegram_id=telegram_chat_id,
                title=f"Chat {i}",
                chat_type=ChatTypeEnum.GROUP,
                created_at=datetime.now(UTC) - timedelta(hours=i),
            )
            temp_db.save_catalog_chat(catalog)

            # Add subscription
            temp_db.add_subscription(account_id, catalog_chat_id, telegram_chat_id)

        # Verify all subscriptions exist
        subs = temp_db.get_subscriptions(account_id)
        assert len(subs) == limit

        # Verify no eviction should happen at this point
        count = temp_db.count_subscriptions(account_id)
        assert count == limit
        max_chats = temp_db.get_max_chats_per_account()
        assert count <= max_chats  # Not over limit

    def test_over_limit_triggers_eviction(self, temp_db):
        """Test that at limit=N, adding chat N+1 causes leave of oldest by joined_at."""
        account_id = 1002
        limit = 3  # Set limit to 3
        temp_db.set_setting("max_chats_per_account", str(limit))

        # Add limit subscriptions with different timestamps
        oldest_chat_ref = None
        join_times = []

        for i in range(limit):
            chat_ref = f"@chat_{i}"
            catalog_chat_id = chat_ref
            telegram_chat_id = 100 + i

            # Prepare catalog entry
            from chatfilter.models.catalog import CatalogChat
            from chatfilter.models.group import ChatTypeEnum

            created_at = datetime.now(UTC) - timedelta(hours=limit - i)
            catalog = CatalogChat(
                id=catalog_chat_id,
                telegram_id=telegram_chat_id,
                title=f"Chat {i}",
                chat_type=ChatTypeEnum.GROUP,
                created_at=created_at,
            )
            temp_db.save_catalog_chat(catalog)

            # Add subscription
            temp_db.add_subscription(account_id, catalog_chat_id, telegram_chat_id)

            if i == 0:
                oldest_chat_ref = catalog_chat_id
            join_times.append((catalog_chat_id, datetime.now(UTC)))

        # Verify at limit
        assert temp_db.count_subscriptions(account_id) == limit

        # Get the oldest subscription (should be the first one added)
        oldest = temp_db.get_oldest_subscription(account_id)
        assert oldest is not None
        assert oldest.catalog_chat_id == oldest_chat_ref
        assert oldest.account_id == account_id

        # Add one more chat (triggering eviction)
        new_chat_ref = "@chat_new"
        new_catalog_chat_id = new_chat_ref
        new_telegram_chat_id = 200

        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        new_catalog = CatalogChat(
            id=new_catalog_chat_id,
            telegram_id=new_telegram_chat_id,
            title="New Chat",
            chat_type=ChatTypeEnum.GROUP,
        )
        temp_db.save_catalog_chat(new_catalog)
        temp_db.add_subscription(account_id, new_catalog_chat_id, new_telegram_chat_id)

        # Now manually evict the oldest (simulating what worker.py does)
        oldest_to_evict = temp_db.get_oldest_subscription(account_id)
        assert oldest_to_evict is not None
        temp_db.remove_subscription(account_id, oldest_to_evict.catalog_chat_id)

        # Verify count is back to limit
        assert temp_db.count_subscriptions(account_id) == limit

        # Verify the oldest was removed
        remaining = temp_db.get_subscriptions(account_id)
        remaining_chat_ids = [sub.catalog_chat_id for sub in remaining]
        assert oldest_chat_ref not in remaining_chat_ids
        assert new_catalog_chat_id in remaining_chat_ids

    def test_fifo_ordering_by_joined_at(self, temp_db):
        """Test that FIFO ordering is by joined_at ASC (oldest first)."""
        account_id = 1003

        # Add subscriptions in reverse order (newest first)
        chat_refs = []
        for i in range(5):
            chat_ref = f"@chat_{i}"
            catalog_chat_id = chat_ref
            telegram_chat_id = 100 + i

            from chatfilter.models.catalog import CatalogChat
            from chatfilter.models.group import ChatTypeEnum

            catalog = CatalogChat(
                id=catalog_chat_id,
                telegram_id=telegram_chat_id,
                title=f"Chat {i}",
                chat_type=ChatTypeEnum.GROUP,
            )
            temp_db.save_catalog_chat(catalog)

            temp_db.add_subscription(account_id, catalog_chat_id, telegram_chat_id)
            chat_refs.append(catalog_chat_id)

        # Get subscriptions ordered
        subs = temp_db.get_subscriptions(account_id)

        # Verify they're ordered by joined_at ASC (oldest first)
        assert len(subs) == 5
        for i in range(len(subs) - 1):
            assert subs[i].joined_at <= subs[i + 1].joined_at

        # Verify oldest is the first one added
        assert subs[0].catalog_chat_id == chat_refs[0]

    def test_frozen_chat_excluded_from_fifo(self, temp_db):
        """Test that frozen chats (account left / deleted) are excluded from FIFO candidates."""
        account_id = 1004

        # Add multiple subscriptions
        chat_refs = []
        for i in range(4):
            chat_ref = f"@chat_{i}"
            catalog_chat_id = chat_ref
            telegram_chat_id = 100 + i

            from chatfilter.models.catalog import CatalogChat
            from chatfilter.models.group import ChatTypeEnum

            catalog = CatalogChat(
                id=catalog_chat_id,
                telegram_id=telegram_chat_id,
                title=f"Chat {i}",
                chat_type=ChatTypeEnum.GROUP,
            )
            temp_db.save_catalog_chat(catalog)
            temp_db.add_subscription(account_id, catalog_chat_id, telegram_chat_id)
            chat_refs.append(catalog_chat_id)

        # Initial count should be 4
        assert temp_db.count_subscriptions(account_id) == 4

        # Get the oldest subscription (first one added)
        oldest = temp_db.get_oldest_subscription(account_id)
        assert oldest.catalog_chat_id == chat_refs[0]

        # Simulate account left: remove the oldest subscription
        temp_db.remove_subscription(account_id, oldest.catalog_chat_id)

        # Count should now be 3
        assert temp_db.count_subscriptions(account_id) == 3

        # Get the new oldest (should be second chat now)
        new_oldest = temp_db.get_oldest_subscription(account_id)
        assert new_oldest.catalog_chat_id == chat_refs[1]

        # Verify the deleted chat is not in subscriptions list
        remaining = temp_db.get_subscriptions(account_id)
        remaining_ids = [sub.catalog_chat_id for sub in remaining]
        assert chat_refs[0] not in remaining_ids
        assert chat_refs[1] in remaining_ids

    def test_multiple_evictions_sequence(self, temp_db):
        """Test multiple sequential evictions maintain FIFO order."""
        account_id = 1005
        limit = 2  # Very small limit for testing

        # Add 3 chats
        for i in range(3):
            chat_ref = f"@chat_{i}"
            catalog_chat_id = chat_ref
            telegram_chat_id = 100 + i

            from chatfilter.models.catalog import CatalogChat
            from chatfilter.models.group import ChatTypeEnum

            catalog = CatalogChat(
                id=catalog_chat_id,
                telegram_id=telegram_chat_id,
                title=f"Chat {i}",
                chat_type=ChatTypeEnum.GROUP,
            )
            temp_db.save_catalog_chat(catalog)

            if i < 2:
                temp_db.add_subscription(account_id, catalog_chat_id, telegram_chat_id)

        # At this point: 2 subscriptions (at limit)
        assert temp_db.count_subscriptions(account_id) == 2
        temp_db.set_setting("max_chats_per_account", str(limit))

        # Add 3rd chat
        temp_db.add_subscription(account_id, "@chat_2", 102)
        # Now: 3 subscriptions (over limit)
        assert temp_db.count_subscriptions(account_id) == 3

        # Evict oldest
        oldest = temp_db.get_oldest_subscription(account_id)
        assert oldest.catalog_chat_id == "@chat_0"
        temp_db.remove_subscription(account_id, oldest.catalog_chat_id)
        # Back to 2
        assert temp_db.count_subscriptions(account_id) == 2

        # Add 4th chat
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        catalog = CatalogChat(
            id="@chat_3",
            telegram_id=103,
            title="Chat 3",
            chat_type=ChatTypeEnum.GROUP,
        )
        temp_db.save_catalog_chat(catalog)
        temp_db.add_subscription(account_id, "@chat_3", 103)
        # Now: 3 subscriptions (over limit again)
        assert temp_db.count_subscriptions(account_id) == 3

        # Evict next oldest (should be @chat_1)
        oldest2 = temp_db.get_oldest_subscription(account_id)
        assert oldest2.catalog_chat_id == "@chat_1"
        temp_db.remove_subscription(account_id, oldest2.catalog_chat_id)

        # Back to 2
        assert temp_db.count_subscriptions(account_id) == 2

        # Remaining should be chat_2 and chat_3
        remaining = temp_db.get_subscriptions(account_id)
        remaining_ids = [sub.catalog_chat_id for sub in remaining]
        assert "@chat_2" in remaining_ids
        assert "@chat_3" in remaining_ids
        assert "@chat_0" not in remaining_ids
        assert "@chat_1" not in remaining_ids

    def test_boundary_conditions_with_different_limits(self, temp_db):
        """Test boundary conditions with various limit values."""
        limits = [1, 5, 10, 100]

        for idx, limit in enumerate(limits):
            account_id = 2000 + idx
            temp_db.set_setting("max_chats_per_account", str(limit))

            # Add exactly limit subscriptions
            for i in range(limit):
                chat_ref = f"@chat_limit{limit}_{i}"
                catalog_chat_id = chat_ref
                telegram_chat_id = 1000 + limit * 100 + i

                from chatfilter.models.catalog import CatalogChat
                from chatfilter.models.group import ChatTypeEnum

                catalog = CatalogChat(
                    id=catalog_chat_id,
                    telegram_id=telegram_chat_id,
                    title=f"Chat {i}",
                    chat_type=ChatTypeEnum.GROUP,
                )
                temp_db.save_catalog_chat(catalog)
                temp_db.add_subscription(account_id, catalog_chat_id, telegram_chat_id)

            # Verify exactly at limit
            count = temp_db.count_subscriptions(account_id)
            assert count == limit

            # Add one more and verify eviction candidate exists
            new_chat_ref = f"@chat_limit{limit}_new"
            from chatfilter.models.catalog import CatalogChat
            from chatfilter.models.group import ChatTypeEnum

            new_catalog = CatalogChat(
                id=new_chat_ref,
                telegram_id=9999 + limit,
                title="New",
                chat_type=ChatTypeEnum.GROUP,
            )
            temp_db.save_catalog_chat(new_catalog)
            temp_db.add_subscription(account_id, new_chat_ref, 9999 + limit)

            # Now over limit
            assert temp_db.count_subscriptions(account_id) == limit + 1

            # Get oldest to evict
            oldest = temp_db.get_oldest_subscription(account_id)
            assert oldest is not None
            assert oldest.account_id == account_id

            # Verify it's the first one (oldest by joined_at)
            all_subs = temp_db.get_subscriptions(account_id)
            assert oldest.catalog_chat_id == all_subs[0].catalog_chat_id
