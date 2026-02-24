"""Tests for FloodWaitTracker — account lockout tracking."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from chatfilter.telegram.flood_tracker import FloodWaitTracker


class TestFloodWaitTrackerBasics:
    """Basic FloodWaitTracker functionality tests."""

    def test_record_and_is_blocked(self) -> None:
        """Test record_flood_wait makes account blocked."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 5)

        assert tracker.is_blocked("account_1") is True

    def test_is_blocked_returns_false_initially(self) -> None:
        """Test is_blocked returns False for untracked account."""
        tracker = FloodWaitTracker()
        assert tracker.is_blocked("unknown_account") is False

    def test_is_blocked_returns_false_after_expiry(self) -> None:
        """Test is_blocked returns False after wait period expires."""
        tracker = FloodWaitTracker()
        # Very short wait time
        tracker.record_flood_wait("account_1", 1)

        # Initially blocked
        assert tracker.is_blocked("account_1") is True

        # Wait for expiry
        time.sleep(1.1)

        # No longer blocked
        assert tracker.is_blocked("account_1") is False

    def test_get_wait_until_returns_correct_timestamp(self) -> None:
        """Test get_wait_until returns correct expiry timestamp."""
        tracker = FloodWaitTracker()
        before = time.time()
        tracker.record_flood_wait("account_1", 10)
        after = time.time()

        wait_until = tracker.get_wait_until("account_1")
        assert wait_until is not None

        # Timestamp should be before + 10 seconds (with tolerance)
        expected_min = before + 10
        expected_max = after + 10
        assert expected_min <= wait_until <= expected_max

    def test_get_wait_until_returns_none_for_untracked(self) -> None:
        """Test get_wait_until returns None for untracked account."""
        tracker = FloodWaitTracker()
        assert tracker.get_wait_until("unknown_account") is None

    def test_get_wait_until_returns_none_after_expiry(self) -> None:
        """Test get_wait_until returns None after expiry (lazy cleanup)."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 1)

        # Wait for expiry
        time.sleep(1.1)

        # is_blocked triggers cleanup
        tracker.is_blocked("account_1")

        # Now get_wait_until should return None
        assert tracker.get_wait_until("account_1") is None


class TestFloodWaitTrackerMultipleAccounts:
    """Tests with multiple blocked accounts."""

    def test_get_earliest_available_returns_min_expiry(self) -> None:
        """Test get_earliest_available returns earliest expiry timestamp."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 10)
        tracker.record_flood_wait("account_2", 5)
        tracker.record_flood_wait("account_3", 20)

        earliest = tracker.get_earliest_available()
        assert earliest is not None

        # account_2 has the shortest wait (5s)
        account_2_expiry = tracker.get_wait_until("account_2")
        assert earliest == account_2_expiry

    def test_get_earliest_available_returns_none_when_empty(self) -> None:
        """Test get_earliest_available returns None when no accounts blocked."""
        tracker = FloodWaitTracker()
        assert tracker.get_earliest_available() is None

    def test_get_blocked_accounts_returns_all_blocked(self) -> None:
        """Test get_blocked_accounts returns all currently blocked accounts."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 10)
        tracker.record_flood_wait("account_2", 20)

        blocked = tracker.get_blocked_accounts()
        assert len(blocked) == 2
        assert "account_1" in blocked
        assert "account_2" in blocked

    def test_get_blocked_accounts_returns_empty_dict_initially(self) -> None:
        """Test get_blocked_accounts returns empty dict when no blocks."""
        tracker = FloodWaitTracker()
        blocked = tracker.get_blocked_accounts()
        assert blocked == {}

    def test_get_blocked_accounts_cleans_expired(self) -> None:
        """Test get_blocked_accounts removes expired entries."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 1)  # Short wait
        tracker.record_flood_wait("account_2", 10)  # Long wait

        # Wait for account_1 to expire
        time.sleep(1.1)

        blocked = tracker.get_blocked_accounts()
        # Only account_2 should remain
        assert len(blocked) == 1
        assert "account_2" in blocked
        assert "account_1" not in blocked


class TestFloodWaitTrackerClearExpired:
    """Tests for clear_expired() functionality."""

    def test_clear_expired_removes_expired_entries(self) -> None:
        """Test clear_expired removes entries past expiry timestamp."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 1)  # Short wait
        tracker.record_flood_wait("account_2", 10)  # Long wait

        # Wait for account_1 to expire
        time.sleep(1.1)

        cleared_count = tracker.clear_expired()
        assert cleared_count == 1

        # account_1 should be gone
        assert tracker.get_wait_until("account_1") is None
        # account_2 should remain
        assert tracker.get_wait_until("account_2") is not None

    def test_clear_expired_returns_zero_when_none_expired(self) -> None:
        """Test clear_expired returns 0 when no entries expired."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 10)

        cleared_count = tracker.clear_expired()
        assert cleared_count == 0

    def test_clear_expired_returns_zero_when_empty(self) -> None:
        """Test clear_expired returns 0 when tracker is empty."""
        tracker = FloodWaitTracker()
        cleared_count = tracker.clear_expired()
        assert cleared_count == 0


class TestFloodWaitTrackerThreadSafety:
    """Thread safety tests for concurrent access."""

    def test_concurrent_record_flood_wait(self) -> None:
        """Test concurrent record_flood_wait calls don't corrupt state."""
        tracker = FloodWaitTracker()
        num_threads = 10
        accounts_per_thread = 5

        def record_floods(thread_id: int) -> None:
            for i in range(accounts_per_thread):
                account_id = f"account_{thread_id}_{i}"
                tracker.record_flood_wait(account_id, 10)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(record_floods, i) for i in range(num_threads)]
            for future in futures:
                future.result()

        # All accounts should be tracked
        blocked = tracker.get_blocked_accounts()
        assert len(blocked) == num_threads * accounts_per_thread

    def test_concurrent_is_blocked_checks(self) -> None:
        """Test concurrent is_blocked checks are thread-safe."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 10)

        num_threads = 20
        results = []

        # Synchronize all threads to start at once
        barrier = Barrier(num_threads)

        def check_blocked() -> bool:
            barrier.wait()  # Wait for all threads
            return tracker.is_blocked("account_1")

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(check_blocked) for _ in range(num_threads)]
            results = [future.result() for future in futures]

        # All threads should see account_1 as blocked
        assert all(results)

    def test_concurrent_read_write_mixed(self) -> None:
        """Test mixed concurrent reads and writes don't cause race conditions."""
        tracker = FloodWaitTracker()
        num_threads = 20
        barrier = Barrier(num_threads)

        def mixed_operations(thread_id: int) -> None:
            barrier.wait()  # Synchronize start
            if thread_id % 2 == 0:
                # Writer threads
                tracker.record_flood_wait(f"account_{thread_id}", 10)
            else:
                # Reader threads
                tracker.is_blocked(f"account_{thread_id - 1}")
                tracker.get_blocked_accounts()
                tracker.get_earliest_available()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(mixed_operations, i) for i in range(num_threads)]
            for future in futures:
                future.result()

        # Half the accounts should be tracked (even thread IDs)
        blocked = tracker.get_blocked_accounts()
        assert len(blocked) == num_threads // 2

    def test_concurrent_clear_expired_safe(self) -> None:
        """Test concurrent clear_expired calls are thread-safe."""
        tracker = FloodWaitTracker()

        # Record some short-lived entries
        for i in range(10):
            tracker.record_flood_wait(f"account_{i}", 1)

        # Wait for expiry
        time.sleep(1.1)

        # Clear from multiple threads simultaneously
        num_threads = 5
        results = []

        def clear_entries() -> int:
            return tracker.clear_expired()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(clear_entries) for _ in range(num_threads)]
            results = [future.result() for future in futures]

        # Total cleared should be 10 (one thread clears, others see 0)
        total_cleared = sum(results)
        assert total_cleared == 10

        # Tracker should be empty
        assert len(tracker.get_blocked_accounts()) == 0


class TestFloodWaitTrackerHelperMethods:
    """Tests for helper/utility methods."""

    def test_clear_account_removes_specific_account(self) -> None:
        """Test clear_account removes specific account entry."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 10)
        tracker.record_flood_wait("account_2", 10)

        removed = tracker.clear_account("account_1")
        assert removed is True

        # account_1 should be gone
        assert tracker.is_blocked("account_1") is False
        # account_2 should remain
        assert tracker.is_blocked("account_2") is True

    def test_clear_account_returns_false_for_untracked(self) -> None:
        """Test clear_account returns False for untracked account."""
        tracker = FloodWaitTracker()
        removed = tracker.clear_account("unknown_account")
        assert removed is False

    def test_clear_all_removes_all_entries(self) -> None:
        """Test clear_all removes all FloodWait entries."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 10)
        tracker.record_flood_wait("account_2", 10)
        tracker.record_flood_wait("account_3", 10)

        cleared_count = tracker.clear_all()
        assert cleared_count == 3

        # Tracker should be empty
        assert len(tracker.get_blocked_accounts()) == 0

    def test_clear_all_returns_zero_when_empty(self) -> None:
        """Test clear_all returns 0 when tracker is empty."""
        tracker = FloodWaitTracker()
        cleared_count = tracker.clear_all()
        assert cleared_count == 0


class TestFloodWaitTrackerEdgeCases:
    """Edge cases and boundary conditions."""

    def test_zero_seconds_flood_wait(self) -> None:
        """Test recording FloodWait with 0 seconds."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 0)

        # Should immediately be unblocked (expired)
        assert tracker.is_blocked("account_1") is False

    def test_negative_seconds_flood_wait(self) -> None:
        """Test recording FloodWait with negative seconds (edge case)."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", -5)

        # Should immediately be unblocked (already expired)
        assert tracker.is_blocked("account_1") is False

    def test_very_large_flood_wait(self) -> None:
        """Test recording very large FloodWait duration."""
        tracker = FloodWaitTracker()
        # 1 year in seconds
        tracker.record_flood_wait("account_1", 31_536_000)

        # Should be blocked
        assert tracker.is_blocked("account_1") is True

        wait_until = tracker.get_wait_until("account_1")
        assert wait_until is not None
        # Should be ~1 year in the future
        assert wait_until > time.time() + 31_535_000

    def test_rerecording_same_account_updates_timestamp(self) -> None:
        """Test recording FloodWait again for same account updates timestamp."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 5)

        first_expiry = tracker.get_wait_until("account_1")
        assert first_expiry is not None

        # Record again with longer duration
        time.sleep(0.1)
        tracker.record_flood_wait("account_1", 10)

        second_expiry = tracker.get_wait_until("account_1")
        assert second_expiry is not None

        # Second expiry should be later than first
        assert second_expiry > first_expiry

    def test_is_blocked_lazy_cleanup_behavior(self) -> None:
        """Test is_blocked performs lazy cleanup of expired entries."""
        tracker = FloodWaitTracker()
        tracker.record_flood_wait("account_1", 1)

        # Entry exists
        assert "account_1" in tracker.get_blocked_accounts()

        # Wait for expiry
        time.sleep(1.1)

        # is_blocked should trigger cleanup
        is_blocked = tracker.is_blocked("account_1")
        assert is_blocked is False

        # Entry should be gone from internal storage
        assert "account_1" not in tracker.get_blocked_accounts()
