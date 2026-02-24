"""Tests for AccountHealthTracker: dead chats and FloodWait are ignored."""

from __future__ import annotations

from chatfilter.analyzer.group_engine import AccountHealthTracker


class TestHealthTrackerIgnoresDeadChats:
    """Dead chat errors should NOT trigger should_stop."""

    def test_ten_dead_chats_should_not_stop(self) -> None:
        """10 dead chats in a row → should_stop returns False."""
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        for _ in range(10):
            tracker.record_chat_error("acc1")

        assert not tracker.should_stop("acc1")

    def test_dead_chats_increment_total_error(self) -> None:
        """Dead chats still count in total_error for stats."""
        tracker = AccountHealthTracker()

        for _ in range(10):
            tracker.record_chat_error("acc1")

        stats = tracker.get_stats("acc1")
        assert stats["total_error"] == 10
        assert stats["consecutive_errors"] == 0


class TestHealthTrackerIgnoresFloodWait:
    """FloodWait exhaustion should NOT trigger should_stop."""

    def test_floodwait_exhaustion_should_not_stop(self) -> None:
        """FloodWait exhaustion → should_stop returns False.

        FloodWait is handled via record_chat_error (not account's fault).
        """
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        # Simulate FloodWait exhaustion: many "errors" that are really FloodWait
        for _ in range(10):
            tracker.record_chat_error("acc1")

        assert not tracker.should_stop("acc1")
        assert tracker.consecutive_errors.get("acc1", 0) == 0


class TestHealthTrackerRealErrors:
    """Real account errors still trigger should_stop correctly."""

    def test_five_real_errors_should_stop(self) -> None:
        """5 real account errors → should_stop returns True (still works)."""
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        for _ in range(5):
            tracker.record_failure("acc1")

        assert tracker.should_stop("acc1")

    def test_four_real_errors_should_not_stop(self) -> None:
        """4 real account errors → should_stop returns False (threshold not reached)."""
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        for _ in range(4):
            tracker.record_failure("acc1")

        assert not tracker.should_stop("acc1")


class TestHealthTrackerMixedErrors:
    """Mixed dead chats + real errors: only real errors increment consecutive counter."""

    def test_mixed_dead_chats_and_real_errors(self) -> None:
        """Dead chats interspersed with real errors reset consecutive counter."""
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        # 2 real errors
        tracker.record_failure("acc1")
        tracker.record_failure("acc1")
        assert tracker.consecutive_errors["acc1"] == 2

        # Dead chat resets consecutive counter
        tracker.record_chat_error("acc1")
        assert tracker.consecutive_errors["acc1"] == 0

        # 2 more real errors — consecutive is 2, not 4
        tracker.record_failure("acc1")
        tracker.record_failure("acc1")
        assert tracker.consecutive_errors["acc1"] == 2

        # Should NOT stop (only 2 consecutive, not 5)
        assert not tracker.should_stop("acc1")

    def test_dead_chats_between_real_errors_prevent_stop(self) -> None:
        """Even with many total errors, dead chats break the consecutive chain."""
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        for _ in range(20):
            # Pattern: 4 real errors, then dead chat resets
            tracker.record_failure("acc1")
            tracker.record_failure("acc1")
            tracker.record_failure("acc1")
            tracker.record_failure("acc1")
            tracker.record_chat_error("acc1")  # resets consecutive

        # Never reached 5 consecutive real errors
        assert not tracker.should_stop("acc1")
        # But total errors are high
        stats = tracker.get_stats("acc1")
        assert stats["total_error"] == 100  # 20 * (4 real + 1 chat)
        assert stats["consecutive_errors"] == 0

    def test_real_errors_after_dead_chats_still_accumulate(self) -> None:
        """Real errors after dead chats accumulate correctly toward threshold."""
        tracker = AccountHealthTracker(max_consecutive_errors=5)

        # Many dead chats first
        for _ in range(10):
            tracker.record_chat_error("acc1")

        # Then real errors hit threshold
        for _ in range(5):
            tracker.record_failure("acc1")

        assert tracker.should_stop("acc1")


class TestRecordChatErrorBehavior:
    """record_chat_error does NOT increment consecutive_errors."""

    def test_record_chat_error_does_not_increment_consecutive(self) -> None:
        """record_chat_error increments total_error but not consecutive_errors."""
        tracker = AccountHealthTracker()

        tracker.record_chat_error("acc1")

        assert tracker.consecutive_errors.get("acc1", 0) == 0
        assert tracker.total_error.get("acc1", 0) == 1

    def test_record_chat_error_resets_consecutive_after_failures(self) -> None:
        """record_chat_error resets consecutive counter even after real failures."""
        tracker = AccountHealthTracker()

        tracker.record_failure("acc1")
        tracker.record_failure("acc1")
        assert tracker.consecutive_errors["acc1"] == 2

        tracker.record_chat_error("acc1")
        assert tracker.consecutive_errors["acc1"] == 0

    def test_record_chat_error_multiple_calls(self) -> None:
        """Multiple record_chat_error calls never increment consecutive."""
        tracker = AccountHealthTracker()

        for _ in range(100):
            tracker.record_chat_error("acc1")

        assert tracker.consecutive_errors.get("acc1", 0) == 0
        assert tracker.total_error["acc1"] == 100
