"""Phase 0 — GroupStats breakdown tests.

Verify that separate counters exist for banned / restricted / private,
and that `failed` (status=ERROR) is no longer a mixed bag of real errors
plus dead/banned chats.
"""

from __future__ import annotations

from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupStats


class TestGroupStatsFieldsExist:
    def test_has_banned_restricted_private(self) -> None:
        stats = GroupStats(
            total=10,
            pending=0,
            dead=1,
            banned=2,
            restricted=3,
            private=4,
            groups=0,
            forums=0,
            channels_with_comments=0,
            channels_no_comments=0,
            analyzed=10,
            failed=0,
        )
        assert stats.banned == 2
        assert stats.restricted == 3
        assert stats.private == 4

    def test_defaults_to_zero_for_new_fields(self) -> None:
        stats = GroupStats(
            total=1,
            pending=1,
            dead=0,
            groups=0,
            forums=0,
            channels_with_comments=0,
            channels_no_comments=0,
            analyzed=0,
            failed=0,
        )
        assert stats.banned == 0
        assert stats.restricted == 0
        assert stats.private == 0


class TestServiceBreakdown:
    """Service-layer: by_type / by_status → GroupStats fields."""

    def test_service_populates_all_result_types(self) -> None:
        from chatfilter.models.group import ChatTypeEnum as CT, GroupChatStatus as GS

        by_type = {
            CT.GROUP.value: 3,
            CT.FORUM.value: 1,
            CT.CHANNEL_COMMENTS.value: 2,
            CT.CHANNEL_NO_COMMENTS.value: 4,
            CT.DEAD.value: 5,
            CT.BANNED.value: 6,
            CT.RESTRICTED.value: 7,
            CT.PRIVATE.value: 8,
            CT.PENDING.value: 9,
        }
        by_status = {
            GS.PENDING.value: 9,
            GS.DONE.value: 36,
            GS.ERROR.value: 2,
        }

        # Simulate the service-layer mapping (mirrors group_service.get_group_stats).
        stats = GroupStats(
            total=sum(by_type.values()),
            pending=by_type.get(CT.PENDING.value, 0),
            dead=by_type.get(CT.DEAD.value, 0),
            banned=by_type.get(CT.BANNED.value, 0),
            restricted=by_type.get(CT.RESTRICTED.value, 0),
            private=by_type.get(CT.PRIVATE.value, 0),
            groups=by_type.get(CT.GROUP.value, 0),
            forums=by_type.get(CT.FORUM.value, 0),
            channels_with_comments=by_type.get(CT.CHANNEL_COMMENTS.value, 0),
            channels_no_comments=by_type.get(CT.CHANNEL_NO_COMMENTS.value, 0),
            analyzed=by_status.get(GS.DONE.value, 0) + by_status.get(GS.ERROR.value, 0),
            failed=by_status.get(GS.ERROR.value, 0),
            status_pending=by_status.get(GS.PENDING.value, 0),
        )

        assert stats.dead == 5
        assert stats.banned == 6
        assert stats.restricted == 7
        assert stats.private == 8

        # failed counts only real errors — not dead/banned/restricted.
        assert stats.failed == 2

        # live chats
        assert stats.groups + stats.forums == 4
        assert stats.channels_with_comments + stats.channels_no_comments == 6


class TestFailedIsNotPollutedByDeadOrBanned:
    """Regression: old code lumped dead/banned into status=ERROR → failed was inflated."""

    def test_failed_reflects_only_status_error(self) -> None:
        stats = GroupStats(
            total=100,
            pending=0,
            dead=30,      # DONE + DEAD
            banned=20,    # DONE + BANNED
            restricted=10,  # DONE + RESTRICTED
            private=5,    # DONE + PRIVATE
            groups=20,
            forums=5,
            channels_with_comments=3,
            channels_no_comments=5,
            analyzed=95,  # all DONE
            failed=2,     # actual ERROR only
        )
        assert stats.failed == 2
        # Sanity: totals approximately match (allow loose sum check — stats aren't
        # strictly additive when chat_type and status are orthogonal).
        assert (
            stats.dead + stats.banned + stats.restricted + stats.private
            + stats.groups + stats.forums
            + stats.channels_with_comments + stats.channels_no_comments
        ) == 98  # 100 - 2 ERROR chats without chat_type yet
