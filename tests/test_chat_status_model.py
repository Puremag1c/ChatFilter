"""Phase 0 — tests for the orthogonal chat-status / chat-type model.

This file documents the business rules via tests:

    Axis 1 — process:  GroupChatStatus = {PENDING, DONE, ERROR}
    Axis 2 — result:   ChatTypeEnum = {PENDING, GROUP, FORUM,
                                       CHANNEL_COMMENTS, CHANNEL_NO_COMMENTS,
                                       DEAD, BANNED, RESTRICTED, PRIVATE}

Invariants:
    - DONE means "Telegram responded" regardless of chat_type.
    - ERROR means "network/crash", not billable, retriable.
    - Billing charges on status == DONE only.
    - Retry targets status == ERROR only.
    - DEAD/BANNED/PRIVATE/RESTRICTED are *results*, not errors.
"""

from __future__ import annotations

import pytest

from chatfilter.models.group import (
    BILLABLE_STATUSES,
    RETRIABLE_STATUSES,
    TERMINAL_STATUSES,
    UNUSABLE_CHAT_TYPES,
    ChatTypeEnum,
    GroupChatStatus,
)


class TestEnumShape:
    def test_all_new_chat_types_present(self) -> None:
        """Phase 0 adds BANNED, RESTRICTED, PRIVATE. Existing values stay."""
        names = {m.name for m in ChatTypeEnum}
        assert {"BANNED", "RESTRICTED", "PRIVATE"}.issubset(names)
        # historical compatibility: DEAD, GROUP, FORUM, CHANNEL_COMMENTS,
        # CHANNEL_NO_COMMENTS, PENDING must still exist
        assert {"DEAD", "GROUP", "FORUM", "CHANNEL_COMMENTS",
                "CHANNEL_NO_COMMENTS", "PENDING"}.issubset(names)

    def test_group_chat_status_is_only_three(self) -> None:
        """Status remains PENDING/DONE/ERROR. No dead/banned here."""
        assert {m.name for m in GroupChatStatus} == {"PENDING", "DONE", "ERROR"}


class TestBillableRules:
    def test_only_done_is_billable(self) -> None:
        assert BILLABLE_STATUSES == {GroupChatStatus.DONE}

    def test_error_not_billable(self) -> None:
        assert GroupChatStatus.ERROR not in BILLABLE_STATUSES

    def test_pending_not_billable(self) -> None:
        assert GroupChatStatus.PENDING not in BILLABLE_STATUSES

    @pytest.mark.parametrize(
        "chat_type",
        [
            ChatTypeEnum.GROUP,
            ChatTypeEnum.FORUM,
            ChatTypeEnum.CHANNEL_COMMENTS,
            ChatTypeEnum.CHANNEL_NO_COMMENTS,
            ChatTypeEnum.DEAD,
            ChatTypeEnum.BANNED,
            ChatTypeEnum.RESTRICTED,
            ChatTypeEnum.PRIVATE,
        ],
    )
    def test_done_billable_regardless_of_chat_type(
        self, chat_type: ChatTypeEnum
    ) -> None:
        """DONE is billable for every chat_type — including dead/banned/etc.

        Business rule: if Telegram gave us an answer (the chat is dead,
        banned, private, a channel, a forum — whatever), the service
        was delivered and must be charged.
        """
        # Axis orthogonality: result-type does not influence billability.
        assert (GroupChatStatus.DONE in BILLABLE_STATUSES) is True


class TestRetriableRules:
    def test_only_error_is_retriable(self) -> None:
        assert RETRIABLE_STATUSES == {GroupChatStatus.ERROR}

    def test_done_not_retriable(self) -> None:
        """DEAD/BANNED/PRIVATE/RESTRICTED are final answers — no retry."""
        assert GroupChatStatus.DONE not in RETRIABLE_STATUSES


class TestUnusableChatTypes:
    def test_contains_all_four_unusable(self) -> None:
        assert UNUSABLE_CHAT_TYPES == {
            ChatTypeEnum.DEAD,
            ChatTypeEnum.BANNED,
            ChatTypeEnum.RESTRICTED,
            ChatTypeEnum.PRIVATE,
        }

    @pytest.mark.parametrize(
        "chat_type",
        [
            ChatTypeEnum.GROUP,
            ChatTypeEnum.FORUM,
            ChatTypeEnum.CHANNEL_COMMENTS,
            ChatTypeEnum.CHANNEL_NO_COMMENTS,
        ],
    )
    def test_usable_types_not_in_set(self, chat_type: ChatTypeEnum) -> None:
        assert chat_type not in UNUSABLE_CHAT_TYPES


class TestTerminalStatuses:
    def test_done_and_error_both_terminal(self) -> None:
        assert TERMINAL_STATUSES == {GroupChatStatus.DONE, GroupChatStatus.ERROR}

    def test_pending_not_terminal(self) -> None:
        assert GroupChatStatus.PENDING not in TERMINAL_STATUSES
