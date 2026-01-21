"""Tests for AccountInfo model and subscription limits."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from chatfilter.models import AccountInfo
from chatfilter.models.account import (
    CRITICAL_THRESHOLD,
    PREMIUM_CHAT_LIMIT,
    STANDARD_CHAT_LIMIT,
    WARNING_THRESHOLD,
)


class TestAccountInfoModel:
    """Test AccountInfo model validation and computed properties."""

    def test_valid_account_info(self):
        """Test that valid account info is accepted."""
        info = AccountInfo(
            user_id=123456,
            username="testuser",
            first_name="Test",
            last_name="User",
            is_premium=False,
            chat_count=100,
        )
        assert info.user_id == 123456
        assert info.username == "testuser"
        assert info.first_name == "Test"
        assert info.is_premium is False
        assert info.chat_count == 100

    def test_negative_user_id(self):
        """Test that negative user_id is rejected."""
        with pytest.raises(ValidationError, match="user_id must be positive"):
            AccountInfo(user_id=-1, chat_count=100)

    def test_zero_user_id(self):
        """Test that zero user_id is rejected."""
        with pytest.raises(ValidationError, match="user_id must be positive"):
            AccountInfo(user_id=0, chat_count=100)

    def test_negative_chat_count(self):
        """Test that negative chat_count is rejected."""
        with pytest.raises(ValidationError, match="chat_count cannot be negative"):
            AccountInfo(user_id=123, chat_count=-1)

    def test_optional_fields(self):
        """Test that optional fields can be None."""
        info = AccountInfo(user_id=123)
        assert info.username is None
        assert info.first_name is None
        assert info.last_name is None
        assert info.chat_count == 0


class TestAccountLimits:
    """Test chat subscription limit calculations."""

    def test_standard_chat_limit(self):
        """Test that standard accounts have 500 chat limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=100)
        assert info.chat_limit == STANDARD_CHAT_LIMIT
        assert info.chat_limit == 500

    def test_premium_chat_limit(self):
        """Test that premium accounts have 1000 chat limit."""
        info = AccountInfo(user_id=123, is_premium=True, chat_count=100)
        assert info.chat_limit == PREMIUM_CHAT_LIMIT
        assert info.chat_limit == 1000

    def test_remaining_slots_standard(self):
        """Test remaining slots calculation for standard account."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=450)
        assert info.remaining_slots == 50

    def test_remaining_slots_premium(self):
        """Test remaining slots calculation for premium account."""
        info = AccountInfo(user_id=123, is_premium=True, chat_count=900)
        assert info.remaining_slots == 100

    def test_remaining_slots_at_limit(self):
        """Test remaining slots when at limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=500)
        assert info.remaining_slots == 0

    def test_remaining_slots_over_limit(self):
        """Test remaining slots when over limit (capped at 0)."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=550)
        assert info.remaining_slots == 0


class TestLimitDetection:
    """Test limit threshold detection."""

    def test_is_at_limit_false(self):
        """Test is_at_limit when under limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=400)
        assert info.is_at_limit is False

    def test_is_at_limit_true(self):
        """Test is_at_limit when at limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=500)
        assert info.is_at_limit is True

    def test_is_at_limit_over(self):
        """Test is_at_limit when over limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=600)
        assert info.is_at_limit is True

    def test_is_near_limit_false(self):
        """Test is_near_limit when well under limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=100)
        assert info.is_near_limit is False

    def test_is_near_limit_true(self):
        """Test is_near_limit at 90% threshold."""
        # 90% of 500 = 450
        info = AccountInfo(user_id=123, is_premium=False, chat_count=450)
        assert info.is_near_limit is True

    def test_is_near_limit_just_under_threshold(self):
        """Test is_near_limit just under 90% threshold."""
        # Just under 90% of 500 = 449
        info = AccountInfo(user_id=123, is_premium=False, chat_count=449)
        assert info.is_near_limit is False

    def test_is_critical_false(self):
        """Test is_critical when under critical threshold."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=450)
        assert info.is_critical is False

    def test_is_critical_true(self):
        """Test is_critical at 98% threshold."""
        # 98% of 500 = 490
        info = AccountInfo(user_id=123, is_premium=False, chat_count=490)
        assert info.is_critical is True

    def test_is_critical_premium(self):
        """Test is_critical threshold for premium account."""
        # 98% of 1000 = 980
        info = AccountInfo(user_id=123, is_premium=True, chat_count=980)
        assert info.is_critical is True


class TestUsageCalculation:
    """Test usage percentage calculation."""

    def test_usage_percent_empty(self):
        """Test usage percentage with zero chats."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=0)
        assert info.usage_percent == 0.0

    def test_usage_percent_half(self):
        """Test usage percentage at 50%."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=250)
        assert info.usage_percent == 50.0

    def test_usage_percent_full(self):
        """Test usage percentage at 100%."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=500)
        assert info.usage_percent == 100.0

    def test_usage_percent_over_limit(self):
        """Test usage percentage over 100%."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=600)
        assert info.usage_percent == 120.0


class TestDisplayName:
    """Test display_name computed property."""

    def test_display_name_with_username(self):
        """Test display name when username is set."""
        info = AccountInfo(user_id=123, username="testuser", first_name="Test")
        assert info.display_name == "@testuser"

    def test_display_name_with_first_name_only(self):
        """Test display name when only first_name is set."""
        info = AccountInfo(user_id=123, first_name="Test")
        assert info.display_name == "Test"

    def test_display_name_fallback_to_id(self):
        """Test display name falls back to user_id."""
        info = AccountInfo(user_id=123)
        assert info.display_name == "123"


class TestCanJoinChats:
    """Test can_join_chats method."""

    def test_can_join_single_chat(self):
        """Test can join single chat when under limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=400)
        assert info.can_join_chats(1) is True

    def test_can_join_multiple_chats(self):
        """Test can join multiple chats when enough slots."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=400)
        assert info.can_join_chats(100) is True

    def test_cannot_join_at_limit(self):
        """Test cannot join when at limit."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=500)
        assert info.can_join_chats(1) is False

    def test_cannot_join_insufficient_slots(self):
        """Test cannot join when insufficient slots."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=495)
        assert info.can_join_chats(10) is False

    def test_can_join_exact_slots(self):
        """Test can join when exact number of slots."""
        info = AccountInfo(user_id=123, is_premium=False, chat_count=495)
        assert info.can_join_chats(5) is True


class TestFakeFactory:
    """Test AccountInfo.fake() factory method."""

    def test_fake_default_values(self):
        """Test fake creates valid default account."""
        info = AccountInfo.fake()
        assert info.user_id > 0
        assert info.first_name == "Test"
        assert info.chat_count == 100

    def test_fake_custom_values(self):
        """Test fake accepts custom values."""
        info = AccountInfo.fake(
            user_id=999,
            username="custom",
            is_premium=True,
            chat_count=800,
        )
        assert info.user_id == 999
        assert info.username == "custom"
        assert info.is_premium is True
        assert info.chat_count == 800
        assert info.chat_limit == 1000  # Premium limit


class TestThresholdConstants:
    """Test threshold constants are correctly defined."""

    def test_standard_limit(self):
        """Test standard chat limit constant."""
        assert STANDARD_CHAT_LIMIT == 500

    def test_premium_limit(self):
        """Test premium chat limit constant."""
        assert PREMIUM_CHAT_LIMIT == 1000

    def test_warning_threshold(self):
        """Test warning threshold constant."""
        assert WARNING_THRESHOLD == 0.90

    def test_critical_threshold(self):
        """Test critical threshold constant."""
        assert CRITICAL_THRESHOLD == 0.98
