"""Tests for Telegram error mapping module."""

from __future__ import annotations

import pytest

from chatfilter.telegram.error_mapping import (
    ERROR_MESSAGES,
    _extract_wait_time,
    _format_duration,
    get_error_category,
    get_user_friendly_message,
    should_retry_on_error,
)


class TestFormatDuration:
    """Tests for _format_duration helper function."""

    def test_format_seconds(self) -> None:
        """Test formatting seconds."""
        assert _format_duration(1) == "1 second"
        assert _format_duration(30) == "30 seconds"
        assert _format_duration(59) == "59 seconds"

    def test_format_minutes(self) -> None:
        """Test formatting minutes."""
        assert _format_duration(60) == "1 minute"
        assert _format_duration(120) == "2 minutes"
        assert _format_duration(1800) == "30 minutes"
        assert _format_duration(3599) == "59 minutes"

    def test_format_hours(self) -> None:
        """Test formatting hours."""
        assert _format_duration(3600) == "1 hour"
        assert _format_duration(7200) == "2 hours"
        assert _format_duration(86400) == "24 hours"


class TestExtractWaitTime:
    """Tests for _extract_wait_time helper function."""

    def test_extract_from_seconds_attribute(self) -> None:
        """Test extracting wait time from exception with seconds attribute."""

        class MockFloodError(Exception):
            def __init__(self, seconds: int) -> None:
                self.seconds = seconds
                super().__init__(f"A wait of {seconds} seconds is required")

        error = MockFloodError(3600)
        assert _extract_wait_time(error) == 3600

    def test_extract_from_error_message(self) -> None:
        """Test extracting wait time from error message."""
        error = Exception("A wait of 120 seconds is required")
        assert _extract_wait_time(error) == 120

        error2 = Exception("Please wait 60 second before retrying")
        assert _extract_wait_time(error2) == 60

    def test_no_wait_time_found(self) -> None:
        """Test when no wait time can be extracted."""
        error = Exception("Some error without wait time")
        assert _extract_wait_time(error) is None


class TestGetUserFriendlyMessage:
    """Tests for get_user_friendly_message function."""

    def test_session_expired_error(self) -> None:
        """Test session expired error mapping."""

        class SessionExpiredError(Exception):
            pass

        error = SessionExpiredError("Session expired")
        msg = get_user_friendly_message(error)
        assert "session has expired" in msg.lower()
        assert "log in again" in msg.lower()

    def test_auth_key_unregistered_error(self) -> None:
        """Test auth key unregistered error mapping."""

        class AuthKeyUnregisteredError(Exception):
            pass

        error = AuthKeyUnregisteredError()
        msg = get_user_friendly_message(error)
        assert "session has expired" in msg.lower() or "revoked" in msg.lower()
        assert "log in again" in msg.lower()

    def test_chat_forbidden_error(self) -> None:
        """Test chat forbidden error mapping."""

        class ChatForbiddenError(Exception):
            pass

        error = ChatForbiddenError()
        msg = get_user_friendly_message(error)
        assert "access" in msg.lower()
        assert "restricted" in msg.lower() or "removed" in msg.lower()

    def test_channel_private_error(self) -> None:
        """Test channel private error mapping."""

        class ChannelPrivateError(Exception):
            pass

        error = ChannelPrivateError()
        msg = get_user_friendly_message(error)
        assert "private" in msg.lower()
        assert "invite link" in msg.lower()

    def test_user_banned_error(self) -> None:
        """Test user banned error mapping."""

        class UserBannedInChannelError(Exception):
            pass

        error = UserBannedInChannelError()
        msg = get_user_friendly_message(error)
        assert "banned" in msg.lower()

    def test_flood_wait_error_with_time(self) -> None:
        """Test FloodWaitError with wait time."""

        class FloodWaitError(Exception):
            def __init__(self, seconds: int) -> None:
                self.seconds = seconds
                super().__init__(f"A wait of {seconds} seconds is required")

        error = FloodWaitError(3600)
        msg = get_user_friendly_message(error)
        assert "rate limit" in msg.lower()
        assert "1 hour" in msg.lower()

    def test_flood_wait_error_short_time(self) -> None:
        """Test FloodWaitError with short wait time."""

        class FloodWaitError(Exception):
            def __init__(self, seconds: int) -> None:
                self.seconds = seconds
                super().__init__(f"A wait of {seconds} seconds is required")

        error = FloodWaitError(30)
        msg = get_user_friendly_message(error)
        assert "rate limit" in msg.lower()
        assert "30 seconds" in msg.lower()

    def test_username_invalid_error(self) -> None:
        """Test username invalid error mapping."""

        class UsernameInvalidError(Exception):
            pass

        error = UsernameInvalidError()
        msg = get_user_friendly_message(error)
        assert "invalid username" in msg.lower()

    def test_invite_hash_expired_error(self) -> None:
        """Test invite hash expired error mapping."""

        class InviteHashExpiredError(Exception):
            pass

        error = InviteHashExpiredError()
        msg = get_user_friendly_message(error)
        assert "expired" in msg.lower()
        assert "invite" in msg.lower()

    def test_timeout_error(self) -> None:
        """Test timeout error mapping."""

        class TimeoutError(Exception):
            pass

        error = TimeoutError("Connection timed out")
        msg = get_user_friendly_message(error)
        assert "timeout" in msg.lower() or "timed out" in msg.lower()
        assert "try again" in msg.lower()

    def test_unknown_error_fallback(self) -> None:
        """Test fallback for unknown error types."""

        class SomeUnknownError(Exception):
            pass

        error = SomeUnknownError("Something went wrong")
        msg = get_user_friendly_message(error)
        # Should include error class name for debugging
        assert "SomeUnknownError" in msg
        assert "error occurred" in msg.lower()

    def test_error_message_pattern_matching_flood(self) -> None:
        """Test pattern matching for flood errors without known class."""

        class GenericError(Exception):
            pass

        error = GenericError("FLOOD_WAIT_120: A wait of 120 seconds is required")
        msg = get_user_friendly_message(error)
        assert "rate limit" in msg.lower()
        assert "2 minutes" in msg.lower()

    def test_error_message_pattern_matching_session(self) -> None:
        """Test pattern matching for session errors without known class."""

        class GenericError(Exception):
            pass

        error = GenericError("Session expired, please login again")
        msg = get_user_friendly_message(error)
        assert "session has expired" in msg.lower()
        assert "log in again" in msg.lower()

    def test_error_message_pattern_matching_banned(self) -> None:
        """Test pattern matching for banned errors without known class."""

        class GenericError(Exception):
            pass

        error = GenericError("User was banned from the chat")
        msg = get_user_friendly_message(error)
        assert "banned" in msg.lower() or "removed" in msg.lower()

    def test_slow_mode_wait_error(self) -> None:
        """Test SlowModeWaitError with wait time."""

        class SlowModeWaitError(Exception):
            def __init__(self, seconds: int) -> None:
                self.seconds = seconds
                super().__init__(f"Slow mode wait of {seconds} seconds")

        error = SlowModeWaitError(60)
        msg = get_user_friendly_message(error)
        assert "slow mode" in msg.lower()
        assert "1 minute" in msg.lower()


class TestGetErrorCategory:
    """Tests for get_error_category function."""

    def test_auth_category(self) -> None:
        """Test authentication error category."""

        class SessionExpiredError(Exception):
            pass

        class AuthKeyUnregisteredError(Exception):
            pass

        assert get_error_category(SessionExpiredError()) == "auth"
        assert get_error_category(AuthKeyUnregisteredError()) == "auth"

    def test_access_category(self) -> None:
        """Test access denied error category."""

        class ChatForbiddenError(Exception):
            pass

        class ChannelPrivateError(Exception):
            pass

        class UserBannedInChannelError(Exception):
            pass

        assert get_error_category(ChatForbiddenError()) == "access"
        assert get_error_category(ChannelPrivateError()) == "access"
        assert get_error_category(UserBannedInChannelError()) == "access"

    def test_rate_limit_category(self) -> None:
        """Test rate limiting error category."""

        class FloodWaitError(Exception):
            pass

        class SlowModeWaitError(Exception):
            pass

        assert get_error_category(FloodWaitError()) == "rate_limit"
        assert get_error_category(SlowModeWaitError()) == "rate_limit"

    def test_network_category(self) -> None:
        """Test network error category."""

        class NetworkError(Exception):
            pass

        class TimeoutError(Exception):
            pass

        class ConnectionError(Exception):
            pass

        assert get_error_category(NetworkError()) == "network"
        assert get_error_category(TimeoutError()) == "network"
        assert get_error_category(ConnectionError()) == "network"

    def test_invalid_input_category(self) -> None:
        """Test invalid input error category."""

        class UsernameInvalidError(Exception):
            pass

        class InviteHashExpiredError(Exception):
            pass

        class PeerIdInvalidError(Exception):
            pass

        assert get_error_category(UsernameInvalidError()) == "invalid_input"
        assert get_error_category(InviteHashExpiredError()) == "invalid_input"
        assert get_error_category(PeerIdInvalidError()) == "invalid_input"

    def test_other_category(self) -> None:
        """Test unknown error category."""

        class SomeUnknownError(Exception):
            pass

        assert get_error_category(SomeUnknownError()) == "other"


class TestShouldRetryOnError:
    """Tests for should_retry_on_error function."""

    def test_retry_network_errors(self) -> None:
        """Test that network errors should be retried."""

        class NetworkError(Exception):
            pass

        class TimeoutError(Exception):
            pass

        assert should_retry_on_error(NetworkError()) is True
        assert should_retry_on_error(TimeoutError()) is True

    def test_no_retry_auth_errors(self) -> None:
        """Test that auth errors should not be retried."""

        class SessionExpiredError(Exception):
            pass

        class AuthKeyUnregisteredError(Exception):
            pass

        assert should_retry_on_error(SessionExpiredError()) is False
        assert should_retry_on_error(AuthKeyUnregisteredError()) is False

    def test_no_retry_access_errors(self) -> None:
        """Test that access errors should not be retried."""

        class ChatForbiddenError(Exception):
            pass

        class UserBannedInChannelError(Exception):
            pass

        assert should_retry_on_error(ChatForbiddenError()) is False
        assert should_retry_on_error(UserBannedInChannelError()) is False

    def test_no_retry_invalid_input(self) -> None:
        """Test that invalid input errors should not be retried."""

        class UsernameInvalidError(Exception):
            pass

        class InviteHashExpiredError(Exception):
            pass

        assert should_retry_on_error(UsernameInvalidError()) is False
        assert should_retry_on_error(InviteHashExpiredError()) is False

    def test_retry_flood_wait(self) -> None:
        """Test that FloodWait errors can be retried (with wait)."""

        class FloodWaitError(Exception):
            pass

        assert should_retry_on_error(FloodWaitError()) is True

    def test_retry_slow_mode(self) -> None:
        """Test that SlowMode errors can be retried (with wait)."""

        class SlowModeWaitError(Exception):
            pass

        assert should_retry_on_error(SlowModeWaitError()) is True

    def test_no_retry_unknown_errors(self) -> None:
        """Test that unknown errors should not be retried by default."""

        class UnknownError(Exception):
            pass

        assert should_retry_on_error(UnknownError()) is False


class TestErrorMessagesCoverage:
    """Tests to ensure ERROR_MESSAGES dict is comprehensive."""

    def test_all_error_messages_are_non_empty(self) -> None:
        """Test that all error messages in the dict are non-empty strings."""
        for error_type, message in ERROR_MESSAGES.items():
            assert isinstance(message, str), f"Message for {error_type} is not a string"
            assert len(message) > 0, f"Message for {error_type} is empty"
            assert len(message) < 500, f"Message for {error_type} is too long (>500 chars)"

    def test_error_messages_are_user_friendly(self) -> None:
        """Test that error messages don't contain technical jargon."""
        technical_terms = ["exception", "traceback", "stack", "null", "undefined"]

        for error_type, message in ERROR_MESSAGES.items():
            msg_lower = message.lower()
            for term in technical_terms:
                assert (
                    term not in msg_lower
                ), f"Message for {error_type} contains technical term '{term}': {message}"

    def test_error_messages_provide_guidance(self) -> None:
        """Test that error messages provide actionable guidance."""
        # Most messages should tell user what to do
        guidance_keywords = [
            "please",
            "try",
            "contact",
            "check",
            "wait",
            "verify",
            "request",
            "upload",
            "log in",
        ]

        messages_without_guidance = []
        for error_type, message in ERROR_MESSAGES.items():
            msg_lower = message.lower()
            has_guidance = any(keyword in msg_lower for keyword in guidance_keywords)
            if not has_guidance:
                messages_without_guidance.append((error_type, message))

        # Allow some messages to not have guidance (descriptive errors)
        # Some errors are inherently descriptive (e.g., "You have been banned")
        # and don't need actionable guidance, so we allow up to 50%
        assert (
            len(messages_without_guidance) < len(ERROR_MESSAGES) * 0.5
        ), f"Too many messages without guidance: {messages_without_guidance}"

    def test_coverage_of_common_telegram_errors(self) -> None:
        """Test that common Telegram errors are covered."""
        common_errors = [
            "FloodWaitError",  # Rate limiting (handled specially)
            "SessionExpiredError",
            "AuthKeyUnregisteredError",
            "ChatForbiddenError",
            "ChannelPrivateError",
            "UserBannedInChannelError",
            "UsernameInvalidError",
            "InviteHashExpiredError",
            "TimeoutError",
        ]

        for error in common_errors:
            # Should be in ERROR_MESSAGES or handled specially in get_user_friendly_message
            if error == "FloodWaitError":
                # This is handled specially in the function
                continue
            assert (
                error in ERROR_MESSAGES
            ), f"Common Telegram error '{error}' is not in ERROR_MESSAGES"
