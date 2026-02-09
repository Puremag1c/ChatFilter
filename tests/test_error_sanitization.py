"""Tests for error message sanitization module."""

from __future__ import annotations

from chatfilter.web.routers.sessions import sanitize_error_message_for_client


class TestSanitizeErrorMessageForClient:
    """Tests for sanitize_error_message_for_client function."""

    def test_safe_message_passes_through(self) -> None:
        """Test that safe messages pass through unchanged."""
        safe_messages = [
            "Connection failed",
            "Network error",
            "Please try again",
            "Invalid credentials",
            "Phone number required",
        ]
        for msg in safe_messages:
            result = sanitize_error_message_for_client(msg, "error")
            assert result == msg, f"Safe message should pass through: {msg}"

    def test_file_path_unix_sanitized(self) -> None:
        """Test that Unix file paths are sanitized."""
        error_message = "File not found: /home/user/sessions/session.session"
        result = sanitize_error_message_for_client(error_message, "error")
        assert result == "An error occurred. Please try again or contact support."
        assert "/home/user" not in result

    def test_file_path_windows_sanitized(self) -> None:
        """Test that Windows file paths are sanitized."""
        error_message = "Cannot access C:\\Users\\Admin\\sessions\\data.json"
        result = sanitize_error_message_for_client(error_message, "error")
        assert result == "An error occurred. Please try again or contact support."
        assert "C:\\" not in result

    def test_stack_trace_sanitized(self) -> None:
        """Test that stack traces are sanitized."""
        error_message = 'Traceback (most recent call last):\n  File "sessions.py", line 123, in connect'
        result = sanitize_error_message_for_client(error_message, "error")
        assert result == "An error occurred. Please try again or contact support."
        assert "Traceback" not in result

    def test_python_file_reference_sanitized(self) -> None:
        """Test that Python file references are sanitized."""
        error_message = 'Error in File "sessions.py", line 456: connection failed'
        result = sanitize_error_message_for_client(error_message, "error")
        assert result == "An error occurred. Please try again or contact support."
        assert "sessions.py" not in result

    def test_line_numbers_sanitized(self) -> None:
        """Test that line numbers are sanitized."""
        error_message = "Error at line 123 in module"
        result = sanitize_error_message_for_client(error_message, "error")
        assert result == "An error occurred. Please try again or contact support."
        assert "line 123" not in result

    def test_error_class_names_sanitized(self) -> None:
        """Test that error class names are sanitized."""
        error_messages = [
            "ValueError: Invalid input",
            "ConnectionError occurred",
            "RuntimeException in handler",
            "AuthenticationError: bad credentials",
        ]
        for msg in error_messages:
            result = sanitize_error_message_for_client(msg, "error")
            assert result == "An error occurred. Please try again or contact support."
            assert "Error" not in result and "Exception" not in result

    def test_internal_ids_sanitized(self) -> None:
        """Test that internal IDs are sanitized."""
        error_message = "Proxy 'abc123-xyz' not found in pool"
        result = sanitize_error_message_for_client(error_message, "proxy_error")
        assert result == "Connection failed. Please check your proxy settings and try again."
        assert "abc123-xyz" not in result

    def test_hex_hashes_sanitized(self) -> None:
        """Test that hex hashes/IDs are sanitized."""
        error_message = "Session 0a1b2c3d4e5f6789 is invalid"
        result = sanitize_error_message_for_client(error_message, "error")
        assert result == "An error occurred. Please try again or contact support."
        assert "0a1b2c3d4e5f6789" not in result

    def test_error_state_specific_fallback(self) -> None:
        """Test that error state determines fallback message."""
        error_message = "ConnectionError at line 123"

        result_proxy = sanitize_error_message_for_client(error_message, "proxy_error")
        assert result_proxy == "Connection failed. Please check your proxy settings and try again."

        result_network = sanitize_error_message_for_client(error_message, "network_error")
        assert result_network == "Network connection error. Please check your internet connection and try again."

        result_timeout = sanitize_error_message_for_client(error_message, "timeout")
        assert result_timeout == "Connection timeout. Please try again."

        result_banned = sanitize_error_message_for_client(error_message, "banned")
        assert result_banned == "Account restricted. Please check your Telegram account status."

    def test_unknown_error_state_fallback(self) -> None:
        """Test that unknown error states use generic fallback."""
        error_message = "ValueError: something went wrong"
        result = sanitize_error_message_for_client(error_message, "unknown_state")
        assert result == "An error occurred. Please try again or contact support."

    def test_multiple_sensitive_patterns(self) -> None:
        """Test message with multiple sensitive patterns."""
        error_message = "ConnectionError in /home/user/app.py line 123: session abc123 failed"
        result = sanitize_error_message_for_client(error_message, "network_error")
        assert result == "Network connection error. Please check your internet connection and try again."
        assert "/home/user" not in result
        assert "line 123" not in result
        assert "abc123" not in result
        assert "ConnectionError" not in result
