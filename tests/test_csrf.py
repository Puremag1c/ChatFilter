"""Tests for CSRF protection module.

Tests cover:
- Token generation (format, uniqueness, entropy)
- Token retrieval (creation on demand, persistence)
- Token validation (timing-safe comparison, rejection of invalid tokens)
- Token rotation
"""

from __future__ import annotations

from unittest.mock import MagicMock

from chatfilter.web.csrf import (
    CSRF_SESSION_KEY,
    generate_csrf_token,
    get_csrf_token,
    rotate_csrf_token,
    validate_csrf_token,
)


class TestGenerateCsrfToken:
    """Tests for generate_csrf_token function."""

    def test_returns_string(self) -> None:
        """Token should be a string."""
        token = generate_csrf_token()
        assert isinstance(token, str)

    def test_token_length(self) -> None:
        """Token should be URL-safe base64 encoded 32 bytes (43 chars)."""
        token = generate_csrf_token()
        # 32 bytes in URL-safe base64 = ~43 characters
        assert len(token) >= 40

    def test_tokens_are_unique(self) -> None:
        """Each call should produce a unique token."""
        tokens = [generate_csrf_token() for _ in range(100)]
        assert len(set(tokens)) == 100

    def test_token_is_url_safe(self) -> None:
        """Token should only contain URL-safe characters."""
        token = generate_csrf_token()
        # URL-safe base64 uses A-Z, a-z, 0-9, -, _
        import re

        assert re.match(r"^[A-Za-z0-9_-]+$", token)


class TestGetCsrfToken:
    """Tests for get_csrf_token function."""

    def test_creates_token_if_missing(self) -> None:
        """Should create new token if session doesn't have one."""
        session = MagicMock()
        session.get.return_value = None
        session.session_id = "test-session-12345678"

        token = get_csrf_token(session)

        assert token is not None
        assert isinstance(token, str)
        session.set.assert_called_once()
        # Verify the key used
        call_args = session.set.call_args
        assert call_args[0][0] == CSRF_SESSION_KEY

    def test_returns_existing_token(self) -> None:
        """Should return existing token without modification."""
        session = MagicMock()
        existing_token = "existing-token-abc123"
        session.get.return_value = existing_token

        token = get_csrf_token(session)

        assert token == existing_token
        session.set.assert_not_called()

    def test_stores_generated_token(self) -> None:
        """New token should be stored in session."""
        session = MagicMock()
        session.get.return_value = None
        session.session_id = "test-session-12345678"

        token = get_csrf_token(session)

        session.set.assert_called_once_with(CSRF_SESSION_KEY, token)


class TestValidateCsrfToken:
    """Tests for validate_csrf_token function."""

    def test_valid_token(self) -> None:
        """Should return True for matching token."""
        session = MagicMock()
        token = "valid-token-xyz789"
        session.get.return_value = token
        session.session_id = "test-session-12345678"

        result = validate_csrf_token(session, token)

        assert result is True

    def test_invalid_token(self) -> None:
        """Should return False for non-matching token."""
        session = MagicMock()
        session.get.return_value = "expected-token"
        session.session_id = "test-session-12345678"

        result = validate_csrf_token(session, "wrong-token")

        assert result is False

    def test_missing_session_token(self) -> None:
        """Should return False if session has no token."""
        session = MagicMock()
        session.get.return_value = None
        session.session_id = "test-session-12345678"

        result = validate_csrf_token(session, "any-token")

        assert result is False

    def test_empty_submitted_token(self) -> None:
        """Should return False for empty token."""
        session = MagicMock()
        session.get.return_value = "expected-token"
        session.session_id = "test-session-12345678"

        result = validate_csrf_token(session, "")

        assert result is False

    def test_timing_safe_comparison(self) -> None:
        """Validation should use constant-time comparison.

        This test verifies behavior, not timing (timing tests are unreliable).
        The implementation uses secrets.compare_digest which is timing-safe.
        """
        session = MagicMock()
        token = generate_csrf_token()
        session.get.return_value = token
        session.session_id = "test-session-12345678"

        # Should work correctly with valid token
        assert validate_csrf_token(session, token) is True

        # Should reject with different token
        assert validate_csrf_token(session, token + "x") is False


class TestRotateCsrfToken:
    """Tests for rotate_csrf_token function."""

    def test_generates_new_token(self) -> None:
        """Should generate a new token."""
        session = MagicMock()
        session.session_id = "test-session-12345678"
        old_token = "old-token-123"

        new_token = rotate_csrf_token(session)

        assert new_token != old_token
        assert isinstance(new_token, str)
        assert len(new_token) >= 40

    def test_stores_new_token(self) -> None:
        """New token should be stored in session."""
        session = MagicMock()
        session.session_id = "test-session-12345678"

        new_token = rotate_csrf_token(session)

        session.set.assert_called_once_with(CSRF_SESSION_KEY, new_token)

    def test_returns_new_token(self) -> None:
        """Should return the new token."""
        session = MagicMock()
        session.session_id = "test-session-12345678"

        result = rotate_csrf_token(session)

        # Verify returned token matches stored token
        stored_token = session.set.call_args[0][1]
        assert result == stored_token

    def test_subsequent_rotations_different(self) -> None:
        """Multiple rotations should produce different tokens."""
        session = MagicMock()
        session.session_id = "test-session-12345678"

        tokens = [rotate_csrf_token(session) for _ in range(10)]

        assert len(set(tokens)) == 10


class TestCsrfIntegration:
    """Integration tests for CSRF workflow."""

    def test_full_csrf_flow(self) -> None:
        """Test complete CSRF token lifecycle."""
        from chatfilter.web.session import SessionData

        # Create a real session
        session = SessionData(session_id="integration-test-session")

        # Get initial token (should create)
        token1 = get_csrf_token(session)
        assert token1 is not None

        # Get again (should return same)
        token2 = get_csrf_token(session)
        assert token2 == token1

        # Validate correct token
        assert validate_csrf_token(session, token1) is True

        # Validate incorrect token
        assert validate_csrf_token(session, "wrong-token") is False

        # Rotate
        new_token = rotate_csrf_token(session)
        assert new_token != token1

        # Old token should now be invalid
        assert validate_csrf_token(session, token1) is False

        # New token should be valid
        assert validate_csrf_token(session, new_token) is True
