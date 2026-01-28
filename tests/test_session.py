"""Tests for server-side session management.

Tests cover:
- SessionData: get/set/delete/clear, expiration, touch
- SessionStore: create, get, delete, cleanup, thread-safety
- get_session_store: singleton behavior
- get_session: request integration
- Cookie helpers: set_session_cookie, delete_session_cookie
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from chatfilter.web.session import (
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    SessionData,
    SessionStore,
    delete_session_cookie,
    get_session,
    get_session_store,
    set_session_cookie,
)


class TestSessionData:
    """Tests for SessionData dataclass."""

    def test_creation(self) -> None:
        """SessionData should initialize with correct defaults."""
        session = SessionData(session_id="test-123")

        assert session.session_id == "test-123"
        assert session.data == {}
        assert session.created_at > 0
        assert session.last_accessed > 0

    def test_get_missing_key(self) -> None:
        """get() should return default for missing keys."""
        session = SessionData(session_id="test")

        assert session.get("missing") is None
        assert session.get("missing", "default") == "default"

    def test_get_existing_key(self) -> None:
        """get() should return stored value."""
        session = SessionData(session_id="test")
        session.data["key"] = "value"

        assert session.get("key") == "value"

    def test_set(self) -> None:
        """set() should store value and touch session."""
        session = SessionData(session_id="test")
        old_accessed = session.last_accessed

        time.sleep(0.01)
        session.set("key", "value")

        assert session.get("key") == "value"
        assert session.last_accessed >= old_accessed

    def test_delete(self) -> None:
        """delete() should remove key and touch session."""
        session = SessionData(session_id="test")
        session.data["key"] = "value"

        session.delete("key")

        assert session.get("key") is None

    def test_delete_missing_key(self) -> None:
        """delete() should not raise for missing key."""
        session = SessionData(session_id="test")

        session.delete("nonexistent")  # Should not raise

    def test_clear(self) -> None:
        """clear() should remove all data and touch session."""
        session = SessionData(session_id="test")
        session.data["a"] = 1
        session.data["b"] = 2

        session.clear()

        assert session.data == {}

    def test_touch(self) -> None:
        """touch() should update last_accessed."""
        session = SessionData(session_id="test")
        old_accessed = session.last_accessed

        time.sleep(0.01)
        session.touch()

        assert session.last_accessed > old_accessed

    def test_is_expired_false(self) -> None:
        """is_expired() should return False for fresh session."""
        session = SessionData(session_id="test")

        assert session.is_expired() is False

    def test_is_expired_true(self) -> None:
        """is_expired() should return True for old session."""
        session = SessionData(session_id="test")
        session.last_accessed = time.time() - SESSION_TTL - 1

        assert session.is_expired() is True

    def test_is_expired_custom_ttl(self) -> None:
        """is_expired() should respect custom TTL."""
        session = SessionData(session_id="test")
        session.last_accessed = time.time() - 10

        assert session.is_expired(ttl=5) is True
        assert session.is_expired(ttl=20) is False


class TestSessionStore:
    """Tests for SessionStore class."""

    def test_create_session(self) -> None:
        """create_session() should create new session with unique ID."""
        store = SessionStore()

        session = store.create_session()

        assert session is not None
        assert isinstance(session.session_id, str)
        assert len(session.session_id) >= 40

    def test_create_session_unique_ids(self) -> None:
        """Each created session should have unique ID."""
        store = SessionStore()

        sessions = [store.create_session() for _ in range(100)]
        ids = [s.session_id for s in sessions]

        assert len(set(ids)) == 100

    def test_get_session_existing(self) -> None:
        """get_session() should return existing session."""
        store = SessionStore()
        created = store.create_session()

        retrieved = store.get_session(created.session_id)

        assert retrieved is not None
        assert retrieved.session_id == created.session_id

    def test_get_session_touches(self) -> None:
        """get_session() should touch the session."""
        store = SessionStore()
        session = store.create_session()
        old_accessed = session.last_accessed

        time.sleep(0.01)
        store.get_session(session.session_id)

        assert session.last_accessed > old_accessed

    def test_get_session_missing(self) -> None:
        """get_session() should return None for missing ID."""
        store = SessionStore()

        result = store.get_session("nonexistent-id")

        assert result is None

    def test_get_session_expired(self) -> None:
        """get_session() should return None for expired session."""
        store = SessionStore()
        session = store.create_session()
        session.last_accessed = time.time() - SESSION_TTL - 1

        result = store.get_session(session.session_id)

        assert result is None

    def test_delete_session(self) -> None:
        """delete_session() should remove session."""
        store = SessionStore()
        session = store.create_session()

        store.delete_session(session.session_id)

        assert store.get_session(session.session_id) is None

    def test_delete_session_missing(self) -> None:
        """delete_session() should not raise for missing ID."""
        store = SessionStore()

        store.delete_session("nonexistent-id")  # Should not raise

    def test_cleanup_expired(self) -> None:
        """cleanup_expired() should remove expired sessions."""
        store = SessionStore()
        fresh = store.create_session()
        expired = store.create_session()
        expired.last_accessed = time.time() - SESSION_TTL - 1

        removed = store.cleanup_expired()

        assert removed == 1
        assert store.get_session(fresh.session_id) is not None
        assert store.get_session(expired.session_id) is None

    def test_get_session_count(self) -> None:
        """get_session_count() should return correct count."""
        store = SessionStore()

        assert store.get_session_count() == 0

        store.create_session()
        assert store.get_session_count() == 1

        store.create_session()
        assert store.get_session_count() == 2

    def test_thread_safety(self) -> None:
        """Store should handle concurrent access."""
        import threading

        store = SessionStore()
        errors: list[Exception] = []
        sessions: list[SessionData] = []

        def create_and_access() -> None:
            try:
                session = store.create_session()
                sessions.append(session)
                for _ in range(10):
                    store.get_session(session.session_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_and_access) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(sessions) == 10


class TestGetSessionStore:
    """Tests for get_session_store singleton."""

    def test_returns_store(self) -> None:
        """get_session_store() should return SessionStore instance."""
        store = get_session_store()

        assert isinstance(store, SessionStore)

    def test_singleton(self) -> None:
        """get_session_store() should return same instance."""
        store1 = get_session_store()
        store2 = get_session_store()

        assert store1 is store2


class TestGetSession:
    """Tests for get_session function."""

    def test_creates_new_session(self) -> None:
        """Should create new session if no cookie."""
        request = MagicMock()
        request.cookies = {}
        request.state = MagicMock(spec=[])  # No session attribute

        session = get_session(request)

        assert session is not None
        assert isinstance(session.session_id, str)

    def test_returns_existing_session_from_state(self) -> None:
        """Should return session from request.state if present."""
        existing_session = SessionData(session_id="existing-123")
        request = MagicMock()
        request.state.session = existing_session

        session = get_session(request)

        assert session is existing_session

    def test_returns_session_from_cookie(self) -> None:
        """Should return session from cookie if valid."""
        store = get_session_store()
        stored = store.create_session()

        request = MagicMock()
        request.cookies = {SESSION_COOKIE_NAME: stored.session_id}
        request.state = MagicMock(spec=[])  # No session attribute

        session = get_session(request)

        assert session.session_id == stored.session_id

    def test_creates_new_if_cookie_invalid(self) -> None:
        """Should create new session if cookie ID is invalid."""
        request = MagicMock()
        request.cookies = {SESSION_COOKIE_NAME: "invalid-session-id"}
        request.state = MagicMock(spec=[])

        session = get_session(request)

        assert session is not None
        assert session.session_id != "invalid-session-id"

    def test_attaches_to_request_state(self) -> None:
        """Should store session in request.state."""
        request = MagicMock()
        request.cookies = {}
        request.state = MagicMock(spec=[])

        session = get_session(request)

        assert request.state.session is session


class TestSetSessionCookie:
    """Tests for set_session_cookie function."""

    def test_sets_cookie(self) -> None:
        """Should set cookie with session ID."""
        response = MagicMock()
        session = SessionData(session_id="test-session-xyz")

        set_session_cookie(response, session)

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args[1]
        assert call_kwargs["key"] == SESSION_COOKIE_NAME
        assert call_kwargs["value"] == "test-session-xyz"

    def test_cookie_security_settings(self) -> None:
        """Cookie should have secure settings."""
        response = MagicMock()
        session = SessionData(session_id="test")

        set_session_cookie(response, session)

        call_kwargs = response.set_cookie.call_args[1]
        assert call_kwargs["httponly"] is True
        assert call_kwargs["samesite"] == "lax"
        assert call_kwargs["max_age"] == SESSION_TTL


class TestDeleteSessionCookie:
    """Tests for delete_session_cookie function."""

    def test_deletes_cookie(self) -> None:
        """Should delete the session cookie."""
        response = MagicMock()

        delete_session_cookie(response)

        response.delete_cookie.assert_called_once_with(key=SESSION_COOKIE_NAME)


class TestSessionIntegration:
    """Integration tests for session workflow."""

    def test_full_session_lifecycle(self) -> None:
        """Test complete session lifecycle."""
        store = SessionStore()

        # Create session
        session = store.create_session()
        session_id = session.session_id

        # Store data
        session.set("user_id", 123)
        session.set("preferences", {"theme": "dark"})

        # Retrieve and verify
        retrieved = store.get_session(session_id)
        assert retrieved is not None
        assert retrieved.get("user_id") == 123
        assert retrieved.get("preferences") == {"theme": "dark"}

        # Modify data
        retrieved.set("user_id", 456)
        assert store.get_session(session_id).get("user_id") == 456

        # Delete
        store.delete_session(session_id)
        assert store.get_session(session_id) is None

    def test_multiple_independent_sessions(self) -> None:
        """Multiple sessions should be independent."""
        store = SessionStore()

        session1 = store.create_session()
        session2 = store.create_session()

        session1.set("value", "session1")
        session2.set("value", "session2")

        assert store.get_session(session1.session_id).get("value") == "session1"
        assert store.get_session(session2.session_id).get("value") == "session2"
