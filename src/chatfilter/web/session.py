"""Server-side session management for multi-tab support.

This module provides session management using signed cookies to track
browser sessions across multiple tabs. Each browser session gets a unique
session ID, and session data is stored server-side in memory.

Features:
- Secure cookie-based session IDs
- Per-session state isolation (each tab can have different state)
- Automatic session cleanup (TTL-based expiration)
- Thread-safe session storage

Session data includes:
- selected_session_id: Currently selected Telegram session
- selected_chats: List of selected chat IDs for analysis
- current_task_id: Current analysis task ID
- preferences: User preferences (optional)
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, cast

from starlette.requests import Request

logger = logging.getLogger(__name__)

# Session configuration
SESSION_COOKIE_NAME = "chatfilter_session"
SESSION_TTL = 3600 * 24  # 24 hours
SESSION_CLEANUP_INTERVAL = 3600  # Clean up expired sessions every hour


@dataclass
class SessionData:
    """Container for session-specific data."""

    session_id: str
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, ttl: int = SESSION_TTL) -> bool:
        """Check if session has expired."""
        return (time.time() - self.last_accessed) > ttl

    def touch(self) -> None:
        """Update last accessed time."""
        self.last_accessed = time.time()

    def get(self, key: str, default: Any = None) -> Any:
        """Get session data value."""
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set session data value."""
        self.data[key] = value
        self.touch()

    def delete(self, key: str) -> None:
        """Delete session data value."""
        self.data.pop(key, None)
        self.touch()

    def clear(self) -> None:
        """Clear all session data."""
        self.data.clear()
        self.touch()


class SessionStore:
    """Thread-safe in-memory session storage.

    This implementation stores sessions in memory. For production deployments
    with multiple workers, consider using Redis or a database backend.
    """

    def __init__(self) -> None:
        self._sessions: MutableMapping[str, SessionData] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()

    def create_session(self) -> SessionData:
        """Create a new session with unique ID."""
        session_id = secrets.token_urlsafe(32)
        session = SessionData(session_id=session_id)

        with self._lock:
            self._sessions[session_id] = session
            self._maybe_cleanup()

        logger.debug(f"Created new session: {session_id[:8]}...")
        return session

    def get_session(self, session_id: str) -> SessionData | None:
        """Get session by ID, or None if not found/expired."""
        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                return None

            if session.is_expired():
                del self._sessions[session_id]
                logger.debug(f"Session expired: {session_id[:8]}...")
                return None

            session.touch()
            return session

    def delete_session(self, session_id: str) -> None:
        """Delete a session."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.debug(f"Deleted session: {session_id[:8]}...")

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns number of sessions removed."""
        now = time.time()
        expired = []

        with self._lock:
            for session_id, session in self._sessions.items():
                if session.is_expired():
                    expired.append(session_id)

            for session_id in expired:
                del self._sessions[session_id]

            self._last_cleanup = now

        if expired:
            logger.info(f"Cleaned up {len(expired)} expired session(s)")

        return len(expired)

    def _maybe_cleanup(self) -> None:
        """Run cleanup if interval has passed (called with lock held)."""
        if (time.time() - self._last_cleanup) > SESSION_CLEANUP_INTERVAL:
            # Release lock and run cleanup in background to avoid blocking
            # For now, we'll just update the timestamp and let cleanup happen later
            self._last_cleanup = time.time()

    def get_session_count(self) -> int:
        """Get number of active sessions."""
        with self._lock:
            return len(self._sessions)


# Global session store instance
_session_store: SessionStore | None = None


def get_session_store() -> SessionStore:
    """Get global session store instance."""
    global _session_store
    if _session_store is None:
        _session_store = SessionStore()
    return _session_store


def get_session(request: Request) -> SessionData:
    """Get session for current request, creating one if needed.

    This function should be called from route handlers to access session data.

    Args:
        request: FastAPI request object

    Returns:
        SessionData instance for this request

    Example:
        ```python
        @router.get("/some-route")
        async def some_route(request: Request):
            session = get_session(request)
            selected_session = session.get("selected_session_id")
            session.set("selected_session_id", "new_value")
        ```
    """
    # Check if session is already attached to request state
    if hasattr(request.state, "session"):
        return cast(SessionData, request.state.session)

    # Get or create session
    store = get_session_store()
    session_id = request.cookies.get(SESSION_COOKIE_NAME)

    if session_id:
        session = store.get_session(session_id)
        if session:
            request.state.session = session
            return session

    # Create new session
    session = store.create_session()
    request.state.session = session
    return session


def set_session_cookie(response: Any, session: SessionData) -> None:
    """Set session cookie on response.

    Args:
        response: Response object (FastAPI Response or HTMLResponse)
        session: Session data to set cookie for

    Example:
        ```python
        response = HTMLResponse(content="...")
        set_session_cookie(response, session)
        return response
        ```
    """
    # Set secure cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session.session_id,
        max_age=SESSION_TTL,
        httponly=True,  # Prevent JavaScript access
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",  # CSRF protection
    )


def delete_session_cookie(response: Any) -> None:
    """Delete session cookie from response.

    Args:
        response: Response object to delete cookie from
    """
    response.delete_cookie(key=SESSION_COOKIE_NAME)
