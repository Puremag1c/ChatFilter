"""Server-side session management for multi-tab support.

This module provides session management using signed cookies to track
browser sessions across multiple tabs. Each browser session gets a unique
session ID, and session data is stored server-side in SQLite.

Features:
- Secure cookie-based session IDs
- Per-session state isolation (each tab can have different state)
- Automatic session cleanup (TTL-based expiration)
- Thread-safe session storage
- Persistent storage: sessions survive server restarts

Session data includes:
- selected_session_id: Currently selected Telegram session
- selected_chats: List of selected chat IDs for analysis
- current_task_id: Current analysis task ID
- preferences: User preferences (optional)
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, cast

from sqlalchemy import text
from starlette.requests import Request

from chatfilter.storage.engine import create_db_engine

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
    _save_callback: Any = field(default=None, repr=False, compare=False, init=False)

    def is_expired(self, ttl: int = SESSION_TTL) -> bool:
        """Check if session has expired."""
        return (time.time() - self.last_accessed) > ttl

    def touch(self) -> None:
        """Update last accessed time."""
        self.last_accessed = time.time()
        if self._save_callback is not None:
            self._save_callback(self)

    def get(self, key: str, default: Any = None) -> Any:
        """Get session data value."""
        return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set session data value."""
        self.data[key] = value
        self.last_accessed = time.time()
        if self._save_callback is not None:
            self._save_callback(self)

    def delete(self, key: str) -> None:
        """Delete session data value."""
        self.data.pop(key, None)
        self.last_accessed = time.time()
        if self._save_callback is not None:
            self._save_callback(self)

    def clear(self) -> None:
        """Clear all session data."""
        self.data.clear()
        self.last_accessed = time.time()
        if self._save_callback is not None:
            self._save_callback(self)


_CREATE_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_accessed REAL NOT NULL
)
"""

_CREATE_SESSIONS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions (last_accessed)
"""


class SessionStore:
    """SQLite-backed session storage that also caches sessions in memory.

    Sessions are persisted to SQLite so they survive server restarts.
    An in-memory dict acts as a write-through cache for fast access.
    """

    def __init__(self, db_url: str = "sqlite:///:memory:") -> None:
        self._sessions: dict[str, SessionData] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()
        self._engine = create_db_engine(db_url)
        self._init_table()

    def _init_table(self) -> None:
        """Ensure sessions table exists (idempotent)."""
        with self._engine.connect() as conn:
            conn.execute(text(_CREATE_SESSIONS_TABLE))
            conn.execute(text(_CREATE_SESSIONS_INDEX))
            conn.commit()

    def _upsert(self, conn: Any, session: SessionData) -> None:
        """Write session to DB (INSERT OR REPLACE)."""
        conn.execute(
            text(
                "INSERT OR REPLACE INTO sessions (session_id, data, created_at, last_accessed)"
                " VALUES (:sid, :data, :cat, :lat)"
            ),
            {
                "sid": session.session_id,
                "data": json.dumps(session.data),
                "cat": session.created_at,
                "lat": session.last_accessed,
            },
        )

    def _persist(self, session: SessionData) -> None:
        """Write-through callback — called by SessionData on every mutation."""
        with self._engine.connect() as conn:
            self._upsert(conn, session)
            conn.commit()

    def _load_from_db(self, session_id: str) -> SessionData | None:
        """Load a single session from DB. Returns None if not found."""
        with self._engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT session_id, data, created_at, last_accessed"
                    " FROM sessions WHERE session_id = :sid"
                ),
                {"sid": session_id},
            ).fetchone()
        if row is None:
            return None
        session = SessionData(
            session_id=row[0],
            data=json.loads(row[1]),
            created_at=row[2],
            last_accessed=row[3],
        )
        session._save_callback = self._persist
        return session

    def create_session(self) -> SessionData:
        """Create a new session with unique ID."""
        session_id = secrets.token_urlsafe(32)
        session = SessionData(session_id=session_id)
        session._save_callback = self._persist

        with self._lock:
            self._sessions[session_id] = session
            self._persist(session)
            self._maybe_cleanup()

        logger.debug(f"Created new session: {session_id[:8]}...")
        return session

    def get_session(self, session_id: str) -> SessionData | None:
        """Get session by ID, or None if not found/expired."""
        with self._lock:
            session = self._sessions.get(session_id)

            if session is None:
                # Not in memory — try DB (e.g. after server restart)
                session = self._load_from_db(session_id)
                if session is not None:
                    self._sessions[session_id] = session

            if session is None:
                return None

            if session.is_expired():
                del self._sessions[session_id]
                self._delete_from_db(session_id)
                logger.debug(f"Session expired: {session_id[:8]}...")
                return None

            session.touch()
            return session

    def delete_session(self, session_id: str) -> None:
        """Delete a session."""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._delete_from_db(session_id)
            logger.debug(f"Deleted session: {session_id[:8]}...")

    def _delete_from_db(self, session_id: str) -> None:
        with self._engine.connect() as conn:
            conn.execute(
                text("DELETE FROM sessions WHERE session_id = :sid"),
                {"sid": session_id},
            )
            conn.commit()

    def cleanup_expired(self) -> int:
        """Remove expired sessions. Returns number of sessions removed."""
        now = time.time()
        cutoff = now - SESSION_TTL
        expired = []

        with self._lock:
            for session_id, session in list(self._sessions.items()):
                if session.is_expired():
                    expired.append(session_id)

            for session_id in expired:
                del self._sessions[session_id]

            with self._engine.connect() as conn:
                # Delete expired in-memory sessions by ID — handles direct
                # last_accessed mutation that bypasses the save callback
                if expired:
                    placeholders = ",".join(f":id{i}" for i in range(len(expired)))
                    params = {f"id{i}": sid for i, sid in enumerate(expired)}
                    conn.execute(
                        text(
                            f"DELETE FROM sessions WHERE session_id IN ({placeholders})"
                        ),
                        params,
                    )
                # Also clean up by timestamp (catches sessions not in memory cache)
                result = conn.execute(
                    text("DELETE FROM sessions WHERE last_accessed < :cutoff"),
                    {"cutoff": cutoff},
                )
                db_removed = result.rowcount
                conn.commit()

            self._last_cleanup = now

        # Total removed = in-memory expired + any extra in DB not in memory
        total = max(len(expired), db_removed)
        if total:
            logger.info(f"Cleaned up {total} expired session(s)")

        return len(expired)

    def _maybe_cleanup(self) -> None:
        """Run cleanup if interval has passed (called with lock held)."""
        if (time.time() - self._last_cleanup) > SESSION_CLEANUP_INTERVAL:
            self._last_cleanup = time.time()

    def get_session_count(self) -> int:
        """Get number of active sessions."""
        with self._lock:
            return len(self._sessions)


# Global session store instance
_session_store: SessionStore | None = None


def get_session_store() -> SessionStore:
    """Get global session store instance backed by the configured database."""
    global _session_store
    if _session_store is None:
        from chatfilter.config import get_settings

        settings = get_settings()
        _session_store = SessionStore(db_url=settings.effective_database_url)
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
