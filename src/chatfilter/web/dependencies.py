"""Dependency injection helpers for FastAPI routes.

This module provides reusable dependencies for route handlers,
including session management, service access, and more.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from chatfilter.service import ChatAnalysisService
from chatfilter.telegram.session import SessionManager
from chatfilter.web.session import SessionData, get_session

if TYPE_CHECKING:
    from chatfilter.analyzer.group_engine import GroupAnalysisEngine


def get_web_session(request: Request) -> SessionData:
    """Dependency to get web session for current request.

    This is a FastAPI dependency that can be used in route handlers
    to access session data.

    Example:
        ```python
        @router.get("/some-route")
        async def some_route(
            session: Annotated[SessionData, Depends(get_web_session)]
        ):
            selected_session = session.get("selected_session_id")
            session.set("selected_session_id", "new_value")
        ```
    """
    return get_session(request)


# Type alias for session dependency
WebSession = Annotated[SessionData, Depends(get_web_session)]


def require_admin(request: Request) -> SessionData:
    """Route dependency that returns the session only if the user is admin.

    Raises 403 Forbidden otherwise (works both for authenticated non-admin
    users and for unauthenticated requests — the middleware already
    redirects anon users to /login before we get here in real flows).

    Usage:
        @router.get("/admin-only")
        async def view(_: Annotated[SessionData, Depends(require_admin)]):
            ...
    """
    from fastapi import HTTPException, status

    session = get_session(request)
    if not session.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return session


AdminSession = Annotated[SessionData, Depends(require_admin)]


def require_own_accounts(request: Request) -> SessionData:
    """Allow the request only if the user opted into their own accounts.

    Guards /sessions, /proxies and their APIs — the personal pool.
    Being admin is NOT enough: admins without ``use_own_accounts=True``
    have no personal accounts, they manage the shared pool via
    /admin/accounts instead. To also own a private pool an admin just
    ticks the profile toggle like any other user.
    """
    from fastapi import HTTPException, status

    session = get_session(request)
    user_id = session.get("user_id")
    if user_id:
        try:
            from chatfilter.storage.user_database import get_user_db

            settings = request.app.state.settings
            user_db = get_user_db(settings.effective_database_url)
            user = user_db.get_user_by_id(user_id)
            if user and user.get("use_own_accounts"):
                return session
        except Exception:
            pass
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Enable 'Use my own accounts' in your profile to access this page",
    )


OwnAccountsSession = Annotated[SessionData, Depends(require_own_accounts)]


def get_pool_scope(request: Request) -> str:
    """Return the pool scope this request should read/write.

    Scope is chosen by **URL path**, not by user role:

      - Any ``/admin/...`` request → ``"admin"`` (the shared admin pool).
        Route-level ``require_admin`` already ensures only admins reach
        these endpoints.
      - Anything else → ``"user_{id}"`` (the caller's personal pool).
        Route-level ``require_own_accounts`` keeps non-power-users out.

    Scope is a filesystem-safe identifier: colon-free, so it can be
    used directly as a subdirectory name under ``sessions_dir`` / as a
    suffix in ``proxies_<scope>.json``.
    """
    try:
        path = request.url.path
    except Exception:
        path = ""
    if path.startswith("/admin/") or path == "/admin":
        return "admin"
    session = get_session(request)
    uid = session.get("user_id")
    if uid:
        return f"user_{uid}"
    return "admin"


def get_proxy_scope(request: Request) -> str:
    """Scope key used to identify this user's proxy pool.

    Same rule as :func:`get_pool_scope` — URL-based, so the session
    forms render proxies from the pool that matches the current view
    (admin mount → admin pool, personal mount → personal pool). That
    means a single admin can be a power-user on ``/proxies`` without
    their admin-pool proxies leaking into their personal view.

    Kept as a separate function (alias) so any test that references
    ``get_proxy_scope`` explicitly still resolves.
    """
    return get_pool_scope(request)


def get_owner_key(request: Request) -> str:
    """Return the ownership key stored in .account_info.json / routed by scheduler.

    Same rule as :func:`get_pool_scope` but formatted for the queue's
    pool_key column: ``"admin"`` for the shared admin pool, or
    ``"user:{id}"`` for a personal pool (note the colon, required by
    the scheduler).
    """
    try:
        path = request.url.path
    except Exception:
        path = ""
    if path.startswith("/admin/") or path == "/admin":
        return "admin"
    session = get_session(request)
    uid = session.get("user_id")
    if uid:
        return f"user:{uid}"
    return "admin"


# Global instances (in production, these would be in app state)
_session_manager: SessionManager | None = None
_chat_service: ChatAnalysisService | None = None
_group_engine: GroupAnalysisEngine | None = None


def get_session_manager() -> SessionManager:
    """Get or create the Telegram session manager instance.

    This manages Telegram client connections and sessions.
    """
    global _session_manager
    if _session_manager is None:
        from chatfilter.config import get_settings

        settings = get_settings()
        _session_manager = SessionManager(
            connect_timeout=settings.connect_timeout,
            operation_timeout=settings.operation_timeout,
            heartbeat_interval=settings.heartbeat_interval,
            heartbeat_timeout=settings.heartbeat_timeout,
            heartbeat_max_failures=settings.heartbeat_max_failures,
        )
    return _session_manager


def get_chat_analysis_service() -> ChatAnalysisService:
    """Get or create the chat analysis service instance."""
    global _chat_service
    if _chat_service is None:
        from chatfilter.config import get_settings

        settings = get_settings()
        _chat_service = ChatAnalysisService(
            session_manager=get_session_manager(),
            data_dir=settings.sessions_dir,
        )
    return _chat_service


def get_group_engine() -> GroupAnalysisEngine:
    """Get or create the group analysis engine instance.

    Returns:
        GroupAnalysisEngine instance for managing group analysis workflow
    """
    global _group_engine
    if _group_engine is None:
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine
        from chatfilter.config import get_settings
        from chatfilter.storage.group_database import GroupDatabase

        settings = get_settings()
        settings.data_dir.mkdir(parents=True, exist_ok=True)

        db = GroupDatabase(settings.effective_database_url)
        session_manager = get_session_manager()

        _group_engine = GroupAnalysisEngine(
            db=db,
            session_manager=session_manager,
        )
    return _group_engine


def reset_group_engine() -> None:
    """Reset cached group engine instance.

    Used in tests to ensure each test gets a fresh engine with isolated database.
    """
    global _group_engine
    _group_engine = None
