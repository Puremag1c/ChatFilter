"""Dependency injection helpers for FastAPI routes.

This module provides reusable dependencies for route handlers,
including session management, service access, and more.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, Request

from chatfilter.service import ChatAnalysisService
from chatfilter.telegram.session_manager import SessionManager
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
        db_path = settings.data_dir / "groups.db"
        settings.data_dir.mkdir(parents=True, exist_ok=True)

        db = GroupDatabase(db_path)
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
