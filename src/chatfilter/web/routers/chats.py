"""Chats router for chat listing and selection."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse

from chatfilter.telegram.client import TelegramClientLoader, get_dialogs
from chatfilter.telegram.session_manager import SessionManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chats"])

# Data directory for stored sessions
DATA_DIR = Path.cwd() / "data" / "sessions"

# Global session manager instance (in production, this would be in app state)
_session_manager: SessionManager | None = None


def get_session_manager() -> SessionManager:
    """Get or create the session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def get_session_paths(session_id: str) -> tuple[Path, Path]:
    """Get session and config file paths for a session ID.

    Args:
        session_id: Session identifier

    Returns:
        Tuple of (session_path, config_path)

    Raises:
        HTTPException: If session not found
    """
    session_dir = DATA_DIR / session_id

    if not session_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )

    session_path = session_dir / "session.session"
    config_path = session_dir / "config.json"

    if not session_path.exists() or not config_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' is incomplete (missing files)",
        )

    return session_path, config_path


@router.get("/api/chats", response_class=HTMLResponse)
async def get_chats(
    request: Request,
    session_id: str = Query(alias="session-select"),
) -> HTMLResponse:
    """Fetch chats from a session and return as HTML partial.

    Connects to Telegram using the stored session, fetches dialog list,
    and returns HTML for HTMX to swap into the page.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    if not session_id:
        return templates.TemplateResponse(
            "partials/chat_list.html",
            {"request": request, "chats": [], "session_id": ""},
        )

    try:
        session_path, config_path = get_session_paths(session_id)

        # Create loader and register with session manager
        loader = TelegramClientLoader(session_path, config_path)
        loader.validate()

        manager = get_session_manager()
        manager.register(session_id, loader)

        # Connect and fetch dialogs
        try:
            async with manager.session(session_id) as client:
                chats = await get_dialogs(client)

            logger.info(f"Fetched {len(chats)} chats from session '{session_id}'")

            return templates.TemplateResponse(
                "partials/chat_list.html",
                {
                    "request": request,
                    "chats": chats,
                    "session_id": session_id,
                },
            )

        except Exception as e:
            logger.exception(f"Failed to fetch chats from session '{session_id}'")
            return templates.TemplateResponse(
                "partials/chat_list.html",
                {
                    "request": request,
                    "error": f"Failed to connect to Telegram: {e}",
                    "chats": [],
                    "session_id": session_id,
                },
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error loading session '{session_id}'")
        return templates.TemplateResponse(
            "partials/chat_list.html",
            {
                "request": request,
                "error": f"Failed to load session: {e}",
                "chats": [],
                "session_id": session_id,
            },
        )
