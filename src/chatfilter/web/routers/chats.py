"""Chats router for chat listing and selection."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse

from chatfilter.service import ChatAnalysisService
from chatfilter.service.chat_analysis import SessionNotFoundError
from chatfilter.telegram.session_manager import (
    SessionInvalidError,
    SessionManager,
    SessionReauthRequiredError,
)
from chatfilter.web.dependencies import WebSession

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chats"])

# Data directory for stored sessions
DATA_DIR = Path.cwd() / "data" / "sessions"

# Global session manager instance (in production, this would be in app state)
_session_manager: SessionManager | None = None
_chat_service: ChatAnalysisService | None = None


def get_session_manager() -> SessionManager:
    """Get or create the session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager


def get_chat_service() -> ChatAnalysisService:
    """Get or create the chat analysis service instance."""
    global _chat_service
    if _chat_service is None:
        _chat_service = ChatAnalysisService(
            session_manager=get_session_manager(),
            data_dir=DATA_DIR,
        )
    return _chat_service


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


def cleanup_invalid_session(session_id: str) -> None:
    """Clean up an invalid session by securely deleting its files.

    This is called when a session is detected as permanently invalid
    (e.g., account banned, session revoked, auth key unregistered).

    Args:
        session_id: Session identifier to clean up
    """
    from chatfilter.web.routers.sessions import secure_delete_file

    session_dir = DATA_DIR / session_id
    if not session_dir.exists():
        return

    try:
        # Securely delete session files
        session_file = session_dir / "session.session"
        config_file = session_dir / "config.json"

        secure_delete_file(session_file)
        secure_delete_file(config_file)

        # Remove directory
        shutil.rmtree(session_dir, ignore_errors=True)
        logger.info(f"Cleaned up invalid session '{session_id}'")
    except Exception as e:
        logger.error(f"Failed to clean up invalid session '{session_id}': {e}")


@router.get("/api/chats", response_class=HTMLResponse)
async def get_chats(
    request: Request,
    web_session: WebSession,
    session_id: str = Query(alias="session-select"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> HTMLResponse:
    """Fetch chats from a session and return as HTML partial.

    Uses the ChatAnalysisService to fetch dialog list from Telegram.
    Supports pagination to prevent timeouts with large chat lists.

    This endpoint also stores the selected Telegram session in the user's
    web session for persistence across page refreshes and multi-tab support.

    Args:
        request: FastAPI request object
        web_session: User's web session (injected dependency)
        session_id: Telegram session identifier
        offset: Number of chats to skip (for pagination)
        limit: Maximum number of chats to return (1-500, default 100)
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    if not session_id:
        return templates.TemplateResponse(
            "partials/chat_list.html",
            {"request": request, "chats": [], "session_id": ""},
        )

    # Store selected Telegram session in user's web session
    # This enables multi-tab support and persistence across refreshes
    web_session.set("selected_telegram_session", session_id)

    service = get_chat_service()

    try:
        # Fetch paginated chats and total count
        chats, total_count = await service.get_chats_paginated(
            session_id, offset=offset, limit=limit
        )

        # Calculate if there are more chats to load
        has_more = (offset + len(chats)) < total_count
        remaining = total_count - (offset + len(chats))

        return templates.TemplateResponse(
            "partials/chat_list.html",
            {
                "request": request,
                "chats": chats,
                "session_id": session_id,
                "offset": offset,
                "limit": limit,
                "total_count": total_count,
                "has_more": has_more,
                "remaining": remaining,
                "is_initial_load": offset == 0,
            },
        )

    except SessionNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except SessionInvalidError as e:
        logger.error(f"Invalid session '{session_id}': {e}")
        # Clean up the invalid session
        cleanup_invalid_session(session_id)
        return templates.TemplateResponse(
            "partials/chat_list.html",
            {
                "request": request,
                "error": (
                    "Session is invalid and has been removed. "
                    "The session may have been revoked, logged out from another device, "
                    "or the account may be banned or deactivated. "
                    "Please upload a new session file from an active Telegram account."
                ),
                "chats": [],
                "session_id": session_id,
            },
        )
    except SessionReauthRequiredError as e:
        logger.warning(f"Session '{session_id}' requires re-authorization: {e}")
        error_msg = str(e)
        if "2FA" in error_msg or "password" in error_msg.lower():
            user_message = (
                "Two-factor authentication (2FA) is required. "
                "This session needs re-authorization with your 2FA password. "
                "Please create a new session file using Telethon or Pyrogram, "
                "and make sure to enter your 2FA password during the authentication process. "
                "See the Upload page for detailed instructions."
            )
        else:
            user_message = (
                "Session has expired and requires re-authorization. "
                "Please create and upload a new session file from your Telegram account. "
                "See the Upload page for step-by-step instructions."
            )
        return templates.TemplateResponse(
            "partials/chat_list.html",
            {
                "request": request,
                "error": user_message,
                "chats": [],
                "session_id": session_id,
            },
        )
    except Exception as e:
        logger.exception(f"Failed to fetch chats from session '{session_id}'")
        return templates.TemplateResponse(
            "partials/chat_list.html",
            {
                "request": request,
                "error": "Failed to connect to Telegram. Please check your session and try again.",
                "chats": [],
                "session_id": session_id,
            },
        )
