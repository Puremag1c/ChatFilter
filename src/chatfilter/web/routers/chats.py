"""Chats router for chat listing and selection."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.service.chat_analysis import SessionNotFoundError
from chatfilter.telegram.error_mapping import get_actionable_error_info
from chatfilter.telegram.session_manager import (
    SessionInvalidError,
    SessionReauthRequiredError,
)
from chatfilter.web.dependencies import WebSession, get_chat_analysis_service

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chats"])

# Data directory for stored sessions
DATA_DIR = Path.cwd() / "data" / "sessions"


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
            request=request,
            name="partials/chat_list.html",
            context={"chats": [], "session_id": ""},
        )

    # Store selected Telegram session in user's web session
    # This enables multi-tab support and persistence across refreshes
    web_session.set("selected_telegram_session", session_id)

    service = get_chat_analysis_service()

    try:
        # Fetch paginated chats and total count
        chats, total_count = await service.get_chats_paginated(
            session_id, offset=offset, limit=limit
        )

        # Calculate if there are more chats to load
        has_more = (offset + len(chats)) < total_count
        remaining = total_count - (offset + len(chats))

        return templates.TemplateResponse(
            request=request,
            name="partials/chat_list.html",
            context={
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
        ) from None
    except SessionInvalidError as e:
        logger.error(f"Invalid session '{session_id}': {e}")
        # Clean up the invalid session
        cleanup_invalid_session(session_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/chat_list.html",
            context={
                "error": _(
                    "Session is invalid and has been removed. "
                    "The session may have been revoked, logged out from another device, "
                    "or the account may be banned or deactivated."
                ),
                "error_action": _("Upload a new session file from an active Telegram account"),
                "error_action_type": "reauth",
                "error_can_retry": False,
                "chats": [],
                "session_id": session_id,
            },
        )
    except SessionReauthRequiredError as e:
        logger.warning(f"Session '{session_id}' requires re-authorization: {e}")
        error_msg = str(e)
        if "2FA" in error_msg or "password" in error_msg.lower():
            user_message = _(
                "Two-factor authentication (2FA) is required. "
                "This session needs re-authorization with your 2FA password."
            )
            action_message = _(
                "Create a new session file using Telethon or Pyrogram and enter your 2FA password "
                "during authentication. See the Upload page for instructions."
            )
        else:
            user_message = _("Session has expired and requires re-authorization.")
            action_message = _(
                "Create and upload a new session file from your Telegram account. "
                "See the Upload page for step-by-step instructions."
            )
        return templates.TemplateResponse(
            request=request,
            name="partials/chat_list.html",
            context={
                "error": user_message,
                "error_action": action_message,
                "error_action_type": "reauth",
                "error_can_retry": False,
                "chats": [],
                "session_id": session_id,
            },
        )
    except Exception as e:
        logger.exception(f"Failed to fetch chats from session '{session_id}'")

        # Try to extract actionable error info if it's a Telegram error
        error_info = None
        try:
            # Check if it's a Telethon error by checking for common Telethon error attributes
            if hasattr(e, "__class__") and e.__class__.__module__.startswith("telethon"):
                error_info = get_actionable_error_info(e)
        except Exception:  # nosec B110 - fallback to generic error
            pass

        if error_info:
            return templates.TemplateResponse(
                request=request,
                name="partials/chat_list.html",
                context={
                    "error": error_info["message"],
                    "error_action": error_info["action"],
                    "error_action_type": error_info["action_type"],
                    "error_can_retry": error_info["can_retry"],
                    "chats": [],
                    "session_id": session_id,
                },
            )
        else:
            return templates.TemplateResponse(
                request=request,
                name="partials/chat_list.html",
                context={
                    "error": _("Failed to connect to Telegram. Please check your session."),
                    "error_action": _(
                        "Verify your session file is valid or try uploading a new one"
                    ),
                    "error_action_type": "retry",
                    "error_can_retry": True,
                    "chats": [],
                    "session_id": session_id,
                },
            )


@router.get("/api/chats/json")
async def get_chats_json(
    web_session: WebSession,
    session_id: str = Query(alias="session-select"),
) -> dict[str, Any]:
    """Fetch all chats from a session and return as JSON.

    This endpoint is used for virtual scrolling to fetch all chats at once.
    Returns chat data in JSON format for client-side rendering.

    Args:
        web_session: User's web session (injected dependency)
        session_id: Telegram session identifier

    Returns:
        Dict with chats list and total_count
    """
    if not session_id:
        return {"chats": [], "total_count": 0, "session_id": ""}

    # Store selected Telegram session in user's web session
    web_session.set("selected_telegram_session", session_id)

    service = get_chat_analysis_service()

    try:
        # Fetch all chats (use a high limit to get everything)
        chats, total_count = await service.get_chats_paginated(session_id, offset=0, limit=10000)

        # Convert chats to JSON-serializable format
        chats_data = [
            {
                "id": str(chat.id),
                "title": chat.title,
                "username": chat.username,
                "chat_type": chat.chat_type.value if chat.chat_type else "",
                "member_count": chat.member_count,
            }
            for chat in chats
        ]

        return {
            "chats": chats_data,
            "total_count": total_count,
            "session_id": session_id,
        }

    except SessionNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from None
    except SessionInvalidError as e:
        logger.error(f"Invalid session '{session_id}': {e}")
        cleanup_invalid_session(session_id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session is invalid and has been removed",
        ) from None
    except SessionReauthRequiredError as e:
        logger.warning(f"Session '{session_id}' requires re-authorization: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired and requires re-authorization",
        ) from None
    except Exception:
        logger.exception(f"Failed to fetch chats from session '{session_id}'")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to connect to Telegram. Please check your session.",
        ) from None


@router.get("/api/account-info", response_class=HTMLResponse)
async def get_account_info_endpoint(
    request: Request,
    web_session: WebSession,
    session_id: str = Query(alias="session-select"),
) -> HTMLResponse:
    """Get account info including subscription limits as HTML partial.

    Returns account info with Premium status, chat count, and limit warnings.

    Args:
        request: FastAPI request object
        web_session: User's web session (injected dependency)
        session_id: Telegram session identifier
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    if not session_id:
        return templates.TemplateResponse(
            request=request,
            name="partials/account_info.html",
            context={"account_info": None},
        )

    service = get_chat_analysis_service()

    try:
        account_info = await service.get_account_info(session_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/account_info.html",
            context={
                "account_info": account_info,
                "session_id": session_id,
            },
        )

    except SessionNotFoundError:
        return templates.TemplateResponse(
            request=request,
            name="partials/account_info.html",
            context={"account_info": None, "error": _("Session not found")},
        )
    except Exception as e:
        logger.warning(f"Failed to fetch account info for session '{session_id}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/account_info.html",
            context={"account_info": None, "error": _("Failed to fetch account info")},
        )


@router.get("/api/account-info/json")
async def get_account_info_json(
    web_session: WebSession,
    session_id: str = Query(alias="session-select"),
) -> dict[str, Any]:
    """Get account info including subscription limits as JSON.

    Returns account info with Premium status, chat count, and limit info.

    Args:
        web_session: User's web session (injected dependency)
        session_id: Telegram session identifier

    Returns:
        Dict with account info fields
    """
    if not session_id:
        return {"error": _("No session selected")}

    service = get_chat_analysis_service()

    try:
        info = await service.get_account_info(session_id)

        return {
            "user_id": info.user_id,
            "username": info.username,
            "first_name": info.first_name,
            "last_name": info.last_name,
            "display_name": info.display_name,
            "is_premium": info.is_premium,
            "chat_count": info.chat_count,
            "chat_limit": info.chat_limit,
            "remaining_slots": info.remaining_slots,
            "usage_percent": round(info.usage_percent, 1),
            "is_at_limit": info.is_at_limit,
            "is_near_limit": info.is_near_limit,
            "is_critical": info.is_critical,
        }

    except SessionNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from None
    except Exception:
        logger.exception(f"Failed to fetch account info for session '{session_id}'")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch account info",
        ) from None
