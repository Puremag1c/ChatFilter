"""Basic CRUD routes for sessions management."""

from __future__ import annotations

import json
import logging
import shutil
from typing import Annotated

from fastapi import Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.storage.file import secure_delete_file
from chatfilter.storage.helpers import atomic_write
from chatfilter.telegram.flood_tracker import get_flood_tracker
from chatfilter.web.dependencies import get_pool_scope
from chatfilter.web.template_helpers import get_template_context

from . import router
from .io import ensure_data_dir, secure_file_permissions
from .listing import list_stored_sessions
from .validation import sanitize_session_name

logger = logging.getLogger(__name__)


@router.get("/api/sessions", response_class=HTMLResponse)
async def get_sessions(request: Request) -> HTMLResponse:
    """List all registered sessions as HTML partial."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.dependencies import get_session_manager

    scope = get_pool_scope(request)  # "admin" for every admin; "user_<id>" otherwise
    session_manager = get_session_manager()
    auth_manager = get_auth_state_manager()
    sessions = list_stored_sessions(session_manager, auth_manager, user_id=scope)
    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="partials/sessions_list.html",
        context=get_template_context(request, sessions=sessions),
    )


@router.delete("/api/sessions/{session_id}", response_class=HTMLResponse)
async def delete_session(request: Request, session_id: str) -> HTMLResponse:
    """Delete a session.

    Pool is decided by URL prefix — ``/admin/*`` targets the shared
    admin pool; everything else targets the caller's personal pool.

    Returns empty response for HTMX to remove the element.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session name",
        ) from e

    pool_scope = get_pool_scope(request)
    session_dir = ensure_data_dir(pool_scope) / safe_name

    if not session_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    try:
        # Delete credentials from secure storage
        from chatfilter.security import SecureCredentialManager

        storage_dir = session_dir.parent
        try:
            manager = SecureCredentialManager(storage_dir)
            manager.delete_credentials(safe_name)
            logger.info(f"Deleted credentials from secure storage for session: {safe_name}")
        except Exception as e:
            logger.warning(f"Error deleting credentials from secure storage: {e}")

        # Clear any FloodWait entry for this account
        get_flood_tracker().clear_account(session_id)

        # Securely delete session file
        session_file = session_dir / "session.session"
        secure_delete_file(session_file)

        # Delete any legacy plaintext config file (if it exists)
        config_file = session_dir / "config.json"
        if config_file.exists():
            secure_delete_file(config_file)

        # Remove directory
        shutil.rmtree(session_dir, ignore_errors=True)
        logger.info(f"Session '{safe_name}' deleted successfully")
    except Exception as e:
        logger.exception(f"Failed to delete session '{safe_name}'")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete session: {e}",
        ) from e

    # Return empty response - HTMX will remove the element
    return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": "refreshSessions"})


@router.get("/api/sessions/{session_id}/config", response_class=HTMLResponse)
async def get_session_config(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Get session configuration form.

    Returns HTML partial with proxy dropdown showing current selection.

    Always returns the config form, even if session files are missing or corrupted.
    This ensures the Edit button always works - users can fix missing config via the form.
    """
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates
    from chatfilter.web.session import get_session as get_web_session

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError:
        # Return error as HTML with 200 OK to prevent HTMX error handler from destroying session list
        return HTMLResponse(
            content=f'<div class="alert alert-error">{_("Invalid session name")}</div>',
        )

    pool_scope = get_pool_scope(request)
    session_dir = ensure_data_dir(pool_scope) / safe_name
    config_file = session_dir / "config.json"

    # Load current config (use empty values if missing/corrupted)
    # This allows users to fix configuration issues via the Edit form
    current_proxy_id = None

    if config_file.exists():
        try:
            with config_file.open("r", encoding="utf-8") as f:
                config = json.load(f)
                current_proxy_id = config.get("proxy_id")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read config for session {safe_name}: {e}")

    # Load proxy pool
    web_user_id = get_web_session(request).get("user_id", "default")
    proxies = load_proxy_pool(web_user_id)

    return templates.TemplateResponse(
        request=request,
        name="partials/session_config.html",
        context=get_template_context(
            request,
            session_id=safe_name,
            current_proxy_id=current_proxy_id,
            proxies=proxies,
        ),
    )


@router.put("/api/sessions/{session_id}/config", response_class=HTMLResponse)
async def update_session_config(
    request: Request,
    session_id: str,
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Update session configuration.

    Updates proxy_id for a session.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<div class="alert alert-error">{e}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    pool_scope = get_pool_scope(request)
    session_dir = ensure_data_dir(pool_scope) / safe_name
    config_file = session_dir / "config.json"

    if not session_dir.exists() or not config_file.exists():
        return HTMLResponse(
            content='<div class="alert alert-error">Session not found</div>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Validate proxy_id (required)
    if not proxy_id:
        return HTMLResponse(
            content='<div class="alert alert-error">Proxy selection is required</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id
    from chatfilter.web.session import get_session as get_web_session

    web_user_id = get_web_session(request).get("user_id", "default")

    try:
        get_proxy_by_id(proxy_id, web_user_id)
    except StorageNotFoundError:
        return HTMLResponse(
            content='<div class="alert alert-error">Selected proxy not found in pool</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Load existing config
    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read config for session {safe_name}: {e}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to read session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Update proxy_id
    config["proxy_id"] = proxy_id
    config["web_user_id"] = web_user_id

    # Save updated config
    try:
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_file, config_content)
        secure_file_permissions(config_file)
        logger.info(f"Updated config for session '{safe_name}': proxy_id={proxy_id}")
    except Exception:
        logger.exception(f"Failed to save config for session {safe_name}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to save session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Also update secure credential storage
    try:
        from chatfilter.security import SecureCredentialManager

        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_session_config(safe_name, proxy_id)
        logger.info(f"Updated session config in secure storage for session: {safe_name}")
    except Exception as e:
        logger.warning(f"Failed to update secure storage for session {safe_name}: {e}")
        # Non-fatal: config.json is the primary source

    # Return success message with HX-Trigger to refresh sessions list
    return HTMLResponse(
        content='<div class="alert alert-success">Configuration saved</div>',
        headers={"HX-Trigger": "refreshSessions"},
    )


@router.get("/api/sessions/auth/form", response_class=HTMLResponse)
async def get_auth_form(request: Request) -> HTMLResponse:
    """Get the auth flow start form.

    Returns HTML form for starting a new session auth flow.
    """
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates
    from chatfilter.web.session import get_session as get_web_session

    templates = get_templates()
    web_user_id = get_web_session(request).get("user_id", "default")
    proxies = load_proxy_pool(web_user_id)

    return templates.TemplateResponse(
        request=request,
        name="partials/auth_start_form.html",
        context=get_template_context(request, proxies=proxies),
    )
