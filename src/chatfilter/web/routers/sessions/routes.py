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

from .helpers import (
    SessionListItem,
    _get_flood_wait_until,
    ensure_data_dir,
    get_session_config_status,
    list_stored_sessions,
    sanitize_session_name,
    secure_file_permissions,
    validate_telegram_credentials_with_retry,
)
from . import router

logger = logging.getLogger(__name__)


@router.get("/api/sessions", response_class=HTMLResponse)
async def get_sessions(request: Request) -> HTMLResponse:
    """List all registered sessions as HTML partial."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.dependencies import get_session_manager

    session_manager = get_session_manager()
    auth_manager = get_auth_state_manager()
    sessions = list_stored_sessions(session_manager, auth_manager)
    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="partials/sessions_list.html",
        context={"sessions": sessions},
    )


@router.delete("/api/sessions/{session_id}", response_class=HTMLResponse)
async def delete_session(session_id: str) -> HTMLResponse:
    """Delete a session.

    Returns empty response for HTMX to remove the element.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session name",
        ) from e

    session_dir = ensure_data_dir() / safe_name

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

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError:
        # Return error as HTML with 200 OK to prevent HTMX error handler from destroying session list
        return HTMLResponse(
            content=f'<div class="alert alert-error">{_("Invalid session name")}</div>',
        )

    session_dir = ensure_data_dir() / safe_name
    config_file = session_dir / "config.json"

    # Load current config (use empty values if missing/corrupted)
    # This allows users to fix configuration issues via the Edit form
    current_api_id = None
    current_api_hash = None
    current_proxy_id = None

    if config_file.exists():
        try:
            with config_file.open("r", encoding="utf-8") as f:
                config = json.load(f)
                current_api_id = config.get("api_id")
                current_api_hash = config.get("api_hash")
                current_proxy_id = config.get("proxy_id")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read config for session {safe_name}: {e}")

    # Load proxy pool
    proxies = load_proxy_pool()

    return templates.TemplateResponse(
        request=request,
        name="partials/session_config.html",
        context={
            "session_id": safe_name,
            "current_api_id": current_api_id,
            "current_api_hash": current_api_hash,
            "current_proxy_id": current_proxy_id,
            "proxies": proxies,
        },
    )


@router.put("/api/sessions/{session_id}/config", response_class=HTMLResponse)
async def update_session_config(
    request: Request,
    session_id: str,
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Update session configuration.

    Updates api_id, api_hash, and proxy_id for a session.
    All fields are required.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<div class="alert alert-error">{e}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_dir = ensure_data_dir() / safe_name
    config_file = session_dir / "config.json"

    if not session_dir.exists() or not config_file.exists():
        return HTMLResponse(
            content='<div class="alert alert-error">Session not found</div>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Validate api_id
    if api_id < 1:
        return HTMLResponse(
            content='<div class="alert alert-error">API ID must be a positive number</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate api_hash format (32-char hex string)
    api_hash = api_hash.strip()
    if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
        return HTMLResponse(
            content='<div class="alert alert-error">API hash must be a 32-character hexadecimal string</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate proxy_id (required)
    if not proxy_id:
        return HTMLResponse(
            content='<div class="alert alert-error">Proxy selection is required</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id

    try:
        get_proxy_by_id(proxy_id)
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

    # Check if API credentials changed
    old_api_id = config.get("api_id")
    old_api_hash = config.get("api_hash")
    credentials_changed = (old_api_id != api_id) or (old_api_hash != api_hash)

    # If credentials changed, validate them with Telegram API
    if credentials_changed:
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        # Get proxy for validation
        try:
            proxy_entry = get_proxy_by_id(proxy_id)
        except StorageNotFoundError:
            return HTMLResponse(
                content='<div class="alert alert-error">Selected proxy not found</div>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Validate credentials with retry logic
        is_valid, error_message = await validate_telegram_credentials_with_retry(
            api_id=api_id,
            api_hash=api_hash,
            proxy_entry=proxy_entry,
            session_name=safe_name,
        )

        if not is_valid:
            # Validation failed after retries
            status_code = (
                status.HTTP_400_BAD_REQUEST
                if "Invalid API" in error_message
                else status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            return HTMLResponse(
                content=f'<div class="alert alert-error">{error_message}</div>',
                status_code=status_code,
            )

        # Credentials valid - disconnect current session if connected
        from chatfilter.web.dependencies import get_session_manager

        session_manager = get_session_manager()
        try:
            await session_manager.disconnect(safe_name)
            logger.info(f"Disconnected session '{safe_name}' after credentials change")
        except Exception as e:
            logger.warning(f"Failed to disconnect session '{safe_name}': {e}")
            # Non-fatal - continue with config update

    # Update all config fields
    config["api_id"] = api_id
    config["api_hash"] = api_hash
    config["proxy_id"] = proxy_id

    # Save updated config
    try:
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_file, config_content)
        secure_file_permissions(config_file)
        logger.info(
            f"Updated config for session '{safe_name}': api_id={api_id}, proxy_id={proxy_id}"
        )
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
        manager.store_credentials(safe_name, api_id, api_hash, proxy_id)
        logger.info(f"Updated credentials in secure storage for session: {safe_name}")
    except Exception as e:
        logger.warning(f"Failed to update secure storage for session {safe_name}: {e}")
        # Non-fatal: config.json is the primary source

    # If credentials changed, trigger reconnect flow
    if credentials_changed:
        # Return success message with auto-trigger for reconnect
        return HTMLResponse(
            content=f'''
                <div class="alert alert-success">
                    Credentials updated. Re-authorization required...
                </div>
                <form hx-post="/api/sessions/{safe_name}/reconnect/start"
                      hx-target="#session-config-result-{safe_name}"
                      hx-swap="innerHTML"
                      hx-trigger="load">
                </form>
            ''',
            headers={"HX-Trigger": "refreshSessions"},
        )

    # Return success message with HX-Trigger to refresh sessions list
    return HTMLResponse(
        content='<div class="alert alert-success">Configuration saved</div>',
        headers={"HX-Trigger": "refreshSessions"},
    )


@router.put("/api/sessions/{session_id}/credentials", response_class=HTMLResponse)
async def update_session_credentials(
    request: Request,
    session_id: str,
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
) -> HTMLResponse:
    """Update session API credentials.

    Updates api_id and api_hash for a session that was created without credentials
    (e.g., from phone auth flow). Does not change proxy_id or other fields.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<div class="alert alert-error">{e}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_dir = ensure_data_dir() / safe_name
    config_file = session_dir / "config.json"

    if not session_dir.exists() or not config_file.exists():
        return HTMLResponse(
            content='<div class="alert alert-error">Session not found</div>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Validate api_id
    if api_id < 1:
        return HTMLResponse(
            content='<div class="alert alert-error">API ID must be a positive number</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate api_hash format (32-char hex string)
    api_hash = api_hash.strip()
    if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
        return HTMLResponse(
            content='<div class="alert alert-error">API hash must be a 32-character hexadecimal string</div>',
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

    # Check if API credentials changed
    old_api_id = config.get("api_id")
    old_api_hash = config.get("api_hash")
    credentials_changed = (old_api_id != api_id) or (old_api_hash != api_hash)

    # If credentials changed, validate them with Telegram API
    if credentials_changed:
        from chatfilter.storage.errors import StorageNotFoundError
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        # Get proxy for validation
        proxy_id = config.get("proxy_id")
        if not proxy_id:
            return HTMLResponse(
                content='<div class="alert alert-error">Session has no proxy configured. Please use the full config form to set both credentials and proxy.</div>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            proxy_entry = get_proxy_by_id(proxy_id)
        except StorageNotFoundError:
            return HTMLResponse(
                content='<div class="alert alert-error">Session proxy not found in pool</div>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Validate credentials with retry logic
        is_valid, error_message = await validate_telegram_credentials_with_retry(
            api_id=api_id,
            api_hash=api_hash,
            proxy_entry=proxy_entry,
            session_name=safe_name,
        )

        if not is_valid:
            # Validation failed after retries
            status_code = (
                status.HTTP_400_BAD_REQUEST
                if "Invalid API" in error_message
                else status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            return HTMLResponse(
                content=f'<div class="alert alert-error">{error_message}</div>',
                status_code=status_code,
            )

        # Credentials valid - disconnect current session if connected
        from chatfilter.web.dependencies import get_session_manager

        session_manager = get_session_manager()
        try:
            await session_manager.disconnect(safe_name)
            logger.info(f"Disconnected session '{safe_name}' after credentials change")
        except Exception as e:
            logger.warning(f"Failed to disconnect session '{safe_name}': {e}")
            # Non-fatal - continue with config update

    # Update only api_id and api_hash (preserve proxy_id and source)
    config["api_id"] = api_id
    config["api_hash"] = api_hash

    # Save updated config
    try:
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_file, config_content)
        secure_file_permissions(config_file)
        logger.info(
            f"Updated credentials for session '{safe_name}': api_id={api_id}"
        )
    except Exception:
        logger.exception(f"Failed to save config for session {safe_name}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to save session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Also update secure credential storage
    proxy_id = config.get("proxy_id")
    try:
        from chatfilter.security import SecureCredentialManager

        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_credentials(safe_name, api_id, api_hash, proxy_id)
        logger.info(f"Updated credentials in secure storage for session: {safe_name}")
    except Exception as e:
        logger.warning(f"Failed to update secure storage for session {safe_name}: {e}")
        # Non-fatal: config.json is the primary source

    # If credentials changed, need to trigger reconnect flow
    if credentials_changed:
        # Delete session.session file to force re-authorization
        session_file = session_dir / "session.session"
        if session_file.exists():
            try:
                session_file.unlink()
                logger.info(f"Deleted session file for '{safe_name}' to trigger re-auth")
            except Exception as e:
                logger.warning(f"Failed to delete session file for '{safe_name}': {e}")
                # Non-fatal - continue with reconnect

        # Return success message with auto-trigger for reconnect
        return HTMLResponse(
            content=f'''
                <div class="alert alert-success">
                    Credentials updated. Re-authorization required...
                </div>
                <form hx-post="/api/sessions/{safe_name}/reconnect/start"
                      hx-target="#session-config-result-{safe_name}"
                      hx-swap="innerHTML"
                      hx-trigger="load">
                </form>
            ''',
            headers={"HX-Trigger": "refreshSessions"},
        )

    # Get updated session status
    from chatfilter.web.template_helpers import get_template_context

    config_status, _config_reason = get_session_config_status(session_dir)
    session_info = SessionListItem(
        session_id=safe_name,
        state=config_status,
        error_message=config.get("error_message"),
        retry_available=config.get("retry_available"),
        flood_wait_until=_get_flood_wait_until(safe_name),
    )

    # Return session row HTML with updated status
    from chatfilter.web.app import get_templates

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/session_row.html",
        context=get_template_context(request, session=session_info),
        headers={"HX-Trigger": "refreshSessions"},
    )


@router.get("/api/sessions/auth/form", response_class=HTMLResponse)
async def get_auth_form(request: Request) -> HTMLResponse:
    """Get the auth flow start form.

    Returns HTML form for starting a new session auth flow.
    """
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates

    templates = get_templates()
    proxies = load_proxy_pool()

    return templates.TemplateResponse(
        request=request,
        name="partials/auth_start_form.html",
        context={"proxies": proxies},
    )
