"""Sessions router for session file upload and management.

Session Status State Machine
============================

This module implements a finite state machine for session status transitions.
Each transition triggers both an HTML response update and an SSE event publication.

States
------
Core states (9-state model):
- disconnected: Session is ready but not connected to Telegram
- connected: Session is actively connected to Telegram
- connecting: Transient state during connection establishment
- needs_code: Waiting for SMS/app verification code
- needs_2fa: Waiting for 2FA password
- needs_confirmation: Waiting for device confirmation in another Telegram client ("Is this you?")
- needs_config: Configuration required (API ID/hash, proxy misconfigured)
- banned: Account banned by Telegram (terminal state)
- error: Generic error state (includes flood_wait, expired/corrupted sessions - auto-handled by connect flow)

Transition Matrix
-----------------
From State          | Action/Event           | To State      | SSE Event | Endpoint
--------------------|------------------------|---------------|-----------|----------------------------------
disconnected        | connect button         | connecting    | -         | POST /api/sessions/{id}/connect
connecting          | connection success     | connected     | connected | POST /api/sessions/{id}/connect
connecting          | connection failure     | error/*       | error/*   | POST /api/sessions/{id}/connect
connected           | disconnect button      | disconnecting | -         | POST /api/sessions/{id}/disconnect
disconnecting       | disconnect success     | disconnected  | disconn.  | POST /api/sessions/{id}/disconnect
disconnecting       | disconnect failure     | error         | error     | POST /api/sessions/{id}/disconnect
needs_code          | code verified          | connected     | connected | POST /api/sessions/{id}/verify-code
needs_code          | code verified + 2FA    | needs_2fa     | needs_2fa | POST /api/sessions/{id}/verify-code
needs_code          | code invalid           | needs_code    | -         | POST /api/sessions/{id}/verify-code
needs_code          | modal cancelled        | needs_code    | -         | UI only (no API call)
needs_2fa           | password verified      | connected     | connected | POST /api/sessions/{id}/verify-2fa
needs_2fa           | password invalid       | needs_2fa     | -         | POST /api/sessions/{id}/verify-2fa
needs_2fa           | modal cancelled        | needs_2fa     | -         | UI only (no API call)
error               | retry button           | connecting    | -         | POST /api/sessions/{id}/connect
needs_config        | edit button            | -             | -         | GET /dashboard (edit session config)

Error State Classification
--------------------------
Errors are classified by `classify_error_state()` function (simplified 3-state model):
- banned: UserDeactivated, UserDeactivatedBan, PhoneNumberBanned (terminal state)
- needs_config: OSError, ConnectionError, proxy errors (configuration required)
- error: All other errors (including expired/corrupted sessions, flood_wait - handled by connect flow)

SSE Event Publishing
--------------------
Events are published via `get_event_bus().publish(session_id, status)`.
The SSE endpoint is at GET /api/sessions/events.

All status-changing endpoints publish SSE events:
- connect_session: publishes on success (connected) or failure (error state)
- disconnect_session: publishes on success (disconnected) or failure (error)
- verify_code: publishes connected or needs_2fa on success
- verify_2fa: publishes connected on success

Loading States in UI (session_row.html)
---------------------------------------
The template shows spinner indicators via htmx:
- hx-indicator="#connection-spinner-{id}" on connect/disconnect buttons
- hx-disabled-elt="this" disables button during request
- connecting/disconnecting states show disabled button with spinner

Template State Handling:
- Each state has specific button rendering (connect/disconnect/retry/configure)
- Error states show title attribute with error message
- needs_code/needs_2fa show modal trigger buttons
- banned/corrupted show disabled buttons (non-recoverable)

Modal Cancel Behavior (modal_code.html, modal_2fa.html)
--------------------------------------------------------
When user cancels code/2FA modals:
- Session state remains unchanged (stays in needs_code or needs_2fa)
- User sees confirmation: "Authentication cancelled. Session remains disconnected. You can try again anytime."
- No API call is made (client-side only)
- User can re-open modal and retry authentication without data loss
- This is the least destructive option: session stays stable, user can retry later
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import sqlite3
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from chatfilter.config import get_settings
from chatfilter.i18n import _
from chatfilter.parsers.telegram_expert import (
    parse_telegram_expert_json,
    validate_account_info_json,
)
from chatfilter.storage.file import secure_delete_file
from chatfilter.storage.helpers import atomic_write
from chatfilter.telegram.client import SessionFileError, TelegramClientLoader, TelegramConfigError
from chatfilter.telegram.session_manager import SessionBusyError, SessionState
from chatfilter.telegram.flood_tracker import get_flood_tracker
from chatfilter.web.events import get_event_bus
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    from starlette.templating import Jinja2Templates
    from telethon import TelegramClient

    from chatfilter.models.proxy import ProxyEntry
    from chatfilter.web.auth_state import AuthState, AuthStateManager

logger = logging.getLogger(__name__)


# Import helpers from helpers module
from .helpers import (
    MAX_CONFIG_SIZE,
    MAX_JSON_SIZE,
    MAX_SESSION_SIZE,
    READ_CHUNK_SIZE,
    SessionListItem,
    _get_flood_wait_until,
    _get_session_lock,
    _locks_lock,
    _save_error_to_config,
    _save_session_to_disk,
    _session_locks,
    classify_error_state,
    ensure_data_dir,
    find_duplicate_accounts,
    get_account_info_from_session,
    get_session_config_status,
    list_stored_sessions,
    load_account_info,
    migrate_legacy_sessions,
    read_upload_with_size_limit,
    sanitize_error_message_for_client,
    sanitize_session_name,
    save_account_info,
    secure_delete_dir,
    secure_file_permissions,
    validate_config_file_format,
    validate_phone_number,
    validate_session_file_format,
    validate_telegram_credentials_with_retry,
)

router = APIRouter(tags=["sessions"])

# Register SSE routes
from .sse import register_sse_routes
register_sse_routes(router)


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


@router.post("/api/sessions/upload", response_class=HTMLResponse)
async def upload_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    config_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile | None, File()] = None,
) -> HTMLResponse:
    """Upload a new session with config file.

    Args:
        json_file: Optional JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial for HTMX to display result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Sanitize session name (path traversal protection)
        try:
            safe_name = sanitize_session_name(session_name)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Atomically create session directory to prevent TOCTOU race
        session_dir = ensure_data_dir() / safe_name
        try:
            session_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Session '{name}' already exists").format(name=safe_name),
                },
            )

        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid session: {error}").format(error=e)},
            )

        # Read and validate config file with size limit enforcement
        try:
            config_content = await read_upload_with_size_limit(
                config_file, MAX_CONFIG_SIZE, "config"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            config_data = validate_config_file_format(config_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid config: {error}").format(error=e)},
            )

        # Parse JSON file if provided (TelegramExpert format)
        json_account_info = None
        twofa_password = None
        json_api_id = None
        json_api_hash = None
        if json_file:
            try:
                # Read JSON with size limit (10KB max)
                MAX_JSON_SIZE = 10 * 1024  # 10KB
                json_content = await read_upload_with_size_limit(
                    json_file, MAX_JSON_SIZE, "JSON"
                )
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": str(e)},
                )

            try:
                json_data = json.loads(json_content)
                # Security: Zero plaintext JSON after parsing to prevent memory dumps
                json_content = b'\x00' * len(json_content)
                del json_content
            except json.JSONDecodeError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": _("Invalid JSON format: {error}").format(error=str(e))},
                )

            # Validate JSON structure, fields, and phone format
            validation_error = validate_account_info_json(json_data)
            if validation_error:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": _(validation_error)},
                )

            # Extract account info from JSON (validated above)
            json_account_info = {
                "phone": str(json_data["phone"]),
                "first_name": str(json_data.get("first_name", "")),
                "last_name": str(json_data.get("last_name", "")),
            }

            # Extract 2FA password if present (will encrypt later)
            if "twoFA" in json_data and json_data["twoFA"]:
                twofa_password = str(json_data["twoFA"])
                # Security: Zero plaintext 2FA in JSON dict to prevent memory leaks
                json_data["twoFA"] = "\x00" * len(json_data["twoFA"])
                del json_data["twoFA"]

            # Extract API credentials from JSON (if present)
            from chatfilter.parsers.telegram_expert import extract_api_credentials

            json_api_id, json_api_hash = extract_api_credentials(json_data)

        # Extract account info from session to check for duplicates
        import tempfile

        account_info = None
        duplicate_sessions = []

        # Create a temporary session file to test connection
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        # Track credential sources for later storage
        config_has_credentials = False
        json_has_credentials = False

        try:
            # Priority: config.json credentials > JSON credentials
            api_id_value = config_data.get("api_id")
            api_hash_value = config_data.get("api_hash")

            # Convert to appropriate types, handling None
            api_id = int(api_id_value) if api_id_value is not None else None
            api_hash = str(api_hash_value) if api_hash_value is not None else None

            # Fallback to JSON credentials if config doesn't have them
            config_has_credentials = api_id is not None and api_hash is not None
            json_has_credentials = (
                json_api_id is not None and json_api_hash is not None
            )

            if not config_has_credentials and json_has_credentials:
                # Use credentials from JSON
                api_id = json_api_id
                api_hash = json_api_hash
                logger.info(
                    f"Using API credentials from JSON file for session: {safe_name}"
                )

            # Try to get account info from the session only if both api_id and api_hash are available
            account_info = None
            if api_id is not None and api_hash is not None:
                account_info = await get_account_info_from_session(
                    tmp_session_path, api_id, api_hash
                )

            if account_info:
                # Check for duplicate accounts
                user_id = account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(user_id, exclude_session=safe_name)
        finally:
            # Clean up temporary session file
            import contextlib

            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Save session with atomic transaction (no orphaned files on failure)
        # session_dir already created (mkdir exist_ok=False) to prevent TOCTOU race
        # _save_session_to_disk() creates temp dir, writes files, then renames over empty session_dir
        try:
            from chatfilter.utils.disk import DiskSpaceError

            # proxy_id is None - user must configure it after upload
            # source is 'file' because config was uploaded
            # Use json_account_info if provided, otherwise use account_info from session
            final_account_info = json_account_info if json_account_info else account_info
            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=None,
                account_info=final_account_info,
                source="file",
            )

        except DiskSpaceError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Insufficient disk space. Please free up disk space and try again.")},
            )
        except TelegramConfigError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Configuration error. Please check your session file and credentials."),
                },
            )
        except Exception:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Failed to save session files. Please try again."),
                },
            )

        logger.info(f"Session '{safe_name}' uploaded successfully")

        # Store API credentials if they came from JSON (not config.json)
        if not config_has_credentials and json_has_credentials:
            try:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir
                manager = SecureCredentialManager(storage_dir)
                manager.store_credentials(safe_name, api_id, api_hash)
                logger.info(f"Stored API credentials from JSON for session: {safe_name}")
            except Exception:
                logger.exception("Failed to store API credentials from JSON")
                # Don't fail the upload if credential storage fails

        # Store encrypted 2FA password if provided in JSON
        if twofa_password:
            try:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir
                manager = SecureCredentialManager(storage_dir)
                manager.store_2fa(safe_name, twofa_password)
                logger.info(f"Stored encrypted 2FA password for session: {safe_name}")
            except Exception:
                logger.exception("Failed to store 2FA password")
                # Don't fail the upload if 2FA storage fails
            finally:
                # Security: Zero plaintext 2FA password in memory after encryption
                if twofa_password:
                    twofa_password = "\x00" * len(twofa_password)
                    del twofa_password

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": _("Session '{name}' uploaded successfully").format(name=safe_name),
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception("Unexpected error during session upload")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during upload. Please try again."),
            },
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


@router.post("/api/sessions/import/validate", response_class=HTMLResponse)
async def validate_import_session(
    request: Request,
    session_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile, File()],
) -> HTMLResponse:
    """Validate session and JSON files for import.

    Args:
        json_file: JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial with validation result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        # Validate session file format
        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        # Validate JSON file
        try:
            json_content = await read_upload_with_size_limit(
                json_file, MAX_JSON_SIZE, "JSON"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            json_data = json.loads(json_content)

            # Validate JSON structure and fields using dedicated parser module
            validation_error = validate_account_info_json(json_data)
            if validation_error:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/import_validation_result.html",
                    context={"success": False, "error": validation_error},
                )

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": _("Invalid JSON format: {error}").format(error=str(e))},
            )

        # Validation successful - extract API credentials if present
        from chatfilter.parsers.telegram_expert import extract_api_credentials

        api_id, api_hash = extract_api_credentials(json_data)

        logger.info("Session and JSON files validated successfully for import")
        return templates.TemplateResponse(
            request=request,
            name="partials/import_validation_result.html",
            context={
                "success": True,
                "api_id": api_id,
                "api_hash": api_hash,
            },
        )

    except Exception:
        logger.exception("Unexpected error during session validation")
        return templates.TemplateResponse(
            request=request,
            name="partials/import_validation_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during validation."),
            },
        )


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

# =============================================================================
# Session Auth Flow (Create New Session from Phone)
# =============================================================================


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


@router.post("/api/sessions/auth/start", response_class=HTMLResponse)
async def start_auth_flow(
    request: Request,
    session_name: Annotated[str, Form()],
    phone: Annotated[str, Form()],
    api_id: Annotated[str | None, Form()] = None,
    api_hash: Annotated[str | None, Form()] = None,
    proxy_id: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    """Save new session credentials to disk.

    Creates session directory with .account_info.json and .credentials.enc.
    Does NOT connect to Telegram or send code - session appears as 'disconnected'.

    Args:
        session_name: Unique session identifier
        phone: Phone number with country code
        api_id: Optional Telegram API ID
        api_hash: Optional Telegram API hash (32-char hex)
        proxy_id: Optional proxy identifier

    Returns:
        HTML partial with success message or error
    """
    from chatfilter.security import SecureCredentialManager
    from chatfilter.web.app import get_templates

    templates = get_templates()

    # Validate session name
    try:
        safe_name = sanitize_session_name(session_name)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
        )

    # Check if session already exists
    session_dir = ensure_data_dir() / safe_name
    if session_dir.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session '{name}' already exists").format(name=safe_name),
            },
        )

    # Normalize empty strings to None
    if api_id is not None:
        api_id_str = str(api_id).strip()
        api_id = None if api_id_str == "" else int(api_id_str)

    if api_hash is not None:
        api_hash = api_hash.strip()
        api_hash = None if api_hash == "" else api_hash

    if proxy_id is not None:
        proxy_id = proxy_id.strip()
        proxy_id = None if proxy_id == "" else proxy_id

    # Validate api_id and api_hash consistency
    has_api_id = api_id is not None
    has_api_hash = api_hash is not None

    if has_api_id != has_api_hash:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Both API ID and API Hash are required if one is provided."),
            },
        )

    # Validate api_id format (if provided)
    if has_api_id and api_id <= 0:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("API ID must be a positive integer."),
            },
        )

    # Validate api_hash format (if provided)
    if has_api_hash:
        if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={
                    "success": False,
                    "error": _("Invalid API hash format. Must be a 32-character hexadecimal string."),
                },
            )

    # Validate and sanitize phone format
    phone = phone.strip()
    try:
        validate_phone_number(phone)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": str(e),
            },
        )

    # Sanitize phone: remove spaces, dashes, parentheses for Telegram API
    phone = "+" + "".join(c for c in phone[1:] if c.isdigit())

    # Create session directory
    try:
        session_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session '{name}' already exists").format(name=safe_name),
            },
        )

    try:
        # Save account info with disconnected status
        account_info = {
            "phone": phone,
            "status": "disconnected",
        }
        save_account_info(session_dir, account_info)

        # Store credentials if provided
        if has_api_id and has_api_hash:
            cred_manager = SecureCredentialManager(ensure_data_dir())
            cred_manager.store_credentials(
                session_id=safe_name,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=proxy_id,
            )
            logger.info(f"Session '{safe_name}' saved with credentials")
        else:
            logger.info(f"Session '{safe_name}' saved without credentials (will need config later)")

        # Create config.json so session is visible in list_stored_sessions
        session_config: dict[str, int | str | None] = {
            "api_id": api_id,
            "api_hash": api_hash,
            "proxy_id": proxy_id,
            "source": "phone",
        }
        config_path = session_dir / "config.json"
        config_content = json.dumps(session_config, indent=2).encode("utf-8")
        atomic_write(config_path, config_content)
        secure_file_permissions(config_path)

        # Return success message
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": True,
                "message": _("Session '{name}' saved successfully. It will appear as 'disconnected' in the list.").format(name=safe_name),
            },
        )

    except Exception:
        logger.exception(f"Failed to save session '{safe_name}'")
        # Clean up on failure
        if session_dir.exists():
            import shutil
            shutil.rmtree(session_dir, ignore_errors=True)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Failed to save session. Please try again."),
            },
        )


@router.post("/api/sessions/auth/code", response_class=HTMLResponse)
async def submit_auth_code(
    request: Request,
    auth_id: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> HTMLResponse:
    """Submit verification code to complete auth or request 2FA.

    Returns HTML partial with:
    - Success message if auth completed
    - 2FA form if password required
    - Error message if code invalid
    """
    import asyncio

    from telethon.errors import (
        PhoneCodeEmptyError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
        )

    # Validate code format (digits only)
    code = code.strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) < 5:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Invalid code format. Please enter the numeric code you received."),
            },
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
        )

    try:
        # Try to sign in with code
        await asyncio.wait_for(
            client.sign_in(
                phone=auth_state.phone,
                code=code,
                phone_code_hash=auth_state.phone_code_hash,
            ),
            timeout=30.0,
        )

        # Success! Save the session
        return await _complete_auth_flow(request, auth_state, templates, auth_manager)

    except SessionPasswordNeededError:
        # 2FA required
        await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
        logger.info(f"2FA required for auth '{auth_id}'")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
            },
        )

    except PhoneCodeInvalidError:
        await auth_manager.update_auth_state(auth_id, step=AuthStep.CODE_INVALID)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Invalid code. Please check and try again."),
            },
        )

    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Code has expired. Please start over."),
            },
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": get_user_friendly_message(e),
            },
        )

    except PhoneCodeEmptyError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Please enter the verification code."),
            },
        )

    except TimeoutError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Request timeout. Please try again."),
            },
        )

    except Exception:
        logger.exception(f"Failed to verify code for auth '{auth_id}'")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Failed to verify code. Please check the code and try again."),
            },
        )


@router.post("/api/sessions/auth/2fa", response_class=HTMLResponse)
async def submit_auth_2fa(
    request: Request,
    auth_id: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> HTMLResponse:
    """Submit 2FA password to complete auth.

    Returns HTML partial with success message or error.
    """
    import asyncio

    from telethon.errors import FloodWaitError, PasswordHashInvalidError

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(password, str) or len(password) > 256:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid password: must be at most 256 characters.")},
        )

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
        )

    if auth_state.step != AuthStep.NEED_2FA:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Invalid auth state. Please start over."),
            },
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
        )

    try:
        # Try to sign in with 2FA password
        # Separate try-except to prevent password leakage in traceback
        try:
            await asyncio.wait_for(
                client.sign_in(password=password),
                timeout=30.0,
            )
            password = None  # Clear immediately after success
        except Exception:
            password = None  # Clear before re-raising
            raise

        # Success! Save the session
        return await _complete_auth_flow(request, auth_state, templates, auth_manager)

    except PasswordHashInvalidError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Incorrect password. Please try again."),
            },
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": get_user_friendly_message(e),
            },
        )

    except TimeoutError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Request timeout. Please try again."),
            },
        )

    except Exception:
        logger.exception(f"Failed to verify 2FA for auth '{auth_id}'")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Failed to verify password. Please try again."),
            },
        )


async def _complete_auth_flow(
    request: Request,
    auth_state: AuthState,
    templates: Jinja2Templates,
    auth_manager: AuthStateManager,
) -> HTMLResponse:
    """Complete auth flow by saving session and credentials.

    Args:
        request: FastAPI request
        auth_state: Current auth state
        templates: Jinja2 templates
        auth_manager: Auth state manager

    Returns:
        HTML response with success or error message
    """
    import shutil

    from chatfilter.security import SecureCredentialManager

    client = auth_state.client
    if client is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Client connection lost. Please start over.")},
        )

    session_name = auth_state.session_name
    api_id = auth_state.api_id
    api_hash = auth_state.api_hash
    proxy_id = auth_state.proxy_id

    try:
        # Get account info
        me = await asyncio.wait_for(client.get_me(), timeout=30.0)
        account_info = {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }

        # Check for duplicates
        duplicate_sessions = []
        if isinstance(me.id, int):
            duplicate_sessions = find_duplicate_accounts(me.id, exclude_session=session_name)

        # Create session directory
        session_dir = ensure_data_dir() / session_name
        session_dir.mkdir(parents=True, exist_ok=True)
        session_path = session_dir / "session.session"

        # Disconnect client before copying session file
        await asyncio.wait_for(client.disconnect(), timeout=30.0)

        # Copy session file from temp location
        temp_dir = getattr(auth_state, "temp_dir", None)
        if temp_dir:
            temp_session_file = Path(temp_dir) / "auth_session.session"
            if temp_session_file.exists():
                shutil.copy2(temp_session_file, session_path)
                secure_file_permissions(session_path)

        # Store credentials securely
        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_credentials(session_name, api_id, api_hash)

        # Create per-session config.json
        # source is 'phone' because credentials came from auth flow
        session_config: dict[str, int | str | None] = {
            "api_id": api_id,
            "api_hash": api_hash,
            "proxy_id": proxy_id,
            "source": "phone",
        }
        session_config_path = session_dir / "config.json"
        session_config_content = json.dumps(session_config, indent=2).encode("utf-8")
        atomic_write(session_config_path, session_config_content)
        secure_file_permissions(session_config_path)

        # Create secure storage marker
        marker_text = (
            "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
            "Do not create a plaintext config.json file.\n"
        )
        marker_file = session_dir / ".secure_storage"
        atomic_write(marker_file, marker_text)

        # Save account info
        save_account_info(session_dir, account_info)

        # Clean up temp dir
        if temp_dir:
            secure_delete_dir(temp_dir)

        # Remove auth state
        await auth_manager.remove_auth_state(auth_state.auth_id)

        logger.info(f"Session '{session_name}' created successfully via auth flow")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": True,
                "message": _("Session '{name}' created successfully!").format(name=session_name),
                "account_info": account_info,
                "duplicate_sessions": duplicate_sessions,
            },
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception(f"Failed to complete auth flow for '{session_name}'")
        # Clean up on failure
        session_dir = ensure_data_dir() / session_name
        if session_dir.exists():
            shutil.rmtree(session_dir, ignore_errors=True)
        temp_dir = getattr(auth_state, "temp_dir", None)
        if temp_dir:
            secure_delete_dir(temp_dir)
        await auth_manager.remove_auth_state(auth_state.auth_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Failed to save session. Please try again or contact support."),
            },
        )




async def _poll_device_confirmation(
    safe_name: str,
    auth_id: str,
    auth_manager: AuthStateManager,
) -> None:
    """Background task to poll for device confirmation and auto-transition to connected.

    Polls GetAuthorizationsRequest every 5-10 seconds (with backoff) until:
    - User confirms on another device → call _finalize_reconnect_auth
    - Timeout (5 minutes) → cleanup and publish error
    - Auth state removed externally → exit silently

    Args:
        safe_name: Sanitized session name
        auth_id: Auth flow ID
        auth_manager: Auth state manager
    """
    from telethon.errors import AuthKeyUnregisteredError, RPCError
    from telethon.tl.functions.account import GetAuthorizationsRequest

    timeout_seconds = 300  # 5 minutes
    poll_interval = 5  # Start with 5 seconds
    max_poll_interval = 10  # Max 10 seconds
    start_time = time.time()

    logger.info(f"Starting device confirmation polling for session '{safe_name}' (timeout: {timeout_seconds}s)")

    try:
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout_seconds:
                # Check if finalization is already in progress (race condition guard)
                auth_state = await auth_manager.get_auth_state(auth_id)
                if auth_state and auth_state.finalizing:
                    logger.info(f"Device confirmation timeout for '{safe_name}' but finalization already in progress, skipping cleanup")
                    return

                logger.warning(f"Device confirmation timeout for session '{safe_name}' after {timeout_seconds}s")

                # Cleanup: disconnect client, remove state
                if auth_state and auth_state.client:
                    try:
                        await asyncio.wait_for(auth_state.client.disconnect(), timeout=10.0)
                    except Exception as e:
                        logger.error(f"Error disconnecting client during timeout cleanup: {e}")

                await auth_manager.remove_auth_state(auth_id)
                await get_event_bus().publish(safe_name, "disconnected")
                return

            # Get current auth state
            auth_state = await auth_manager.get_auth_state(auth_id)
            if not auth_state:
                # Auth state removed (e.g., expired, or user retried) — exit silently
                logger.debug(f"Auth state removed for '{safe_name}', stopping polling")
                return

            client = auth_state.client
            if not client:
                logger.error(f"No client in auth state for '{safe_name}', stopping polling")
                await get_event_bus().publish(safe_name, "error")
                return

            # Poll GetAuthorizationsRequest
            try:
                authorizations = await asyncio.wait_for(
                    client(GetAuthorizationsRequest()),
                    timeout=10.0
                )

                # Find current session
                current_session = next(
                    (auth for auth in authorizations.authorizations if auth.current),
                    None
                )

                # Check if still unconfirmed
                if current_session and getattr(current_session, 'unconfirmed', False):
                    # Still waiting for confirmation
                    logger.debug(f"Session '{safe_name}' still unconfirmed, continuing to poll")
                else:
                    # Confirmed! Set finalizing flag to prevent timeout race
                    auth_state.finalizing = True
                    logger.info(f"Device confirmation detected for session '{safe_name}', finalizing auth")

                    try:
                        await _finalize_reconnect_auth(
                            client, auth_state, auth_manager, safe_name, "device confirmation"
                        )
                    except Exception as e:
                        logger.error(f"Error finalizing reconnect auth after confirmation: {e}")
                        await auth_manager.remove_auth_state(auth_id)
                        await get_event_bus().publish(safe_name, "error")

                    return

            except AuthKeyUnregisteredError:
                # FATAL: Client session died during polling — cleanup and stop
                logger.error(
                    f"Session invalidated during device confirmation polling for '{safe_name}' - "
                    "disconnecting client and stopping"
                )

                # Disconnect client
                if client and client.is_connected():
                    try:
                        await asyncio.wait_for(client.disconnect(), timeout=10.0)
                    except Exception as e:
                        logger.error(f"Error disconnecting client during fatal error cleanup: {e}")

                # Remove auth state
                await auth_manager.remove_auth_state(auth_id)

                # Signal frontend (keep 'error' event for compatibility)
                await get_event_bus().publish(safe_name, "error")
                return
            except TimeoutError:
                # API call timeout — log and continue
                logger.warning(f"Timeout polling device confirmation for '{safe_name}', will retry")
            except RPCError as e:
                # Telegram API error — could be serious
                logger.error(f"Telegram API error polling device confirmation for '{safe_name}': {e}")

                # Disconnect client
                if client and client.is_connected():
                    try:
                        await asyncio.wait_for(client.disconnect(), timeout=10.0)
                    except Exception as disconnect_err:
                        logger.error(f"Error disconnecting client during fatal error cleanup: {disconnect_err}")

                await auth_manager.remove_auth_state(auth_id)
                await get_event_bus().publish(safe_name, "error")
                return
            except Exception as e:
                # Unexpected error
                logger.error(f"Unexpected error polling device confirmation for '{safe_name}': {e}")

                # Disconnect client
                if client and client.is_connected():
                    try:
                        await asyncio.wait_for(client.disconnect(), timeout=10.0)
                    except Exception as disconnect_err:
                        logger.error(f"Error disconnecting client during fatal error cleanup: {disconnect_err}")

                await auth_manager.remove_auth_state(auth_id)
                await get_event_bus().publish(safe_name, "error")
                return

            # Exponential backoff (5s → 10s)
            await asyncio.sleep(poll_interval)
            poll_interval = min(poll_interval * 1.5, max_poll_interval)

    except asyncio.CancelledError:
        # Task cancelled (e.g., app shutdown)
        logger.info(f"Device confirmation polling cancelled for session '{safe_name}'")
        raise


async def _handle_needs_confirmation(
    safe_name: str,
    auth_id: str,
    auth_manager: AuthStateManager,
    request: Request,
    log_context: str,
) -> HTMLResponse:
    """Return needs_confirmation session_row and update auth state.

    Helper to avoid code duplication across verify-code, verify-2fa, and auto-2FA paths.

    Launches a background task to poll for device confirmation and auto-transition to connected.

    Args:
        safe_name: Sanitized session name
        auth_id: Auth flow ID
        auth_manager: Auth state manager
        request: FastAPI request for template rendering
        log_context: Context string for log message (e.g., "verify-code", "auto 2FA")

    Returns:
        TemplateResponse with needs_confirmation session_row
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep

    # Update auth state to track confirmation
    await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_CONFIRMATION)

    # Publish SSE event so UI updates (use module-level import)
    await get_event_bus().publish(safe_name, "needs_confirmation")

    logger.info(f"Session '{safe_name}' requires device confirmation ({log_context})")

    # Launch background polling task only if not already running (deduplication)
    auth_state = await auth_manager.get_auth_state(auth_id)
    if auth_state and (auth_state.polling_task is None or auth_state.polling_task.done()):
        polling_task = asyncio.create_task(_poll_device_confirmation(safe_name, auth_id, auth_manager))
        auth_state.polling_task = polling_task
        logger.info(f"Launched device confirmation polling task for session '{safe_name}'")
    else:
        logger.debug(f"Polling task already running for session '{safe_name}', skipping duplicate launch")

    # Return needs_confirmation session_row
    session_path = ensure_data_dir() / safe_name / "session.session"
    session_data = SessionListItem(
        session_id=safe_name,
        state="needs_confirmation",
        auth_id=auth_id,
        error_message=None,
        has_session_file=session_path.exists(),
        retry_available=None,
        flood_wait_until=_get_flood_wait_until(safe_name),
    )
    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/session_row.html",
        context=get_template_context(request, session=session_data),
    )


async def _check_device_confirmation(client: TelegramClient) -> bool:
    """Check if current session requires device confirmation.

    After successful sign_in, Telegram may require the user to confirm
    the login from another device ("Is this you?" prompt).

    Args:
        client: Connected and authenticated TelegramClient

    Returns:
        True if session is waiting for device confirmation, False otherwise

    Raises:
        TimeoutError: If API call times out
        TelegramError: Other Telegram API errors that indicate real problems
    """
    import asyncio

    from telethon.errors import AuthKeyUnregisteredError, RPCError
    from telethon.tl.functions.account import GetAuthorizationsRequest

    try:
        # Get all authorizations for this account
        authorizations = await asyncio.wait_for(
            client(GetAuthorizationsRequest()),
            timeout=10.0
        )

        # Find current session (the one we just logged into)
        current_session = next(
            (auth for auth in authorizations.authorizations if auth.current),
            None
        )

        # Check if current session is unconfirmed
        # unconfirmed flag indicates "Is this you?" pending
        if current_session and getattr(current_session, 'unconfirmed', False):
            return True

        return False

    except TimeoutError:
        # Timeout checking confirmation status — log but don't fail auth
        # Better to proceed than block on edge case
        logger.warning("Timeout checking device confirmation status - assuming no confirmation needed")
        return False
    except AuthKeyUnregisteredError:
        # AuthKeyUnregisteredError after successful sign_in() indicates a problem,
        # NOT device confirmation. Device confirmation is detected via 'unconfirmed' flag only.
        logger.warning("Unexpected AuthKeyUnregisteredError after successful sign_in - this indicates an issue, not device confirmation")
        return False
    except RPCError as e:
        # Telegram API error — this could be a real problem, re-raise
        logger.error(f"Telegram API error checking device confirmation: {e}")
        raise
    except Exception as e:
        # Unexpected error — log and assume no confirmation needed
        # (better to proceed than block, but log for investigation)
        logger.warning(f"Unexpected error checking device confirmation status: {e}", exc_info=True)
        return False


async def _finalize_reconnect_auth(
    client: TelegramClient,
    auth_state: AuthState,
    auth_manager: AuthStateManager,
    safe_name: str,
    log_context: str,
) -> None:
    """Finalize reconnect auth: save session file, adopt client, clean up.

    Common logic used after successful code verification or 2FA in reconnect flows.
    Adopts the existing connected client instead of disconnecting and reconnecting.

    Args:
        client: Connected and authenticated TelegramClient (will be adopted by SessionManager)
        auth_state: Current auth state (will be removed)
        auth_manager: Auth state manager
        safe_name: Sanitized session name
        log_context: Context string for log message (e.g. "code verified", "2FA verified")

    Raises:
        FileNotFoundError: If session directory doesn't exist
    """
    session_dir = ensure_data_dir() / safe_name
    if not session_dir.exists():
        await auth_manager.remove_auth_state(auth_state.auth_id)
        raise FileNotFoundError(f"Session directory not found for '{safe_name}'")

    session_path = session_dir / "session.session"

    # Get account info
    me = await asyncio.wait_for(client.get_me(), timeout=30.0)
    account_info = {
        "user_id": me.id,
        "phone": me.phone or "",
        "first_name": me.first_name or "",
        "last_name": me.last_name or "",
    }

    # Save session to disk (Telethon will save to the path it was initialized with)
    client.session.save()

    # Copy session file from temp location to existing session (with atomic write + backup)
    temp_dir = getattr(auth_state, "temp_dir", None)
    if temp_dir:
        temp_session_file = Path(temp_dir) / "auth_session.session"
        if temp_session_file.exists():
            # Atomic write with backup to prevent corruption
            tmp_path = session_path.with_suffix('.session.tmp')
            backup_path = session_path.with_suffix('.session.bak')

            try:
                # 1. Write to temp file
                shutil.copy2(temp_session_file, tmp_path)
                secure_file_permissions(tmp_path)

                # 2. Backup existing session if it exists
                if session_path.exists():
                    shutil.copy2(session_path, backup_path)

                # 3. Atomic rename (POSIX guarantees atomicity)
                tmp_path.replace(session_path)

                # 4. Remove backup on success
                if backup_path.exists():
                    backup_path.unlink()

            except Exception as e:
                # Rollback: restore from backup if exists
                if backup_path.exists():
                    shutil.copy2(backup_path, session_path)
                    backup_path.unlink()
                    logger.warning(f"Session file write failed, restored from backup: {e}")

                # Clean up temp file if still exists
                if tmp_path.exists():
                    tmp_path.unlink()

                raise  # Re-raise to propagate error

        # Clean up temp dir
        secure_delete_dir(temp_dir)

    # Update account info
    save_account_info(session_dir, account_info)

    # Adopt the existing client into SessionManager (registers as CONNECTED and publishes SSE)
    from chatfilter.web.dependencies import get_session_manager
    session_manager = get_session_manager()

    try:
        await session_manager.adopt_client(safe_name, client)
    except Exception as e:
        # CRITICAL: adopt_client failed — client is orphaned
        # We have: authorized client, saved session file, BUT SessionManager doesn't track it
        # User will see "Disconnected" → retry connect → may create duplicate client
        logger.error(
            f"CRITICAL: adopt_client failed for '{safe_name}': {e}. "
            "Client is orphaned. Cleaning up connection and auth state."
        )

        # Cleanup orphaned client
        try:
            await client.disconnect()
            logger.info(f"Disconnected orphaned client for '{safe_name}'")
        except Exception as disconnect_err:
            logger.warning(f"Failed to disconnect orphaned client: {disconnect_err}")

        # Cleanup auth state
        try:
            await auth_manager.remove_auth_state(auth_state.auth_id)
            logger.info(f"Removed auth state after adopt_client failure for '{safe_name}'")
        except Exception as cleanup_err:
            logger.warning(f"Failed to remove auth state: {cleanup_err}")

        # Publish SSE error event (so UI shows error instead of hanging)
        from chatfilter.web.events import get_event_bus
        await get_event_bus().publish(safe_name, "error")

        # Re-raise original exception (don't swallow it)
        raise

    # Remove auth state
    await auth_manager.remove_auth_state(auth_state.auth_id)

    logger.info(f"Session '{safe_name}' re-authenticated successfully ({log_context})")
async def _do_connect_in_background_v2(session_id: str) -> None:
    """Background task that performs the actual Telegram connection (v2 - no registration).

    This version assumes the loader is already registered and state is already CONNECTING.
    This prevents race conditions from parallel requests.

    This runs after HTTP response is sent. Results are delivered via SSE.

    Handles ALL cases per SPEC (8-state model):
    1. No api_id/api_hash → publish 'needs_config'
    2. Proxy error → publish 'needs_config' with tooltip
    3. Banned → publish 'banned'
    4. No session.session → create client, send_code → publish 'needs_code'
    5. session.session expired/revoked → auto-delete file, send_code → publish 'needs_code'
    6. session.session corrupted → auto-delete file, send_code → publish 'needs_code'
    7. Valid session → connect → publish 'connected'
    8. Needs 2FA → publish 'needs_2fa' (handled by auth flow, not here)
    9. Any other error → publish 'error' with tooltip

    No more 'session_expired', 'corrupted_session', 'flood_wait', 'proxy_error' SSE events.
    """
    import asyncio
    import struct

    from telethon.errors import (
        ApiIdInvalidError,
        AuthKeyUnregisteredError,
        PhoneNumberBannedError,
        SessionExpiredError,
        SessionRevokedError,
        UserDeactivatedBanError,
        UserDeactivatedError,
    )

    from chatfilter.telegram.error_mapping import get_user_friendly_message
    from chatfilter.telegram.session_manager import (
        SessionConnectError,
        SessionInvalidError,
        SessionReauthRequiredError,
    )
    from chatfilter.web.dependencies import get_session_manager
    from chatfilter.web.events import get_event_bus

    # Exception types that indicate session file is invalid and needs auto-recovery
    _SESSION_INVALID_CAUSES = (
        AuthKeyUnregisteredError,
        SessionRevokedError,
        SessionExpiredError,
        SessionFileError,
        struct.error,
    )
    # Exception types that indicate account is banned (terminal state)
    _BANNED_CAUSES = (
        UserDeactivatedBanError,
        UserDeactivatedError,
        PhoneNumberBannedError,
    )

    # Acquire per-session lock to prevent parallel operations
    lock = await _get_session_lock(session_id)
    async with lock:
        session_manager = get_session_manager()
        session_path: Path | None = None
        config_path: Path | None = None

        try:
            # Get paths from the registered factory (loader), NOT from _sessions.
            # register() stores in _factories; _sessions entry is only created by connect().
            factory = session_manager._factories.get(session_id)
            if not factory:
                logger.error(f"Session '{session_id}' factory not found in _do_connect_in_background_v2")
                await get_event_bus().publish(session_id, "error")
                return

            # Extract paths from the factory (TelegramClientLoader has session_path/config_path)
            if hasattr(factory, 'session_path'):
                session_path = factory.session_path
                config_path = session_path.parent / "config.json"
                session_dir = session_path.parent

            # CASE 1: Check config validity (no api_id/api_hash or proxy missing)
            # This catches ApiIdInvalidError BEFORE attempting connection
            config_status, config_reason = get_session_config_status(session_dir)
            if config_status == "needs_config":
                # Missing credentials or proxy → needs_config
                logger.warning(f"Session '{session_id}' has config issue: {config_reason}")
                error_message = config_reason or "Configuration incomplete"
                safe_error_message = sanitize_error_message_for_client(error_message, "needs_config")
                if config_path:
                    _save_error_to_config(config_path, safe_error_message, retry_available=False)
                await get_event_bus().publish(session_id, "needs_config")
                return

            # PRE-CONNECT DIAGNOSTIC: Check SOCKS5 proxy health before wasting 30s on timeout
            # SECURITY: Don't include proxy.name in SSE messages (may contain credentials)
            proxy_id = getattr(factory, '_proxy_id', None)
            proxy_entry = None
            if proxy_id:
                from chatfilter.config import ProxyType
                from chatfilter.service.proxy_health import socks5_tunnel_check
                from chatfilter.storage.errors import StorageNotFoundError
                from chatfilter.storage.proxy_pool import get_proxy_by_id

                try:
                    proxy_entry = get_proxy_by_id(proxy_id)
                    # Only check SOCKS5 proxies (HTTP proxies use different protocol)
                    if proxy_entry.type == ProxyType.SOCKS5:
                        logger.debug(f"Running pre-connect proxy diagnostic for proxy ID: {proxy_id}")
                        proxy_ok = await socks5_tunnel_check(proxy_entry)
                        if not proxy_ok:
                            # Proxy is broken → early return with generic error
                            # SECURITY: Don't include proxy.name in logs (may contain credentials)
                            logger.warning(f"Pre-connect diagnostic failed: proxy ID {proxy_id} not responding")
                            error_message = (
                                "The proxy is not responding. "
                                "Please check proxy settings or switch to another proxy."
                            )
                            safe_error_message = sanitize_error_message_for_client(error_message, "proxy_error")
                            if session_id in session_manager._sessions:
                                session_manager._sessions[session_id].state = SessionState.ERROR
                                session_manager._sessions[session_id].error_message = safe_error_message
                            if config_path:
                                _save_error_to_config(config_path, safe_error_message, retry_available=True)
                            await get_event_bus().publish(session_id, "error")
                            return
                except StorageNotFoundError:
                    # Proxy ID in config but not in storage → will be caught by get_session_config_status
                    logger.warning(f"Proxy {proxy_id} not found in storage")

            # CASE 4: Check if session.session file exists (first time auth)
            # If missing → trigger send_code flow
            if not session_path.exists():
                logger.info(f"Session '{session_id}' has no session file, triggering send_code")
                # Load account_info for phone number
                account_info = load_account_info(session_dir)
                if not account_info or "phone" not in account_info:
                    logger.error(f"Cannot send code for session '{session_id}': phone number unknown")
                    error_message = "Phone number required"
                    safe_error_message = sanitize_error_message_for_client(error_message, "needs_config")
                    if config_path:
                        _save_error_to_config(config_path, safe_error_message, retry_available=False)
                    await get_event_bus().publish(session_id, "needs_config")
                    return

                phone = str(account_info["phone"])
                # Trigger send_code flow (with timeout protection)
                await _send_verification_code_with_timeout(
                    session_id,
                    session_path,
                    config_path,
                    phone,
                )
                return

            # CASE 7: Attempt connection with timeout (30 seconds)
            # session_manager.connect() creates _sessions entry and publishes SSE events
            await asyncio.wait_for(
                session_manager.connect(session_id),
                timeout=30.0
            )
            # Success - SSE "connected" event already published by session_manager

        except ApiIdInvalidError as e:
            # CASE 2: Invalid api_id/api_hash → needs_config
            logger.warning(f"Session '{session_id}' has invalid api_id/api_hash")
            error_message = get_user_friendly_message(e)
            safe_error_message = sanitize_error_message_for_client(error_message, "needs_config")
            if config_path:
                _save_error_to_config(config_path, safe_error_message, retry_available=False)
            await get_event_bus().publish(session_id, "needs_config")

        except (SessionInvalidError, SessionReauthRequiredError, SessionConnectError) as e:
            # session_manager.connect() wraps Telethon errors:
            #   SessionInvalidError  ← AuthKeyUnregistered, SessionRevoked, Banned
            #   SessionReauthRequiredError ← SessionExpired, SessionPasswordNeeded
            #   SessionConnectError  ← SessionFileError, struct.error, other
            # Inspect __cause__ to determine correct action.
            cause = e.__cause__

            if isinstance(cause, _BANNED_CAUSES):
                # CASE 3: Account banned → terminal state
                logger.warning(f"Session '{session_id}' is banned ({type(cause).__name__})")
                if config_path:
                    error_message = get_user_friendly_message(cause)
                    safe_error_message = sanitize_error_message_for_client(error_message, "banned")
                    _save_error_to_config(config_path, safe_error_message, retry_available=False)
                await get_event_bus().publish(session_id, "banned")

            elif isinstance(cause, _SESSION_INVALID_CAUSES):
                # CASE 5 & 6: Session expired/revoked/corrupted → auto-delete + send_code
                await _handle_session_recovery(
                    session_id, session_path, config_path, cause,
                )

            else:
                # Unknown cause → classify and publish
                logger.exception(f"Failed to connect session '{session_id}' in background")
                error_message = get_user_friendly_message(e)
                error_state = classify_error_state(error_message, exception=e)
                safe_error_message = sanitize_error_message_for_client(error_message, error_state)
                if config_path:
                    retry_available = error_state == "error"
                    _save_error_to_config(config_path, safe_error_message, retry_available=retry_available)
                await get_event_bus().publish(session_id, error_state)

        except TimeoutError:
            logger.warning(f"Connection timeout for session '{session_id}'")
            # Proxy-aware timeout: check if proxy was tested
            # SECURITY: Don't include proxy.name in logs (may contain credentials)
            if proxy_entry:
                logger.info(f"Timeout occurred with proxy ID: {proxy_entry.id}")
                error_message = (
                    "Telegram servers are not reachable through the proxy. "
                    "Try a different proxy or check your network."
                )
            else:
                error_message = "Connection timeout"
            safe_error_message = sanitize_error_message_for_client(error_message, "timeout")
            if session_id in session_manager._sessions:
                session_manager._sessions[session_id].state = SessionState.ERROR
                session_manager._sessions[session_id].error_message = safe_error_message
            if config_path:
                _save_error_to_config(config_path, safe_error_message, retry_available=True)
            await get_event_bus().publish(session_id, "error")

        except SessionBusyError:
            # Session is already busy - publish current state
            logger.warning(f"Session busy during background connect: {session_id}")
            info = session_manager.get_info(session_id)
            if info:
                await get_event_bus().publish(session_id, info.state.value)

        except Exception as e:
            logger.exception(f"Failed to connect session '{session_id}' in background")
            error_message = get_user_friendly_message(e)
            error_state = classify_error_state(error_message, exception=e)
            safe_error_message = sanitize_error_message_for_client(error_message, error_state)
            if config_path:
                retry_available = error_state == "error"
                _save_error_to_config(config_path, safe_error_message, retry_available=retry_available)
            await get_event_bus().publish(session_id, error_state)


async def _handle_session_recovery(
    session_id: str,
    session_path: Path | None,
    config_path: Path | None,
    cause: Exception,
) -> None:
    """Auto-recover from invalid/corrupted session: delete file and trigger send_code.

    Handles CASE 5 (expired/revoked) and CASE 6 (corrupted) from the SPEC.
    """
    from chatfilter.web.events import get_event_bus

    logger.info(f"Session '{session_id}' has invalid/corrupted session ({type(cause).__name__}), triggering reauth")

    if not session_path or not config_path:
        logger.error(f"Cannot reauth session '{session_id}': paths not available")
        await get_event_bus().publish(session_id, "error")
        return

    # Securely delete invalid session file
    secure_delete_file(session_path)

    # Load account_info (handles corrupted JSON gracefully - returns None on parse errors)
    session_dir = session_path.parent
    account_info = load_account_info(session_dir)
    if not account_info or "phone" not in account_info:
        logger.error(f"Cannot reauth session '{session_id}': phone number unknown or corrupted account info")
        error_message = _("Phone number required")
        safe_error_message = sanitize_error_message_for_client(error_message, "needs_config")
        if config_path:
            _save_error_to_config(config_path, safe_error_message, retry_available=False)
        await get_event_bus().publish(session_id, "needs_config")
        return

    phone = str(account_info["phone"])
    await _send_verification_code_with_timeout(
        session_id,
        session_path,
        config_path,
        phone,
    )


async def _send_verification_code_with_timeout(
    session_id: str,
    session_path: Path,
    config_path: Path,
    phone: str,
) -> None:
    """Wrapper: run _send_verification_code_and_create_auth with 30s timeout.

    If timeout occurs, publishes 'error' SSE and saves error to config.json.
    This prevents indefinite hangs if network operations stall.
    """
    import asyncio

    from chatfilter.web.events import get_event_bus

    try:
        await asyncio.wait_for(
            _send_verification_code_and_create_auth(
                session_id, session_path, config_path, phone
            ),
            timeout=30.0,
        )
    except TimeoutError:
        logger.warning(f"Verification code request timeout for session '{session_id}'")
        error_message = "Connection timeout"
        # Save error to config.json for UI display (Bug 2 fix)
        _save_error_to_config(config_path, error_message, retry_available=True)
        # Publish error via SSE
        await get_event_bus().publish(session_id, "error")


async def _send_verification_code_and_create_auth(
    session_id: str,
    session_path: Path,
    config_path: Path,
    phone: str,
) -> None:
    """Helper: send verification code and create AuthState for reconnect.

    This is the minimal difference from normal connection flow.
    Publishes 'needs_code' via SSE, then user completes auth via existing /api/sessions/auth/code.

    Retries transient network errors (ConnectionError, TimeoutError) with exponential backoff.
    Does NOT retry on permanent errors (AuthKeyUnregistered, PhoneNumberInvalid).

    NOTE: This function should be called via _send_verification_code_with_timeout() wrapper
    which enforces a 30s overall timeout to prevent indefinite hangs.
    """
    import asyncio
    import json

    from telethon import TelegramClient
    from telethon.errors import AuthKeyUnregisteredError, PhoneNumberInvalidError

    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id
    from chatfilter.telegram.error_mapping import get_user_friendly_message
    from chatfilter.telegram.retry import calculate_backoff_delay
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.events import get_event_bus

    def save_error_metadata(error_message: str, retry_available: bool) -> None:
        """Save error metadata to config.json for SSE/UI display."""
        try:
            with config_path.open("r") as f:
                config = json.load(f)
            config["error_message"] = error_message
            config["retry_available"] = retry_available
            config_content = json.dumps(config, indent=2).encode("utf-8")
            atomic_write(config_path, config_content)
        except Exception:
            logger.exception(f"Failed to save error metadata for session '{session_id}'")

    # Load config once (no retry needed for local file read)
    try:
        with config_path.open("r") as f:
            config = json.load(f)
        api_id = config["api_id"]
        api_hash = config["api_hash"]
        proxy_id = config["proxy_id"]
    except Exception as e:
        logger.exception(f"Failed to load config for session '{session_id}'")
        error_message = get_user_friendly_message(e)
        error_state = classify_error_state(error_message, exception=e)
        # Config read failure is permanent (file corruption/missing)
        # Security: sanitize error message before publishing to client
        safe_error_message = sanitize_error_message_for_client(error_message, error_state)
        save_error_metadata(safe_error_message, retry_available=False)
        await get_event_bus().publish(session_id, error_state)
        return

    # Get proxy once (no retry needed)
    try:
        proxy_info = get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        # Security: sanitize error message before publishing to client
        error_message = f"Proxy '{proxy_id}' not found in pool"
        safe_error_message = sanitize_error_message_for_client(error_message, "needs_config")
        save_error_metadata(safe_error_message, retry_available=False)
        await get_event_bus().publish(session_id, "needs_config")
        return

    # Retry configuration
    max_attempts = 3
    retryable_exceptions = (ConnectionError, TimeoutError, asyncio.TimeoutError, OSError)
    non_retryable_exceptions = (AuthKeyUnregisteredError, PhoneNumberInvalidError)

    # Retry loop for network operations
    last_exception: Exception | None = None
    for attempt in range(max_attempts):
        try:
            # Create client, send code
            client = TelegramClient(
                str(session_path),
                api_id,
                api_hash,
                proxy=proxy_info.to_telethon_proxy(),
            )
            await asyncio.wait_for(client.connect(), timeout=15.0)

            result = await asyncio.wait_for(
                client.send_code_request(phone),
                timeout=15.0,
            )

            # Success - create auth state and publish
            auth_manager = get_auth_state_manager()
            await auth_manager.create_auth_state(
                session_name=session_id,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=proxy_id,
                phone=phone,
                phone_code_hash=result.phone_code_hash,
                client=client,
            )

            await get_event_bus().publish(session_id, "needs_code")
            return  # Success, exit

        except non_retryable_exceptions as e:
            # Permanent errors - do not retry
            logger.error(f"Non-retryable error for session '{session_id}': {type(e).__name__}")
            error_message = get_user_friendly_message(e)
            error_state = classify_error_state(error_message, exception=e)
            # Security: sanitize error message before publishing to client
            safe_error_message = sanitize_error_message_for_client(error_message, error_state)
            save_error_metadata(safe_error_message, retry_available=False)
            await get_event_bus().publish(session_id, error_state)
            return

        except retryable_exceptions as e:
            last_exception = e
            is_final_attempt = attempt == max_attempts - 1

            if is_final_attempt:
                # All retries exhausted - transient error
                logger.error(
                    f"Failed to send code for session '{session_id}' after {max_attempts} attempts: {e}"
                )
                error_message = get_user_friendly_message(e)
                error_state = classify_error_state(error_message, exception=e)
                # Security: sanitize error message before publishing to client
                safe_error_message = sanitize_error_message_for_client(error_message, error_state)
                save_error_metadata(safe_error_message, retry_available=True)
                await get_event_bus().publish(session_id, error_state)
                return
            else:
                # Retry with exponential backoff
                delay = calculate_backoff_delay(attempt, base_delay=1.0, max_delay=4.0, jitter=0.1)
                logger.warning(
                    f"Send code attempt {attempt + 1}/{max_attempts} failed for session '{session_id}' "
                    f"with {type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
                )
                await asyncio.sleep(delay)

        except Exception as e:
            # Unexpected error - treat as non-retryable
            logger.exception(f"Unexpected error sending code for session '{session_id}'")
            error_message = get_user_friendly_message(e)
            error_state = classify_error_state(error_message, exception=e)
            # Security: sanitize error message before publishing to client
            safe_error_message = sanitize_error_message_for_client(error_message, error_state)
            save_error_metadata(safe_error_message, retry_available=False)
            await get_event_bus().publish(session_id, error_state)
            return


@router.post("/api/sessions/{session_id}/connect", response_class=HTMLResponse)
async def connect_session(
    request: Request,
    session_id: str,
    background_tasks: BackgroundTasks,
) -> HTMLResponse:
    """Connect a session to Telegram.

    Returns immediately with 'connecting' state. Actual connection happens
    in background task, with final state delivered via SSE.
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_session_manager

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        session_data = SessionListItem(
            session_id=session_id,
            state="error",
            error_message=str(e),
            has_session_file=False,
            retry_available=False,  # Invalid session name is permanent error
            flood_wait_until=_get_flood_wait_until(session_id),
        )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
            status_code=status.HTTP_200_OK,
        )

    # Check if operation already in progress (prevents race condition)
    lock = await _get_session_lock(safe_name)
    if lock.locked():
        session_data = SessionListItem(
            session_id=safe_name,
            state="error",
            error_message="Operation already in progress",
            has_session_file=False,
            retry_available=True,  # Transient error, can retry later
            flood_wait_until=_get_flood_wait_until(safe_name),
        )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
            status_code=status.HTTP_200_OK,
        )

    session_dir = ensure_data_dir() / safe_name
    session_path = session_dir / "session.session"
    config_path = session_dir / "config.json"

    # Check if session exists (must have at least config.json)
    # Note: session.session can be missing (will trigger send_code flow)
    if not config_path.exists():
        # If session directory exists with .account_info.json, this is needs_config state
        # (account was saved but config.json wasn't created yet)
        account_info_path = session_dir / ".account_info.json"
        if session_dir.exists() and account_info_path.exists():
            session_data = SessionListItem(
                session_id=safe_name,
                state="needs_config",
                error_message="Session configuration required",
                has_session_file=session_path.exists(),
                retry_available=False,  # Must configure first
                flood_wait_until=_get_flood_wait_until(safe_name),
            )
        else:
            # Session directory doesn't exist or no account info - true error
            session_data = SessionListItem(
                session_id=safe_name,
                state="error",
                error_message="Session not found",
                has_session_file=False,
                retry_available=False,  # No config = permanent error
                flood_wait_until=_get_flood_wait_until(safe_name),
            )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
            status_code=status.HTTP_200_OK,
        )

    # Check if session is properly configured
    config_status, _config_reason = get_session_config_status(session_dir)
    if config_status == "needs_config":
        session_data = SessionListItem(
            session_id=safe_name,
            state="needs_config",
            error_message=_config_reason,
            has_session_file=session_path.exists(),
            retry_available=False,  # Must configure first
            flood_wait_until=_get_flood_wait_until(safe_name),
        )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
            status_code=status.HTTP_200_OK,
        )

    session_manager = get_session_manager()

    # Check current session state before attempting connect
    info = session_manager.get_info(safe_name)
    if info and info.state.value in ("connected", "connecting"):
        # Session is already connected or connecting
        session_data = SessionListItem(
            session_id=safe_name,
            state=info.state.value,
            error_message=None,
            has_session_file=session_path.exists(),
            retry_available=None,
            flood_wait_until=_get_flood_wait_until(safe_name),
        )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
            headers={"HX-Trigger": "refreshSessions"},
        )

    # FIX RACE CONDITION: Register loader and set state BEFORE scheduling background task
    # This prevents parallel requests from both seeing DISCONNECTED and scheduling duplicate tasks
    from chatfilter.telegram.session_manager import SessionState

    try:
        loader = TelegramClientLoader(session_path, config_path)
        loader.validate()
    except FileNotFoundError:
        # AC2: Session file doesn't exist - trigger send_code flow instead of error
        account_info = load_account_info(session_dir)
        if not account_info or not account_info.get("phone"):
            session_data = SessionListItem(
                session_id=safe_name,
                state="error",
                error_message="Phone number is required for new session",
                has_session_file=False,
                retry_available=False,  # Must configure phone first
                flood_wait_until=_get_flood_wait_until(safe_name),
            )
            return templates.TemplateResponse(
                request=request,
                name="partials/session_row.html",
                context=get_template_context(request, session=session_data),
                status_code=status.HTTP_200_OK,
            )

        phone = account_info["phone"]
        if not isinstance(phone, str):
            session_data = SessionListItem(
                session_id=safe_name,
                state="error",
                error_message="Invalid phone number format",
                has_session_file=False,
                retry_available=False,  # Must fix phone format first
                flood_wait_until=_get_flood_wait_until(safe_name),
            )
            return templates.TemplateResponse(
                request=request,
                name="partials/session_row.html",
                context=get_template_context(request, session=session_data),
                status_code=status.HTTP_200_OK,
            )

        # Trigger send_code flow in background (with timeout protection)
        background_tasks.add_task(
            _send_verification_code_with_timeout,
            safe_name,
            session_path,
            config_path,
            phone,
        )

        # Return connecting state (will transition to needs_code via SSE)
        # NOTE: Do NOT include HX-Trigger: refreshSessions here!
        # The session is not registered in session_manager yet, so a full
        # session list refresh would show it as "disconnected", immediately
        # reverting the "connecting" state we just set.
        # The SSE event from _send_verification_code_and_create_auth will
        # update the UI when the code is sent (needs_code) or on error.
        session_data = SessionListItem(
            session_id=safe_name,
            state="connecting",
            error_message=None,
            has_session_file=False,
            retry_available=None,
            flood_wait_until=_get_flood_wait_until(safe_name),
        )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
        )
    except Exception as e:
        # Validation error (bad config, missing files, etc.)
        from chatfilter.telegram.error_mapping import get_user_friendly_message
        error_message = get_user_friendly_message(e)
        session_data = SessionListItem(
            session_id=safe_name,
            state="error",
            error_message=error_message,
            has_session_file=session_path.exists(),
            retry_available=True,  # Validation errors are usually transient
            flood_wait_until=_get_flood_wait_until(safe_name),
        )
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
            status_code=status.HTTP_200_OK,
        )

    # Register loader factory (stores in _factories, NOT _sessions)
    session_manager.register(safe_name, loader)

    # Eagerly create _sessions entry so state is CONNECTING before background task runs.
    # This prevents race conditions from parallel requests and ensures get_info() works.
    from chatfilter.telegram.session_manager import ManagedSession
    async with session_manager._global_lock:
        session = session_manager._sessions.get(safe_name)
        if session:
            if session.state in (SessionState.CONNECTED, SessionState.CONNECTING):
                # Another request beat us to it — return current state
                session_data = {
                    "session_id": safe_name,
                    "state": session.state.value,
                    "error_message": None,
                }
                return templates.TemplateResponse(
                    request=request,
                    name="partials/session_row.html",
                    context=get_template_context(request, session=session_data),
                    headers={"HX-Trigger": "refreshSessions"},
                )
            session.state = SessionState.CONNECTING
        else:
            # Create ManagedSession with a client from the factory
            client = loader.create_client()
            session_manager._sessions[safe_name] = ManagedSession(
                client=client, state=SessionState.CONNECTING
            )

    # Now schedule background task (loader already registered, state already CONNECTING)
    background_tasks.add_task(
        _do_connect_in_background_v2,
        safe_name,
    )

    # Return immediately with 'connecting' state (template shows spinner)
    session_data = {
        "session_id": safe_name,
        "state": "connecting",
        "error_message": None,
    }

    return templates.TemplateResponse(
        request=request,
        name="partials/session_row.html",
        context=get_template_context(request, session=session_data),
    )


@router.post("/api/sessions/{session_id}/reconnect/start", response_class=HTMLResponse)
async def reconnect_session_start(
    request: Request,
    session_id: str,
    background_tasks: BackgroundTasks,
) -> HTMLResponse:
    """Start reconnect flow after credential change.

    Triggers send_code flow in background. Returns 'connecting' state immediately.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<div class="alert alert-error">{e}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_dir = ensure_data_dir() / safe_name
    session_path = session_dir / "session.session"
    config_path = session_dir / "config.json"

    if not config_path.exists():
        return HTMLResponse(
            content='<div class="alert alert-error">Session not found</div>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Load phone from account_info
    account_info = load_account_info(session_dir)
    if not account_info or not account_info.get("phone"):
        return HTMLResponse(
            content=f'<div class="alert alert-error">{_("Phone number required for re-authorization")}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    phone = account_info["phone"]
    if not isinstance(phone, str):
        return HTMLResponse(
            content=f'<div class="alert alert-error">{_("Invalid phone number format")}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Trigger send_code flow in background (with timeout protection)
    background_tasks.add_task(
        _send_verification_code_with_timeout,
        safe_name,
        session_path,
        config_path,
        phone,
    )

    # Return connecting state
    session_data = {
        "session_id": safe_name,
        "state": "connecting",
        "error_message": None,
    }
    return templates.TemplateResponse(
        request=request,
        name="partials/session_row.html",
        context=get_template_context(request, session=session_data),
    )


@router.post("/api/sessions/{session_id}/disconnect", response_class=HTMLResponse)
async def disconnect_session(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Disconnect a session from Telegram.

    Returns empty response; SSE OOB swap handles DOM update.
    """
    from chatfilter.web.dependencies import get_session_manager

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<span class="error">{e}</span>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_manager = get_session_manager()

    # Check current session state before attempting disconnect
    info = session_manager.get_info(safe_name)
    if info and info.state.value in ("disconnected", "disconnecting"):
        # Session is already disconnected or disconnecting — DOM already correct
        return HTMLResponse(content="", headers={"HX-Reswap": "none"})

    try:
        # Disconnect — this publishes "disconnected" via SSE event bus
        # (session_manager.py:440), which triggers an OOB swap that updates the <tr> in the DOM.
        await session_manager.disconnect(safe_name)

        # Return empty response with HX-Reswap:none so HTMX doesn't also try to swap the row,
        # which would race with SSE and cause htmx:swapError on the detached element.
        return HTMLResponse(content="", headers={"HX-Reswap": "none"})

    except Exception:
        logger.exception(f"Failed to disconnect session '{safe_name}'")

        # Publish state change event for SSE — this triggers OOB swap to update the row
        await get_event_bus().publish(safe_name, "error")

        # Return empty response; SSE OOB swap handles the DOM update.
        return HTMLResponse(content="", headers={"HX-Reswap": "none"})


@router.post("/api/sessions/{session_id}/verify-code", response_class=HTMLResponse)
async def verify_code(
    request: Request,
    session_id: str,
    auth_id: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> HTMLResponse:
    """Verify authentication code for an existing session.

    For sessions with needs_code status, verifies the code sent to the phone.
    Updates the session file on success and sets status to connected or needs_2fa.

    Returns HTML partial with:
    - Success message if auth completed (status -> connected)
    - 2FA form if password required (status -> needs_2fa)
    - Error message if code invalid
    """
    import asyncio

    from telethon.errors import (
        AuthKeyUnregisteredError,
        FloodWaitError,
        PhoneCodeEmptyError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(code, str):
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid code format.")},
            status_code=400,
        )

    # Security: Telegram codes are always 5-6 digits, reject any other format
    if not code.isdigit() or len(code) not in (5, 6):
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Code must be 5-6 digits.")},
            status_code=400,
        )

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
            status_code=400,
        )

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
            status_code=401,
        )

    # Check if auth is locked due to too many failed attempts
    is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)
    if is_locked:
        remaining_minutes = (remaining_seconds + 59) // 60  # Round up to nearest minute
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                    minutes=remaining_minutes
                ),
            },
            status_code=429,
        )

    # Verify this auth state is for the correct session
    if auth_state.session_name != safe_name:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session mismatch. Please start over."),
            },
            status_code=400,
        )

    # Validate code format (digits only)
    code = code.strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) < 5:
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Invalid code format. Please enter the numeric code you received."),
            },
            status_code=400,
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
            status_code=502,
        )

    try:
        # Try to sign in with code
        await asyncio.wait_for(
            client.sign_in(
                phone=auth_state.phone,
                code=code,
                phone_code_hash=auth_state.phone_code_hash,
            ),
            timeout=30.0,
        )


        # Check if session requires device confirmation ("Is this you?" prompt)
        needs_confirmation = await _check_device_confirmation(client)

        if needs_confirmation:
            return await _handle_needs_confirmation(
                safe_name=safe_name,
                auth_id=auth_id,
                auth_manager=auth_manager,
                request=request,
                log_context="verify-code",
            )

        # Success! Finalize reconnect auth
        try:
            await _finalize_reconnect_auth(
                client, auth_state, auth_manager, safe_name, "code verified"
            )
        except FileNotFoundError:
            await auth_manager.remove_auth_state(auth_id)
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={"success": False, "error": _("Session directory not found.")},
                status_code=500,
            )
        except Exception as e:
            logger.error(f"Error finalizing reconnect auth after code verification: {e}")
            await auth_manager.remove_auth_state(auth_id)
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={"success": False, "error": _("Failed to finalize connection. Please try Connect again.")},
            )

        # Get updated session data after reconnect
        from chatfilter.web.dependencies import get_session_manager
        session_manager = get_session_manager()
        all_sessions = list_stored_sessions(session_manager, auth_manager)
        session_data = next(
            (s for s in all_sessions if s.session_id == safe_name),
            None
        )

        # Fallback if session not found (shouldn't happen, but be defensive)
        if session_data is None:
            session_data = SessionListItem(
                session_id=safe_name,
                state="connected",
                has_session_file=True,
                retry_available=False,
                flood_wait_until=_get_flood_wait_until(safe_name),
            )

        # Return session row HTML (tr element)
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
        )

    except SessionPasswordNeededError:
        # 2FA required — attempt auto-login with stored password (SPEC.md AC #4)
        # Flow: sign_in(code) → SessionPasswordNeededError → sign_in(password) → success or manual form
        from telethon.errors import PasswordHashInvalidError

        from chatfilter.security import SecureCredentialManager

        session_dir = ensure_data_dir() / safe_name
        session_path = session_dir / "session.session"
        manager = SecureCredentialManager(session_dir)

        # Try to retrieve stored 2FA password (returns None if not found)
        stored_2fa_password = manager.retrieve_2fa(safe_name)

        if stored_2fa_password:
            logger.info(f"Found stored 2FA password for session '{safe_name}', attempting auto-login")

            # Attempt automatic sign-in with stored 2FA password
            try:
                await asyncio.wait_for(
                    client.sign_in(password=stored_2fa_password),
                    timeout=30.0,
                )


                # Check if session requires device confirmation
                needs_confirmation = await _check_device_confirmation(client)

                if needs_confirmation:
                    return await _handle_needs_confirmation(
                        safe_name=safe_name,
                        auth_id=auth_id,
                        auth_manager=auth_manager,
                        request=request,
                        log_context="auto-2FA",
                    )

                # Success! Finalize reconnect auth
                try:
                    await _finalize_reconnect_auth(
                        client, auth_state, auth_manager, safe_name, "auto 2FA"
                    )
                except FileNotFoundError:
                    await auth_manager.remove_auth_state(auth_id)
                    return templates.TemplateResponse(
                        request=request,
                        name="partials/auth_result.html",
                        context={"success": False, "error": _("Session directory not found.")},
                        status_code=500,
                    )
                except Exception as e:
                    logger.error(f"Error finalizing reconnect auth after auto 2FA: {e}")
                    await auth_manager.remove_auth_state(auth_id)
                    return templates.TemplateResponse(
                        request=request,
                        name="partials/auth_result.html",
                        context={"success": False, "error": _("Failed to finalize connection. Please try Connect again.")},
                    )

                # Get updated session data after reconnect
                from chatfilter.web.dependencies import get_session_manager
                session_manager = get_session_manager()
                all_sessions = list_stored_sessions(session_manager, auth_manager)
                session_data = next(
                    (s for s in all_sessions if s.session_id == safe_name),
                    None
                )

                # Fallback if session not found (shouldn't happen, but be defensive)
                if session_data is None:
                    session_data = SessionListItem(
                        session_id=safe_name,
                        state="connected",
                        has_session_file=True,
                        retry_available=False,
                        flood_wait_until=_get_flood_wait_until(safe_name),
                    )

                # Return session row HTML (tr element)
                return templates.TemplateResponse(
                    request=request,
                    name="partials/session_row.html",
                    context=get_template_context(request, session=session_data),
                )

            except PasswordHashInvalidError:
                # Stored 2FA password is wrong/outdated - increment failed attempts and return needs_2fa row
                await auth_manager.increment_failed_attempts(auth_id)
                await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
                logger.warning(f"Stored 2FA password invalid for session '{safe_name}', returning needs_2fa row")
                # Emit event for 2FA requirement
                await get_event_bus().publish(safe_name, "needs_2fa")
                # Return session_row with needs_2fa state (proper tr element)
                session_data = SessionListItem(
                    session_id=safe_name,
                    state="needs_2fa",
                    auth_id=auth_id,
                    error_message=None,
                    has_session_file=session_path.exists(),
                    retry_available=None,
                    flood_wait_until=_get_flood_wait_until(safe_name),
                )
                return templates.TemplateResponse(
                    request=request,
                    name="partials/session_row.html",
                    context=get_template_context(request, session=session_data),
                    headers={"HX-Trigger": "refreshSessions"},
                )
        else:
            # No stored 2FA password - return needs_2fa row
            await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
            logger.info(f"2FA required for session '{safe_name}' auth (no stored password)")
            # Emit event for 2FA requirement
            await get_event_bus().publish(safe_name, "needs_2fa")
            # Return session_row with needs_2fa state (proper tr element)
            session_data = SessionListItem(
                session_id=safe_name,
                state="needs_2fa",
                auth_id=auth_id,
                error_message=None,
                has_session_file=session_path.exists(),
                retry_available=None,
                flood_wait_until=_get_flood_wait_until(safe_name),
            )
            return templates.TemplateResponse(
                request=request,
                name="partials/session_row.html",
                context=get_template_context(request, session=session_data),
                headers={"HX-Trigger": "refreshSessions"},
            )

    except PhoneCodeInvalidError:
        # Increment failed attempts and check if locked
        await auth_manager.increment_failed_attempts(auth_id)
        is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)

        if is_locked:
            remaining_minutes = (remaining_seconds + 59) // 60
            error_msg = _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                minutes=remaining_minutes
            )
        else:
            error_msg = _("Invalid code. Please check and try again.")

        await auth_manager.update_auth_state(auth_id, step=AuthStep.CODE_INVALID)
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": error_msg,
            },
            status_code=422,
        )

    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Code has expired. Please start over."),
            },
            status_code=422,
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "session_id": session_id,
                "error": get_user_friendly_message(e),
            },
            status_code=429,
        )

    except PhoneCodeEmptyError:
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Please enter the verification code."),
            },
            status_code=400,
        )

    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        # Update session state to needs_config and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info["error_message"] = f"Proxy connection failed during code verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        logger.error(f"Proxy connection failed during code verification for session '{safe_name}': {e}")
        await auth_manager.remove_auth_state(auth_id)
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
            status_code=502,
        )

    except TimeoutError:
        # Update session state to needs_config for timeout and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info["error_message"] = "Proxy connection timeout during code verification"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        await auth_manager.remove_auth_state(auth_id)
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Request timeout. Please try again."),
            },
            status_code=504,
        )

    except AuthKeyUnregisteredError:
        # AuthKeyUnregisteredError from sign_in() means the session is dead/expired
        # (device confirmation happens AFTER successful auth, not during sign_in)
        logger.error(f"AuthKeyUnregisteredError during code verification for session '{safe_name}' - session expired")
        await auth_manager.remove_auth_state(auth_id)
        await get_event_bus().publish(safe_name, "error")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Session expired or invalidated. Please reconnect your account."),
            },
            status_code=401,
        )

    except Exception:
        logger.exception(f"Failed to verify code for session '{safe_name}'")

        # Cleanup auth state to allow retry with Connect
        await auth_manager.remove_auth_state(auth_id)

        # Publish error state to SSE
        await get_event_bus().publish(safe_name, "error")

        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Code accepted. Connection failed — please try Connect again."),
            },
            status_code=500,
        )



@router.post("/api/sessions/{session_id}/verify-2fa", response_class=HTMLResponse)
async def verify_2fa(
    request: Request,
    session_id: str,
    auth_id: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> HTMLResponse:
    """Verify 2FA password for an existing session.

    For sessions with needs_2fa status, verifies the 2FA password.
    Updates the session file on success and sets status to connected.

    Returns HTML partial with:
    - Success message if auth completed (status -> connected)
    - Error message if password invalid
    """
    import asyncio

    from telethon.errors import (
        AuthKeyInvalidError,
        AuthKeyUnregisteredError,
        FloodWaitError,
        PasswordHashInvalidError,
        SessionRevokedError,
        UserDeactivatedBanError,
        UserDeactivatedError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(password, str) or len(password) > 256:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid password: must be at most 256 characters.")},
            status_code=400,
        )

    # Security: Reject empty or whitespace-only passwords
    if not password or not password.strip():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Password cannot be empty.")},
            status_code=400,
        )

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
            status_code=400,
        )

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
            status_code=410,
        )

    # Check if auth is locked due to too many failed attempts
    is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)
    if is_locked:
        remaining_minutes = (remaining_seconds + 59) // 60  # Round up to nearest minute
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                    minutes=remaining_minutes
                ),
            },
            status_code=429,
        )

    # Verify this auth state is for the correct session
    if auth_state.session_name != safe_name:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session mismatch. Please start over."),
            },
            status_code=400,
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
            status_code=502,
        )

    try:
        # Try to sign in with 2FA password
        # Separate try-except to prevent password leakage in traceback
        try:
            await asyncio.wait_for(
                client.sign_in(password=password),
                timeout=30.0,
            )
            password = None  # Clear immediately after success
        except Exception:
            password = None  # Clear before re-raising
            raise

        # Check if session requires device confirmation
        needs_confirmation = await _check_device_confirmation(client)

        if needs_confirmation:
            return await _handle_needs_confirmation(
                safe_name=safe_name,
                auth_id=auth_id,
                auth_manager=auth_manager,
                request=request,
                log_context="verify-2fa",
            )

        # Success! Finalize reconnect auth
        try:
            await _finalize_reconnect_auth(
                client, auth_state, auth_manager, safe_name, "2FA verified"
            )
        except FileNotFoundError:
            await auth_manager.remove_auth_state(auth_id)
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={"success": False, "error": _("Session directory not found.")},
                status_code=500,
            )
        except Exception as e:
            logger.error(f"Error finalizing reconnect auth after 2FA verification: {e}")
            await auth_manager.remove_auth_state(auth_id)
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={"success": False, "error": _("Failed to finalize connection. Please try Connect again.")},
                status_code=500,
            )

        # Get updated session data after reconnect
        from chatfilter.web.dependencies import get_session_manager
        session_manager = get_session_manager()
        all_sessions = list_stored_sessions(session_manager, auth_manager)
        session_data = next(
            (s for s in all_sessions if s.session_id == safe_name),
            None
        )

        # Fallback if session not found (shouldn't happen, but be defensive)
        if session_data is None:
            session_data = SessionListItem(
                session_id=safe_name,
                state="connected",
                has_session_file=True,
                retry_available=False,
                flood_wait_until=_get_flood_wait_until(safe_name),
            )

        # Return session row HTML (tr element)
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context=get_template_context(request, session=session_data),
        )

    except SessionRevokedError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This session has been revoked. Please delete and recreate the session.")},
            status_code=401,
        )

    except AuthKeyUnregisteredError:
        # AuthKeyUnregisteredError from sign_in() means the session is dead/expired
        # (device confirmation happens AFTER successful auth, not during sign_in)
        logger.error(f"AuthKeyUnregisteredError during 2FA verification for session '{safe_name}' - session expired")
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Session expired or invalidated. Please reconnect your account.")},
            status_code=401,
        )

    except AuthKeyInvalidError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Authorization key is invalid. Please delete and recreate the session.")},
            status_code=401,
        )

    except UserDeactivatedError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This account has been deactivated.")},
            status_code=401,
        )

    except UserDeactivatedBanError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This account has been banned.")},
            status_code=401,
        )

    except PasswordHashInvalidError:
        # Increment failed attempts and check if locked
        await auth_manager.increment_failed_attempts(auth_id)
        is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)

        if is_locked:
            remaining_minutes = (remaining_seconds + 59) // 60
            error_msg = _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                minutes=remaining_minutes
            )
        else:
            error_msg = _("Incorrect password. Please try again.")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": error_msg,
            },
            status_code=422,
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": get_user_friendly_message(e),
            },
            status_code=429,
        )

    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        # Update session state to needs_config and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info["error_message"] = f"Proxy connection failed during 2FA verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        logger.error(f"Proxy connection failed during 2FA verification for session '{safe_name}': {e}")
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
            status_code=502,
        )

    except TimeoutError:
        # Update session state to needs_config for timeout and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info["error_message"] = "Proxy connection timeout during 2FA verification"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Request timeout. Please try again."),
            },
            status_code=504,
        )

    except Exception:
        logger.exception(f"Failed to verify 2FA for session '{safe_name}'")

        # Cleanup auth state to allow retry with Connect
        await auth_manager.remove_auth_state(auth_id)

        # Publish error state to SSE
        await get_event_bus().publish(safe_name, "error")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Password accepted. Connection failed — please try Connect again."),
            },
            status_code=500,
        )

@router.post("/api/sessions/import/save", response_class=HTMLResponse)
async def save_import_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile, File()],
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Save an imported session with configuration.

    Args:
        json_file: JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial with save result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Sanitize session name (path traversal protection)
        try:
            safe_name = sanitize_session_name(session_name)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Check if session already exists
        session_dir = ensure_data_dir() / safe_name
        if session_dir.exists():
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Session '{name}' already exists").format(name=safe_name),
                },
            )

        # Read and validate session file
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid session: {error}").format(error=e)},
            )

        # Validate api_hash format (32-char hex string)
        api_hash = api_hash.strip()
        if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _(
                        "Invalid API hash format. Must be a 32-character hexadecimal string."
                    ),
                },
            )

        # Validate proxy exists
        from chatfilter.storage.errors import StorageNotFoundError
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        try:
            get_proxy_by_id(proxy_id)
        except StorageNotFoundError:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Selected proxy not found. Please select a valid proxy."),
                },
            )

        # Parse JSON file for account info (TelegramExpert format)
        twofa_password = None

        try:
            json_content = await read_upload_with_size_limit(
                json_file, MAX_JSON_SIZE, "JSON"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            json_data = json.loads(json_content)

            # Parse and validate JSON using dedicated parser module
            account_info, twofa_password = parse_telegram_expert_json(json_content, json_data)

        except ValueError as e:
            # Validation error from parser
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid JSON format: {error}").format(error=str(e))},
            )

        # Try to get user_id from session for duplicate check
        # JSON account_info is already prepared above as primary source
        import tempfile

        duplicate_sessions = []

        # Create a temporary session file to try extracting user_id
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        try:
            # Try to get user_id from session (best effort)
            session_account_info = await get_account_info_from_session(tmp_session_path, api_id, api_hash)

            # Add user_id to account_info if available from session
            if session_account_info and "user_id" in session_account_info:
                account_info["user_id"] = session_account_info["user_id"]

                # Check for duplicate accounts only if we have user_id
                user_id = session_account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(user_id, exclude_session=safe_name)

        finally:
            # Clean up temporary session file
            import contextlib

            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Save session files (directory created atomically by _save_session_to_disk)
        try:
            from chatfilter.utils.disk import DiskSpaceError

            # source is 'file' because session was imported from file
            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=proxy_id,
                account_info=account_info,
                source="file",
            )

            # Encrypt and save 2FA password if provided in JSON
            if twofa_password:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir.parent
                manager = SecureCredentialManager(storage_dir)
                manager.store_2fa(safe_name, twofa_password)
                logger.info(f"Stored encrypted 2FA for session: {safe_name}")

                # Update account_info to indicate 2FA is available
                if account_info:
                    account_info_data = load_account_info(session_dir) or {}
                    account_info_data["has_2fa"] = True
                    save_account_info(session_dir, account_info_data)

        except DiskSpaceError:
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Insufficient disk space. Please free up disk space and try again.")},
            )
        except TelegramConfigError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Configuration error. Please check your session file and credentials."),
                },
            )
        except Exception:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Failed to save session files. Please try again."),
                },
            )

        logger.info(f"Session '{safe_name}' imported successfully")

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": _("Session '{name}' imported successfully").format(name=safe_name),
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception("Unexpected error during session import")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during import. Please try again."),
            },
        )
