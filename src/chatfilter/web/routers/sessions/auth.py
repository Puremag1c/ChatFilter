"""Session authentication flow — new session from phone and reconnect verification."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import Form, Request
from fastapi.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.storage.helpers import atomic_write
from chatfilter.web.events import get_event_bus
from chatfilter.web.template_helpers import get_template_context

from .helpers import (
    SessionListItem,
    _get_flood_wait_until,
    ensure_data_dir,
    find_duplicate_accounts,
    list_stored_sessions,
    load_account_info,
    sanitize_session_name,
    save_account_info,
    secure_delete_dir,
    secure_file_permissions,
    validate_phone_number,
)

if TYPE_CHECKING:
    from starlette.templating import Jinja2Templates
    from telethon import TelegramClient

    from chatfilter.web.auth_state import AuthState, AuthStateManager

logger = logging.getLogger(__name__)


def _get_router():
    """Get router instance (lazy import to avoid circular dependency)."""
    from chatfilter.web.routers.sessions import router
    return router


router = _get_router()


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
    from telethon.errors import (
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
    - User confirms on another device -> call _finalize_reconnect_auth
    - Timeout (5 minutes) -> cleanup and publish error
    - Auth state removed externally -> exit silently

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

            # Exponential backoff (5s -> 10s)
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
        # User will see "Disconnected" -> retry connect -> may create duplicate client
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
        await get_event_bus().publish(safe_name, "error")

        # Re-raise original exception (don't swallow it)
        raise

    # Remove auth state
    await auth_manager.remove_auth_state(auth_state.auth_id)

    logger.info(f"Session '{safe_name}' re-authenticated successfully ({log_context})")


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
        # Flow: sign_in(code) -> SessionPasswordNeededError -> sign_in(password) -> success or manual form
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
