"""Re-authentication of existing sessions."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import Form, Request
from fastapi.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.web.template_helpers import get_template_context

from .helpers import (
    SessionListItem,
    _get_flood_wait_until,
    ensure_data_dir,
    list_stored_sessions,
    load_account_info,
    sanitize_session_name,
    save_account_info,
    secure_delete_dir,
    secure_file_permissions,
)

if TYPE_CHECKING:
    from telethon import TelegramClient

    from chatfilter.web.auth_state import AuthState, AuthStateManager

logger = logging.getLogger(__name__)


def _get_router():
    """Get router instance (lazy import to avoid circular dependency)."""
    from chatfilter.web.routers.sessions import router
    return router


router = _get_router()


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

    from . import get_event_bus
    from .auth_device import _check_device_confirmation, _handle_needs_confirmation
    from .auth_errors import auth_code_form_error, auth_error_response
    from .auth_reconnect_helpers import (
        _attempt_auto_2fa_login,
        _finalize_and_return_session_row,
    )

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(code, str):
        return auth_error_response(request, templates, _("Invalid code format."))

    # Security: Telegram codes are always 5-6 digits, reject any other format
    if not code.isdigit() or len(code) not in (5, 6):
        return auth_error_response(request, templates, _("Code must be 5-6 digits."))

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return auth_error_response(request, templates, str(e))

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return auth_error_response(
            request,
            templates,
            _("Auth session expired or not found. Please start over."),
            status_code=401,
        )

    # Check if auth is locked due to too many failed attempts
    is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)
    if is_locked:
        remaining_minutes = (remaining_seconds + 59) // 60  # Round up to nearest minute
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                minutes=remaining_minutes
            ),
            status_code=429,
        )

    # Verify this auth state is for the correct session
    if auth_state.session_name != safe_name:
        return auth_error_response(
            request, templates, _("Auth session mismatch. Please start over.")
        )

    # Validate code format (digits only)
    code = code.strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) < 5:
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Invalid code format. Please enter the numeric code you received."),
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request,
            templates,
            _("Connection lost. Please start over."),
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
        return await _finalize_and_return_session_row(
            request=request,
            templates=templates,
            client=client,
            auth_state=auth_state,
            auth_manager=auth_manager,
            safe_name=safe_name,
            log_msg="code verified",
            auth_id=auth_id,
        )

    except SessionPasswordNeededError:
        # 2FA required — attempt auto-login with stored password (SPEC.md AC #4)
        return await _attempt_auto_2fa_login(
            request=request,
            templates=templates,
            client=client,
            auth_state=auth_state,
            auth_manager=auth_manager,
            safe_name=safe_name,
            session_id=session_id,
            auth_id=auth_id,
        )

    except PhoneCodeInvalidError:
        # Increment failed attempts and check if locked
        await auth_manager.increment_failed_attempts(auth_id)
        is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)

        if is_locked:
            remaining_minutes = (remaining_seconds + 59) // 60
            error_msg = _(
                "Too many failed attempts. Please try again in {minutes} minutes."
            ).format(minutes=remaining_minutes)
        else:
            error_msg = _("Invalid code. Please check and try again.")

        await auth_manager.update_auth_state(auth_id, step=AuthStep.CODE_INVALID)
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            error_msg,
            status_code=422,
        )

    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request,
            templates,
            _("Code has expired. Please start over."),
            status_code=422,
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            auth_state.session_name,
            session_id,
            get_user_friendly_message(e),
            status_code=429,
        )

    except PhoneCodeEmptyError:
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Please enter the verification code."),
        )

    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info[
            "error_message"
        ] = f"Proxy connection failed during code verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        logger.error(
            f"Proxy connection failed during code verification for session '{safe_name}': {e}"
        )
        await auth_manager.remove_auth_state(auth_id)
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Proxy connection failed. Please check your proxy settings and try again."),
            status_code=502,
        )

    except TimeoutError:
        # Update session state to needs_config for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info["error_message"] = "Proxy connection timeout during code verification"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        await auth_manager.remove_auth_state(auth_id)
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Request timeout. Please try again."),
            status_code=504,
        )

    except AuthKeyUnregisteredError:
        # Session is dead/expired
        logger.error(
            f"AuthKeyUnregisteredError during code verification for session '{safe_name}' - session expired"
        )
        await auth_manager.remove_auth_state(auth_id)
        await get_event_bus().publish(safe_name, "error")
        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Session expired or invalidated. Please reconnect your account."),
            status_code=401,
        )

    except Exception:
        logger.exception(f"Failed to verify code for session '{safe_name}'")

        # Cleanup auth state to allow retry with Connect
        await auth_manager.remove_auth_state(auth_id)

        # Publish error state to SSE
        await get_event_bus().publish(safe_name, "error")

        return auth_code_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Code accepted. Connection failed — please try Connect again."),
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

    from . import get_event_bus
    from .auth_device import _check_device_confirmation, _handle_needs_confirmation
    from .auth_errors import auth_2fa_form_error, auth_error_response
    from .auth_reconnect_helpers import _finalize_and_return_session_row

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(password, str) or len(password) > 256:
        return auth_error_response(
            request, templates, _("Invalid password: must be at most 256 characters.")
        )

    # Security: Reject empty or whitespace-only passwords
    if not password or not password.strip():
        return auth_error_response(request, templates, _("Password cannot be empty."))

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return auth_error_response(request, templates, str(e))

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return auth_error_response(
            request,
            templates,
            _("Auth session expired or not found. Please start over."),
            status_code=410,
        )

    # Check if auth is locked due to too many failed attempts
    is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)
    if is_locked:
        remaining_minutes = (remaining_seconds + 59) // 60
        return auth_2fa_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                minutes=remaining_minutes
            ),
            status_code=429,
        )

    # Verify this auth state is for the correct session
    if auth_state.session_name != safe_name:
        return auth_error_response(
            request, templates, _("Auth session mismatch. Please start over.")
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request,
            templates,
            _("Connection lost. Please start over."),
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
        return await _finalize_and_return_session_row(
            request=request,
            templates=templates,
            client=client,
            auth_state=auth_state,
            auth_manager=auth_manager,
            safe_name=safe_name,
            log_msg="2FA verified",
            auth_id=auth_id,
        )

    except SessionRevokedError:
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request,
            templates,
            _("This session has been revoked. Please delete and recreate the session."),
            status_code=401,
        )

    except AuthKeyUnregisteredError:
        logger.error(
            f"AuthKeyUnregisteredError during 2FA verification for session '{safe_name}' - session expired"
        )
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request,
            templates,
            _("Session expired or invalidated. Please reconnect your account."),
            status_code=401,
        )

    except AuthKeyInvalidError:
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request,
            templates,
            _("Authorization key is invalid. Please delete and recreate the session."),
            status_code=401,
        )

    except UserDeactivatedError:
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request, templates, _("This account has been deactivated."), status_code=401
        )

    except UserDeactivatedBanError:
        await auth_manager.remove_auth_state(auth_id)
        return auth_error_response(
            request, templates, _("This account has been banned."), status_code=401
        )

    except PasswordHashInvalidError:
        # Increment failed attempts and check if locked
        await auth_manager.increment_failed_attempts(auth_id)
        is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)

        if is_locked:
            remaining_minutes = (remaining_seconds + 59) // 60
            error_msg = _(
                "Too many failed attempts. Please try again in {minutes} minutes."
            ).format(minutes=remaining_minutes)
        else:
            error_msg = _("Incorrect password. Please try again.")

        return auth_2fa_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            error_msg,
            status_code=422,
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return auth_2fa_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            get_user_friendly_message(e),
            status_code=429,
        )

    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info[
            "error_message"
        ] = f"Proxy connection failed during 2FA verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        logger.error(
            f"Proxy connection failed during 2FA verification for session '{safe_name}': {e}"
        )
        await auth_manager.remove_auth_state(auth_id)
        return auth_2fa_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Proxy connection failed. Please check your proxy settings and try again."),
            status_code=502,
        )

    except TimeoutError:
        # Update session state to needs_config for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_config"
        account_info["error_message"] = "Proxy connection timeout during 2FA verification"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "needs_config")

        await auth_manager.remove_auth_state(auth_id)
        return auth_2fa_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Request timeout. Please try again."),
            status_code=504,
        )

    except Exception:
        logger.exception(f"Failed to verify 2FA for session '{safe_name}'")

        # Cleanup auth state to allow retry with Connect
        await auth_manager.remove_auth_state(auth_id)

        # Publish error state to SSE
        await get_event_bus().publish(safe_name, "error")

        return auth_2fa_form_error(
            request,
            templates,
            auth_id,
            auth_state.phone,
            safe_name,
            session_id,
            _("Password accepted. Connection failed — please try Connect again."),
            status_code=500,
        )
