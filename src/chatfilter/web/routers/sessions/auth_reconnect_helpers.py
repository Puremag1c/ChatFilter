"""Helper functions for auth_reconnect.py to reduce code duplication."""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from starlette.requests import Request
from starlette.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.web.events import get_event_bus
from chatfilter.web.template_helpers import get_template_context

from .helpers import (
    SessionListItem,
    _get_flood_wait_until,
    ensure_data_dir,
    list_stored_sessions,
    load_account_info,
    save_account_info,
    secure_delete_dir,
    secure_file_permissions,
)

if TYPE_CHECKING:
    from telethon import TelegramClient

    from chatfilter.web.auth_state import AuthState, AuthStateManager

logger = logging.getLogger(__name__)


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
            tmp_path = session_path.with_suffix(".session.tmp")
            backup_path = session_path.with_suffix(".session.bak")

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


async def _finalize_and_return_session_row(
    request: Request,
    templates,
    client: TelegramClient,
    auth_state: AuthState,
    auth_manager: AuthStateManager,
    safe_name: str,
    log_msg: str,
    auth_id: str,
) -> HTMLResponse:
    """Finalize reconnect auth and return session row HTML.

    Handles:
    - Calling _finalize_reconnect_auth()
    - Error handling for finalization
    - Fetching updated session data
    - Returning session_row.html template

    Returns HTMLResponse with either:
    - session_row.html (success)
    - auth_result.html (error)
    """
    try:
        await _finalize_reconnect_auth(
            client, auth_state, auth_manager, safe_name, log_msg
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
        logger.error(f"Error finalizing reconnect auth after {log_msg}: {e}")
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Failed to finalize connection. Please try Connect again."),
            },
        )

    # Get updated session data after reconnect
    from chatfilter.web.dependencies import get_session_manager

    session_manager = get_session_manager()
    all_sessions = list_stored_sessions(session_manager, auth_manager)
    session_data = next(
        (s for s in all_sessions if s.session_id == safe_name),
        None,
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


async def _attempt_auto_2fa_login(
    request: Request,
    templates,
    client: TelegramClient,
    auth_state: AuthState,
    auth_manager: AuthStateManager,
    safe_name: str,
    session_id: str,
    auth_id: str,
) -> Optional[HTMLResponse]:
    """Attempt automatic 2FA login with stored password.

    Returns:
    - HTMLResponse if 2FA is handled (either success or needs manual input)
    - None if no stored password exists (caller should handle manually)
    """
    from telethon.errors import PasswordHashInvalidError

    from chatfilter.security import SecureCredentialManager
    from chatfilter.web.auth_state import AuthStep

    from .auth_device import _check_device_confirmation, _handle_needs_confirmation

    session_dir = ensure_data_dir() / safe_name
    session_path = session_dir / "session.session"
    manager = SecureCredentialManager(session_dir)

    # Try to retrieve stored 2FA password (returns None if not found)
    stored_2fa_password = manager.retrieve_2fa(safe_name)

    if not stored_2fa_password:
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

    # Stored password exists - attempt auto-login
    logger.info(
        f"Found stored 2FA password for session '{safe_name}', attempting auto-login"
    )

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
        return await _finalize_and_return_session_row(
            request=request,
            templates=templates,
            client=client,
            auth_state=auth_state,
            auth_manager=auth_manager,
            safe_name=safe_name,
            log_msg="auto 2FA",
            auth_id=auth_id,
        )

    except PasswordHashInvalidError:
        # Stored 2FA password is wrong/outdated - increment failed attempts and return needs_2fa row
        await auth_manager.increment_failed_attempts(auth_id)
        await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
        logger.warning(
            f"Stored 2FA password invalid for session '{safe_name}', returning needs_2fa row"
        )
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
