"""Device confirmation polling for session authentication."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import HTMLResponse

from chatfilter.web.events import get_event_bus
from chatfilter.web.template_helpers import get_template_context

from .helpers import (
    SessionListItem,
    _get_flood_wait_until,
    ensure_data_dir,
)

if TYPE_CHECKING:
    from telethon import TelegramClient

    from chatfilter.web.auth_state import AuthStateManager

logger = logging.getLogger(__name__)


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

    from .auth_reconnect_helpers import _finalize_reconnect_auth

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
