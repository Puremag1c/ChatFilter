"""Session connect/disconnect/reconnect functionality."""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import BackgroundTasks, Form, Request, status
from fastapi.responses import HTMLResponse
from telethon import TelegramClient
from telethon.errors import (
    ApiIdInvalidError,
    AuthKeyUnregisteredError,
    PhoneNumberBannedError,
    PhoneNumberInvalidError,
    SessionExpiredError,
    SessionRevokedError,
    UserDeactivatedBanError,
    UserDeactivatedError,
)

from chatfilter.i18n import _
from chatfilter.storage.errors import StorageNotFoundError
from chatfilter.storage.file import secure_delete_file
from chatfilter.storage.helpers import atomic_write
from chatfilter.storage.proxy_pool import get_proxy_by_id
from chatfilter.telegram.error_mapping import get_user_friendly_message
from chatfilter.telegram.retry import calculate_backoff_delay
from chatfilter.telegram.client import SessionFileError, TelegramClientLoader
from chatfilter.telegram.session_manager import (
    ManagedSession,
    SessionBusyError,
    SessionConnectError,
    SessionInvalidError,
    SessionReauthRequiredError,
    SessionState,
)
from chatfilter.web.auth_state import get_auth_state_manager
from chatfilter.web.dependencies import get_session_manager
from chatfilter.web.events import get_event_bus
from chatfilter.web.routers.sessions.helpers import (
    _get_session_lock,
    _get_flood_wait_until,
    _save_error_to_config,
    classify_error_state,
    ensure_data_dir,
    get_session_config_status,
    load_account_info,
    sanitize_error_message_for_client,
    sanitize_session_name,
    SessionListItem,
)
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

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


# Import router at module end to avoid circular import
# This works because Python executes imports in order, and by the time
# __init__.py imports connect.py, the router is already defined in __init__.py
def _get_router():
    """Get router instance (lazy import to avoid circular dependency)."""
    from chatfilter.web.routers.sessions import router
    return router


router = _get_router()


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
