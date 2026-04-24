"""Session connect/disconnect/reconnect functionality."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastapi import BackgroundTasks, Request, status
from fastapi.responses import HTMLResponse

import chatfilter.web.dependencies as _web_deps
from chatfilter.i18n import _
from chatfilter.telegram.error_mapping import get_user_friendly_message
from chatfilter.telegram.session import (
    ManagedSession,
    SessionState,
)
from chatfilter.web.events import get_event_bus
from chatfilter.web.routers.sessions.background import (
    _do_connect_in_background_v2,
    _send_verification_code_with_timeout,
)
from chatfilter.web.routers.sessions.helpers import (
    SessionListItem,
    _get_flood_wait_until,
    _get_session_lock,
    sanitize_session_name,
)
from chatfilter.web.routers.sessions.io import (
    ensure_data_dir,
    load_account_info,
)
from chatfilter.web.routers.sessions.listing import (
    get_session_config_status,
)
from chatfilter.web.session import get_session
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    from fastapi import APIRouter

logger = logging.getLogger(__name__)


# Import router at module end to avoid circular import
# This works because Python executes imports in order, and by the time
# __init__.py imports connect.py, the router is already defined in __init__.py
def _get_router() -> APIRouter:
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

    # Shared admin pool: all admins write to "admin/"; power-users to "user_<id>/".
    from chatfilter.web.dependencies import get_pool_scope

    scope = get_pool_scope(request)
    session_dir = ensure_data_dir(scope) / safe_name
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

    session_manager = _web_deps.get_session_manager()

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
        # Access via module attribute so tests can mock at
        # chatfilter.web.routers.sessions.TelegramClientLoader
        import chatfilter.web.routers.sessions as _sessions_pkg

        loader = _sessions_pkg.TelegramClientLoader(session_path)
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

    # Persist the desired state so boot recovery can bring this session
    # back up automatically after a restart. Done synchronously here —
    # the connect itself runs in a background task, but the user's
    # *intent* is "connected", which should survive even if the
    # background connect later fails.
    from chatfilter.service.session_autoconnect import set_autoconnect

    set_autoconnect(config_path, True)

    # Pool routing (Phase 4): take the owner from the session's
    # .account_info.json. "admin" by default for every pre-Phase-4
    # session, or "user:{id}" when a power-user uploaded it.
    from chatfilter.web.routers.sessions.io import get_session_owner

    try:
        owner = get_session_owner(safe_name)
    except Exception:
        owner = "admin"
    session_manager.set_owner(safe_name, owner)

    # Eagerly create _sessions entry so state is CONNECTING before background task runs.
    # This prevents race conditions from parallel requests and ensures get_info() works.
    async with session_manager._global_lock:
        session = session_manager._sessions.get(safe_name)
        if session:
            if session.state in (SessionState.CONNECTED, SessionState.CONNECTING):
                # Another request beat us to it — return current state
                session_data = SessionListItem(
                    session_id=safe_name,
                    state=session.state.value,
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
            session.state = SessionState.CONNECTING
        else:
            # Create ManagedSession with a client from the factory
            client = loader.create_client()
            from .client_registry import register_client

            # Track the client under the caller's scope so the
            # register_client bookkeeping keeps working after the
            # shared-pool rename. "admin" covers every admin uploader.
            if scope:
                register_client(str(scope), client)
            session_manager._sessions[safe_name] = ManagedSession(
                client=client, state=SessionState.CONNECTING
            )

    # Now schedule background task (loader already registered, state already CONNECTING)
    background_tasks.add_task(
        _do_connect_in_background_v2,
        safe_name,
    )

    # Return immediately with 'connecting' state (template shows spinner)
    session_data = SessionListItem(
        session_id=safe_name,
        state="connecting",
        error_message=None,
        has_session_file=session_path.exists(),
        retry_available=None,
        flood_wait_until=_get_flood_wait_until(safe_name),
    )

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

    # Shared admin pool: all admins write to "admin/"; power-users to "user_<id>/".
    from chatfilter.web.dependencies import get_pool_scope

    scope = get_pool_scope(request)
    session_dir = ensure_data_dir(scope) / safe_name
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
    session_data = SessionListItem(
        session_id=safe_name,
        state="connecting",
        error_message=None,
        has_session_file=session_path.exists(),
        retry_available=None,
        flood_wait_until=_get_flood_wait_until(safe_name),
    )
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

    session_manager = _web_deps.get_session_manager()

    # Persist the user's intent to stay disconnected — boot recovery
    # skips this session on the next restart. Done BEFORE the actual
    # disconnect so that even if ``session_manager.disconnect`` fails
    # (network, race), the desired state is recorded. Best-effort: if
    # the config.json is unreachable, we still try to disconnect.
    from chatfilter.web.dependencies import get_pool_scope

    try:
        config_path = ensure_data_dir(get_pool_scope(request)) / safe_name / "config.json"
        from chatfilter.service.session_autoconnect import set_autoconnect

        set_autoconnect(config_path, False)
    except Exception:
        logger.warning("Could not write autoconnect=False for %s", safe_name, exc_info=True)

    # Check current session state before attempting disconnect
    info = session_manager.get_info(safe_name)
    if info and info.state.value in ("disconnected", "disconnecting"):
        # Session is already disconnected or disconnecting — DOM already correct
        return HTMLResponse(content="", headers={"HX-Reswap": "none"})

    # Capture client reference before disconnect so we can unregister it
    managed = session_manager._sessions.get(safe_name)
    client_to_unregister = managed.client if managed else None

    try:
        # Disconnect — this publishes "disconnected" via SSE event bus
        # (session_manager.py:440), which triggers an OOB swap that updates the <tr> in the DOM.
        await session_manager.disconnect(safe_name)

        # Unregister from client registry after successful disconnect
        if client_to_unregister is not None:
            user_id = get_session(request).get("user_id")
            if user_id is not None:
                from .client_registry import unregister_client

                unregister_client(str(user_id), client_to_unregister)

        # Return empty response with HX-Reswap:none so HTMX doesn't also try to swap the row,
        # which would race with SSE and cause htmx:swapError on the detached element.
        return HTMLResponse(content="", headers={"HX-Reswap": "none"})

    except Exception:
        logger.exception(f"Failed to disconnect session '{safe_name}'")

        # Publish state change event for SSE — this triggers OOB swap to update the row
        await get_event_bus().publish(safe_name, "error")

        # Return empty response; SSE OOB swap handles the DOM update.
        return HTMLResponse(content="", headers={"HX-Reswap": "none"})
