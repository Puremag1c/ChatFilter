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
from .sse import register_sse_routes, session_events  # noqa: F401
register_sse_routes(router)

# Import connect module to register routes (must be after router definition)
from . import connect  # noqa: E402, F401

# Import basic CRUD routes
from . import routes  # noqa: F401

# Import upload and import routes
from . import upload  # noqa: F401

# Import auth module to register routes
from . import auth  # noqa: F401

# Re-export auth functions for backwards compatibility (used by tests)
from .auth import (  # noqa: F401
    _check_device_confirmation,
    _complete_auth_flow,
    _finalize_reconnect_auth,
    _handle_needs_confirmation,
    _poll_device_confirmation,
    start_auth_flow,
    submit_auth_2fa,
    submit_auth_code,
    verify_2fa,
    verify_code,
)

# Re-export connect functions for backwards compatibility (used by tests)
from .connect import (  # noqa: F401
    _send_verification_code_and_create_auth,
    _send_verification_code_with_timeout,
)

