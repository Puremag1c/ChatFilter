"""Fresh session creation from phone number."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import Form, Request
from fastapi.responses import HTMLResponse

from chatfilter.i18n import _
from chatfilter.storage.helpers import atomic_write
from chatfilter.web.events import get_event_bus
from chatfilter.web.template_helpers import get_template_context
# Access ensure_data_dir via module attribute so tests can mock at
# chatfilter.web.routers.sessions.ensure_data_dir
import chatfilter.web.routers.sessions as _sessions_pkg

from .helpers import (
    SessionListItem,
    _get_flood_wait_until,
    find_duplicate_accounts,
    sanitize_session_name,
    save_account_info,
    secure_delete_dir,
    secure_file_permissions,
    validate_phone_number,
)

if TYPE_CHECKING:
    from starlette.templating import Jinja2Templates

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

    # Check if session already exists (AFTER credential validation)
    session_dir = _sessions_pkg.ensure_data_dir() / safe_name
    if session_dir.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session '{name}' already exists").format(name=safe_name),
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
            cred_manager = SecureCredentialManager(_sessions_pkg.ensure_data_dir())
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
        session_dir = _sessions_pkg.ensure_data_dir() / session_name
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
        session_dir = _sessions_pkg.ensure_data_dir() / session_name
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
