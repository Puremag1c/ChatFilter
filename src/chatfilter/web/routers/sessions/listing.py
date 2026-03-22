"""Session listing and status checking operations."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from chatfilter.storage.helpers import atomic_write

if TYPE_CHECKING:
    from chatfilter.telegram.session import SessionManager
    from chatfilter.web.auth_state import AuthStateManager

logger = logging.getLogger(__name__)


def get_session_config_status(session_dir: Path) -> tuple[str, str | None]:
    """Check session configuration status.

    Validates that the session has required configuration:
    - api_id and api_hash can be null (source=phone means user will provide via auth)
    - If api_id and api_hash are null, source must be 'phone'
    - If api_id and api_hash are set, source can be 'file' or 'phone'
    - proxy_id must be set (sessions require proxy for operation)
    - If proxy_id is set, the proxy must exist in the pool

    Args:
        session_dir: Path to session directory

    Returns:
        Tuple of (status, reason):
        - ("disconnected", None): Configuration is valid
        - ("needs_config", reason): Missing credentials or proxy configuration
          where reason is a specific message like "API credentials required"
    """
    config_file = session_dir / "config.json"

    if not config_file.exists():
        return ("needs_config", "Configuration file missing")

    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read config for session {session_dir.name}: {e}")
        return ("needs_config", "Configuration file corrupted")

    # Check fields
    api_id = config.get("api_id")
    api_hash = config.get("api_hash")
    proxy_id = config.get("proxy_id")

    # If api_id or api_hash are null, check encrypted storage first
    if api_id is None or api_hash is None:
        # Bug 1 fix: Check if credentials exist in SecureCredentialManager (Pattern A)
        try:
            from chatfilter.security import SecureCredentialManager

            storage_dir = session_dir.parent  # Pattern A: credentials stored at parent level

            # Guard: storage_dir must exist (addresses ChatFilter-hv39r)
            if not storage_dir.exists():
                return ("needs_config", "API credentials required")

            manager = SecureCredentialManager(storage_dir)
            session_name = session_dir.name

            # Check if encrypted credentials exist
            if manager.has_credentials(session_name):
                # Credentials exist in encrypted storage - continue to proxy check
                logger.debug(
                    f"Session '{session_name}' has credentials in encrypted storage, "
                    "continuing to proxy check"
                )
            else:
                # No credentials in encrypted storage or plaintext config
                return ("needs_config", "API credentials required")
        except Exception as e:
            # Handle corrupted .credentials.enc gracefully (addresses ChatFilter-f540m)
            # Treat as credentials absent
            # Redact exception message to prevent credential leakage
            logger.warning(
                f"Failed to check encrypted credentials for session '{session_dir.name}': "
                f"{type(e).__name__} [REDACTED]"
            )
            return ("needs_config", "API credentials required")

    # proxy_id is required for session to be connectable
    if not proxy_id:
        return ("needs_config", "Proxy configuration required")

    # Verify proxy exists in pool
    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id

    try:
        get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return ("needs_config", "Proxy not found in pool")

    return ("disconnected", None)


def list_stored_sessions(
    session_manager: SessionManager | None = None,
    auth_manager: AuthStateManager | None = None,
    user_id: str | int | None = None,
) -> list:
    """List all stored sessions with runtime state when available.

    Each session is validated for configuration status:
    - "disconnected": Ready to connect
    - "connected": Currently connected
    - "connecting": Connection in progress
    - "needs_code": Waiting for verification code (runtime state during auth)
    - "needs_2fa": Waiting for 2FA password (runtime state during auth)
    - "error": Connection error (generic)
    - "banned": Account banned by Telegram
    - "flood_wait": Temporary rate limit
    - "proxy_error": Proxy connection failed
    - "needs_config": Missing configuration (API credentials or proxy)

    Args:
        session_manager: Optional session manager to check runtime state
        auth_manager: Optional auth state manager to check auth flow state
        user_id: If provided, list only sessions for this user

    Returns:
        List of session info items
    """
    from chatfilter.telegram.flood_tracker import get_flood_tracker
    from chatfilter.telegram.session import SessionState
    from chatfilter.web.auth_state import AuthStep

    # Import from helpers to avoid duplication
    from .helpers import SessionListItem, classify_error_state, _get_flood_wait_until
    from .io import ensure_data_dir, load_account_info

    sessions = []
    data_dir = ensure_data_dir(user_id)
    flood_tracker = get_flood_tracker()

    for session_dir in data_dir.iterdir():
        if session_dir.is_dir():
            session_file = session_dir / "session.session"
            config_file = session_dir / "config.json"
            account_info_file = session_dir / ".account_info.json"

            if config_file.exists() or account_info_file.exists():
                session_id = session_dir.name

                # Handle missing account_info.json (old sessions)
                if not account_info_file.exists():
                    sessions.append(
                        SessionListItem(
                            session_id=session_id,
                            state="needs_config",
                            error_message="Account information missing",
                            auth_id=None,
                            has_session_file=session_file.is_file(),
                            flood_wait_until=_get_flood_wait_until(session_id),
                        )
                    )
                    continue

                # First check config status
                config_status, config_reason = get_session_config_status(session_dir)

                # For list display, map needs_config to disconnected.
                # Sessions saved without credentials are valid (spec: Save-only flow).
                # The connect_session endpoint will check credentials at connect time.
                if config_status == "needs_config":
                    config_status = "disconnected"
                    config_reason = None

                # If session manager available, check runtime state
                state = config_status
                error_message = config_reason if config_status == "needs_config" else None
                retry_available = None

                # If state is an error state from config, read error_message and retry_available
                if state in ("proxy_error", "banned", "flood_wait", "error"):
                    try:
                        with config_file.open("r", encoding="utf-8") as f:
                            config = json.load(f)
                        error_message = config.get("error_message")
                        retry_available = config.get("retry_available")
                    except Exception:
                        pass

                # Check if session has an active auth flow (highest priority)
                auth_id = None
                if auth_manager is not None:
                    auth_state = auth_manager.get_auth_state_by_session(session_id)
                    if auth_state:
                        auth_id = auth_state.auth_id
                        if auth_state.step in (AuthStep.PHONE_SENT, AuthStep.CODE_INVALID):
                            state = "needs_code"
                        elif auth_state.step == AuthStep.NEED_2FA:
                            state = "needs_2fa"
                        elif auth_state.step == AuthStep.NEED_CONFIRMATION:
                            state = "needs_confirmation"

                # Check runtime session state only if no auth flow and config is ready
                if (
                    session_manager is not None
                    and config_status == "disconnected"
                    and state == config_status
                ):
                    # Session is configured - check if it has runtime state
                    info = session_manager.get_info(session_id)
                    if info:
                        if info.state == SessionState.CONNECTED:
                            state = "connected"
                        elif info.state == SessionState.CONNECTING or info.state == SessionState.DISCONNECTING:
                            state = "connecting"
                        elif info.state == SessionState.ERROR:
                            error_message = info.error_message
                            state = classify_error_state(error_message)
                        # DISCONNECTED keeps config_status

                sessions.append(
                    SessionListItem(
                        session_id=session_id,
                        state=state,
                        error_message=error_message,
                        auth_id=auth_id,
                        has_session_file=session_file.is_file(),
                        retry_available=retry_available,
                        flood_wait_until=_get_flood_wait_until(session_id),
                    )
                )

    return sessions


def _save_error_to_config(config_path: Path, error_message: str, retry_available: bool) -> None:
    """Save error message to config.json for UI display."""
    try:
        with config_path.open("r") as f:
            config = json.load(f)
        config["error_message"] = error_message
        config["retry_available"] = retry_available
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_path, config_content)
    except Exception:
        logger.exception("Failed to save error message to config.json")
