"""Sessions router for session file upload and management."""

from __future__ import annotations

import json
import logging
import re
import shutil
import sqlite3
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from chatfilter.config import get_settings
from chatfilter.telegram.client import TelegramClientLoader, TelegramConfigError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sessions"])

# Maximum file sizes (security limit)
MAX_SESSION_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_CONFIG_SIZE = 1024  # 1 KB


class SessionListItem(BaseModel):
    """Session info for list response."""

    session_id: str
    state: str


def ensure_data_dir() -> Path:
    """Ensure sessions directory exists with proper permissions."""
    sessions_dir = get_settings().sessions_dir
    sessions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return sessions_dir


def secure_file_permissions(file_path: Path) -> None:
    """Set file permissions to 600 (owner read/write only).

    Args:
        file_path: Path to file to secure
    """
    import os
    import stat

    # chmod 600: owner read/write, no access for group/others
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


def secure_delete_file(file_path: Path) -> None:
    """Securely delete a file by overwriting before removal.

    Args:
        file_path: Path to file to securely delete
    """
    if not file_path.exists() or not file_path.is_file():
        return

    try:
        # Get file size
        file_size = file_path.stat().st_size

        # Overwrite with zeros
        with file_path.open("r+b") as f:
            f.write(b"\x00" * file_size)
            f.flush()
            import os

            os.fsync(f.fileno())

        # Delete the file
        file_path.unlink()
    except Exception as e:
        logger.warning(f"Failed to securely delete file, falling back to regular delete: {e}")
        # Fallback to regular deletion
        file_path.unlink(missing_ok=True)


def sanitize_session_name(name: str) -> str:
    """Sanitize session name to prevent path traversal.

    Args:
        name: User-provided session name

    Returns:
        Sanitized name (alphanumeric, underscore, hyphen only)

    Raises:
        ValueError: If name is invalid or empty after sanitization
    """
    # Remove any path components and keep only safe characters
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", name)
    if not sanitized:
        raise ValueError("Session name must contain at least one alphanumeric character")
    if len(sanitized) > 64:
        sanitized = sanitized[:64]
    return sanitized


def validate_session_file_format(content: bytes) -> None:
    """Validate that content is a valid SQLite database with Telethon schema.

    Args:
        content: File content as bytes

    Raises:
        ValueError: If file is not a valid Telethon session or has incompatible version
    """
    # Check SQLite header
    if not content.startswith(b"SQLite format 3"):
        raise ValueError("Not a valid SQLite database file")

    # Check for required Telethon tables by creating a temp database
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
        tmp.write(content)
        tmp.flush()

        try:
            conn = sqlite3.connect(tmp.name)
            cursor = conn.cursor()

            # Get all tables in the database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}

            # Telethon 1.x required tables
            required_tables = {"sessions", "entities"}

            # Check for Telethon 2.x format (incompatible)
            if "version" in tables and not required_tables.issubset(tables):
                conn.close()
                raise ValueError(
                    "Session file is from Telethon 2.x which is incompatible with this application. "
                    "Please generate a new session file using Telethon 1.x (version 1.34.0 or later). "
                    "Telethon 1.x and 2.x use different session formats that are not interchangeable."
                )

            # Check for required Telethon 1.x tables
            if not required_tables.issubset(tables):
                conn.close()
                raise ValueError(
                    f"Invalid session file format. Expected Telethon 1.x session with tables "
                    f"{required_tables}, but found: {tables}. "
                    "Please ensure you're uploading a valid Telethon session file."
                )

            # Check for session data
            cursor.execute("SELECT COUNT(*) FROM sessions")
            count = cursor.fetchone()[0]
            if count == 0:
                conn.close()
                raise ValueError(
                    "Session file is empty (no active session found). "
                    "Please use a session file that has been authenticated with Telegram."
                )

            conn.close()
        except sqlite3.Error as e:
            # Log the actual database error for debugging
            logger.error(f"SQLite database validation error: {e}")
            raise ValueError("Invalid database file") from e


def validate_config_file_format(content: bytes) -> dict:
    """Validate that content is a valid Telegram config JSON.

    Args:
        content: File content as bytes

    Returns:
        Parsed config dict

    Raises:
        ValueError: If file is not a valid config
    """
    try:
        config = json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid JSON format: {e}") from e

    if not isinstance(config, dict):
        raise ValueError("Config must be a JSON object")

    # Check required fields
    if "api_id" not in config:
        raise ValueError("Config missing required field: api_id")
    if "api_hash" not in config:
        raise ValueError("Config missing required field: api_hash")

    # Validate api_id type
    api_id = config["api_id"]
    if isinstance(api_id, str):
        try:
            int(api_id)
        except ValueError:
            raise ValueError("api_id must be an integer or numeric string") from None
    elif not isinstance(api_id, int):
        raise ValueError("api_id must be an integer")

    # Validate api_hash type
    api_hash = config["api_hash"]
    if not isinstance(api_hash, str) or not api_hash.strip():
        raise ValueError("api_hash must be a non-empty string")

    return config


def list_stored_sessions() -> list[SessionListItem]:
    """List all stored sessions.

    Returns:
        List of session info items
    """
    sessions = []
    data_dir = ensure_data_dir()

    for session_dir in data_dir.iterdir():
        if session_dir.is_dir():
            session_file = session_dir / "session.session"
            config_file = session_dir / "config.json"

            if session_file.exists() and config_file.exists():
                sessions.append(
                    SessionListItem(
                        session_id=session_dir.name,
                        state="disconnected",  # All sessions start disconnected
                    )
                )

    return sessions


@router.get("/api/sessions", response_class=HTMLResponse)
async def get_sessions(request: Request) -> HTMLResponse:
    """List all registered sessions as HTML partial."""
    from chatfilter.web.app import get_templates

    sessions = list_stored_sessions()
    templates = get_templates()

    return templates.TemplateResponse(
        "partials/sessions_list.html",
        {"request": request, "sessions": sessions},
    )


@router.post("/api/sessions/upload", response_class=HTMLResponse)
async def upload_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    config_file: Annotated[UploadFile, File()],
) -> HTMLResponse:
    """Upload a new session with config file.

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
                "partials/upload_result.html",
                {"request": request, "success": False, "error": str(e)},
            )

        # Check if session already exists
        session_dir = ensure_data_dir() / safe_name
        if session_dir.exists():
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {
                    "request": request,
                    "success": False,
                    "error": f"Session '{safe_name}' already exists",
                },
            )

        # Read and validate session file
        session_content = await session_file.read()
        if len(session_content) > MAX_SESSION_SIZE:
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {
                    "request": request,
                    "success": False,
                    "error": f"Session file too large (max {MAX_SESSION_SIZE // 1024 // 1024} MB)",
                },
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {"request": request, "success": False, "error": f"Invalid session: {e}"},
            )

        # Read and validate config file
        config_content = await config_file.read()
        if len(config_content) > MAX_CONFIG_SIZE:
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {
                    "request": request,
                    "success": False,
                    "error": f"Config file too large (max {MAX_CONFIG_SIZE} bytes)",
                },
            )

        try:
            config_data = validate_config_file_format(config_content)
        except ValueError as e:
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {"request": request, "success": False, "error": f"Invalid config: {e}"},
            )

        # Create session directory and save files
        session_dir.mkdir(parents=True, exist_ok=True)
        session_path = session_dir / "session.session"

        try:
            # Save session file
            session_path.write_bytes(session_content)
            secure_file_permissions(session_path)

            # Store credentials securely (NOT in plaintext)
            from chatfilter.security import SecureCredentialManager

            api_id = int(config_data["api_id"])
            api_hash = str(config_data["api_hash"])

            # Get storage directory (parent of session_dir)
            storage_dir = session_dir.parent

            # Store credentials in secure storage
            manager = SecureCredentialManager(storage_dir)
            manager.store_credentials(safe_name, api_id, api_hash)

            logger.info(f"Stored credentials securely for session: {safe_name}")

            # Create migration marker to indicate we're using secure storage
            marker_file = session_dir / ".secure_storage"
            marker_file.write_text(
                "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
                "Do not create a plaintext config.json file.\n"
            )

            # Validate that TelegramClientLoader can use secure storage
            loader = TelegramClientLoader(session_path, use_secure_storage=True)
            loader.validate()

        except TelegramConfigError as e:
            # Clean up on failure
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {"request": request, "success": False, "error": f"Config validation failed: {e}"},
            )
        except Exception:
            # Clean up on failure
            shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                "partials/upload_result.html",
                {
                    "request": request,
                    "success": False,
                    "error": "Failed to save session files. Please try again.",
                },
            )

        logger.info(f"Session '{safe_name}' uploaded successfully")

        return templates.TemplateResponse(
            "partials/upload_result.html",
            {
                "request": request,
                "success": True,
                "message": f"Session '{safe_name}' uploaded successfully",
            },
        )

    except Exception:
        logger.exception("Unexpected error during session upload")
        return templates.TemplateResponse(
            "partials/upload_result.html",
            {
                "request": request,
                "success": False,
                "error": "An unexpected error occurred during upload. Please try again.",
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
    return HTMLResponse(content="", status_code=200)
