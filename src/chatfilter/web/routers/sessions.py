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
from chatfilter.storage.helpers import atomic_write
from chatfilter.telegram.client import TelegramClientLoader, TelegramConfigError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sessions"])

# Maximum file sizes (security limit)
MAX_SESSION_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_CONFIG_SIZE = 1024  # 1 KB
# Chunk size for reading uploaded files (to prevent memory exhaustion)
READ_CHUNK_SIZE = 8192  # 8 KB chunks


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


async def read_upload_with_size_limit(
    upload_file: UploadFile, max_size: int, file_type: str = "file"
) -> bytes:
    """Read uploaded file with size limit enforcement.

    Reads file in chunks to prevent loading large files into memory.
    Raises ValueError if file exceeds size limit.

    Args:
        upload_file: FastAPI UploadFile object
        max_size: Maximum allowed file size in bytes
        file_type: Description of file type for error messages

    Returns:
        File content as bytes

    Raises:
        ValueError: If file size exceeds max_size
    """
    chunks = []
    total_size = 0

    # Read file in chunks to enforce size limit without loading entire file
    while True:
        chunk = await upload_file.read(READ_CHUNK_SIZE)
        if not chunk:
            break

        total_size += len(chunk)
        if total_size > max_size:
            # Stop reading immediately to prevent memory exhaustion
            raise ValueError(
                f"{file_type.capitalize()} file too large "
                f"(max {max_size:,} bytes, got {total_size:,}+ bytes)"
            )

        chunks.append(chunk)

    return b"".join(chunks)


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


def validate_config_file_format(content: bytes) -> dict[str, str | int]:
    """Validate that content is a valid Telegram config JSON.

    Performs quick structural validation before parsing to prevent
    expensive parsing of obviously invalid files.

    Args:
        content: File content as bytes

    Returns:
        Parsed config dict

    Raises:
        ValueError: If file is not a valid config
    """
    # Quick structural validation before attempting to parse
    # This prevents expensive JSON parsing of obviously invalid files
    if len(content) == 0:
        raise ValueError("Config file is empty")

    # Decode and trim
    try:
        text = content.decode("utf-8").strip()
    except UnicodeDecodeError as e:
        raise ValueError(f"Config file contains invalid UTF-8: {e}") from e

    if not text:
        raise ValueError("Config file is empty or contains only whitespace")

    # Quick check: valid JSON objects must start with '{' and end with '}'
    if not text.startswith("{") or not text.endswith("}"):
        raise ValueError(
            "Config file does not appear to be a JSON object (must start with '{' and end with '}')"
        )

    # Now attempt full JSON parsing
    try:
        config = json.loads(text)
    except json.JSONDecodeError as e:
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


async def get_account_info_from_session(
    session_path: Path, api_id: int, api_hash: str
) -> dict[str, int | str] | None:
    """Extract account info from a session by connecting to Telegram.

    Args:
        session_path: Path to the session file
        api_id: Telegram API ID
        api_hash: Telegram API hash

    Returns:
        Dict with user_id, phone, first_name, last_name if successful, None otherwise
    """
    import asyncio

    from telethon import TelegramClient

    try:
        # Create a temporary client to get account info
        client = TelegramClient(str(session_path), api_id, api_hash)

        # Connect with a timeout to avoid hanging
        await asyncio.wait_for(client.connect(), timeout=10.0)

        if not await client.is_user_authorized():
            await client.disconnect()
            return None

        # Get user info
        me = await asyncio.wait_for(client.get_me(), timeout=10.0)
        await client.disconnect()

        return {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }
    except Exception as e:
        logger.warning(f"Failed to extract account info from session: {e}")
        return None


def save_account_info(session_dir: Path, account_info: dict[str, int | str]) -> None:
    """Save account info metadata to session directory.

    Args:
        session_dir: Session directory path
        account_info: Account info dict with user_id, phone, etc.
    """
    metadata_file = session_dir / ".account_info.json"
    metadata_content = json.dumps(account_info, indent=2).encode("utf-8")
    atomic_write(metadata_file, metadata_content)
    secure_file_permissions(metadata_file)


def load_account_info(session_dir: Path) -> dict[str, int | str] | None:
    """Load account info metadata from session directory.

    Args:
        session_dir: Session directory path

    Returns:
        Account info dict or None if not found
    """
    metadata_file = session_dir / ".account_info.json"
    if not metadata_file.exists():
        return None

    try:
        with metadata_file.open("r") as f:
            data = json.load(f)
            # Type narrowing: ensure it's a dict before returning
            if isinstance(data, dict):
                return data
            return None
    except Exception as e:
        logger.warning(f"Failed to load account info from {metadata_file}: {e}")
        return None


def find_duplicate_accounts(target_user_id: int, exclude_session: str | None = None) -> list[str]:
    """Find all sessions that belong to the same Telegram account.

    Args:
        target_user_id: The user_id to search for
        exclude_session: Optional session name to exclude from search

    Returns:
        List of session names that have the same user_id
    """
    duplicates = []
    data_dir = ensure_data_dir()

    for session_dir in data_dir.iterdir():
        if not session_dir.is_dir():
            continue

        # Skip the excluded session
        if exclude_session and session_dir.name == exclude_session:
            continue

        # Load account info
        account_info = load_account_info(session_dir)
        if account_info and account_info.get("user_id") == target_user_id:
            duplicates.append(session_dir.name)

    return duplicates


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
        request=request,
        name="partials/sessions_list.html",
        context={"sessions": sessions},
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
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Check if session already exists
        session_dir = ensure_data_dir() / safe_name
        if session_dir.exists():
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": f"Session '{safe_name}' already exists",
                },
            )

        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": f"Invalid session: {e}"},
            )

        # Read and validate config file with size limit enforcement
        try:
            config_content = await read_upload_with_size_limit(
                config_file, MAX_CONFIG_SIZE, "config"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            config_data = validate_config_file_format(config_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": f"Invalid config: {e}"},
            )

        # Extract account info from session to check for duplicates
        import tempfile

        account_info = None
        duplicate_sessions = []

        # Create a temporary session file to test connection
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        try:
            api_id = int(config_data["api_id"])
            api_hash = str(config_data["api_hash"])

            # Try to get account info from the session
            account_info = await get_account_info_from_session(tmp_session_path, api_id, api_hash)

            if account_info:
                # Check for duplicate accounts
                user_id = account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(user_id, exclude_session=safe_name)
        finally:
            # Clean up temporary session file
            import contextlib

            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Create session directory and save files
        session_dir.mkdir(parents=True, exist_ok=True)
        session_path = session_dir / "session.session"

        try:
            # Check disk space before writing session file
            from chatfilter.utils.disk import DiskSpaceError, ensure_space_available

            marker_text = (
                "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
                "Do not create a plaintext config.json file.\n"
            )

            # Calculate total space needed (session file + marker file)
            total_bytes_needed = len(session_content) + len(marker_text.encode("utf-8"))

            try:
                ensure_space_available(session_path, total_bytes_needed)
            except DiskSpaceError as e:
                # Clean up directory if it was just created
                if session_dir.exists():
                    shutil.rmtree(session_dir, ignore_errors=True)
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": str(e)},
                )

            # Atomic write to prevent corruption on crash
            atomic_write(session_path, session_content)
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
            atomic_write(marker_file, marker_text)

            # Validate that TelegramClientLoader can use secure storage
            loader = TelegramClientLoader(session_path, use_secure_storage=True)
            loader.validate()

            # Save account info if we successfully extracted it
            if account_info:
                save_account_info(session_dir, account_info)
                logger.info(
                    f"Saved account info for session '{safe_name}': "
                    f"user_id={account_info['user_id']}, phone={account_info.get('phone', 'N/A')}"
                )

        except TelegramConfigError as e:
            # Clean up on failure
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": f"Config validation failed: {e}"},
            )
        except Exception:
            # Clean up on failure
            shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": "Failed to save session files. Please try again.",
                },
            )

        logger.info(f"Session '{safe_name}' uploaded successfully")

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": f"Session '{safe_name}' uploaded successfully",
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
        )

    except Exception:
        logger.exception("Unexpected error during session upload")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
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
