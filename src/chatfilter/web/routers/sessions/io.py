"""Session I/O operations: reading, writing, and account info management."""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import UploadFile

from chatfilter.storage.helpers import atomic_write

# Import get_settings from helpers to support test mocking.
# Tests patch chatfilter.web.routers.sessions.helpers.get_settings,
# so we import via that path to ensure patches work.
from . import helpers

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# Maximum file sizes (security limit)
MAX_SESSION_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_JSON_SIZE = 10 * 1024  # 10 KB (account info JSON)
MAX_CONFIG_SIZE = 1024  # 1 KB
# Chunk size for reading uploaded files (to prevent memory exhaustion)
READ_CHUNK_SIZE = 8192  # 8 KB chunks


def ensure_data_dir(user_id: str | int) -> Path:
    """Ensure user-scoped sessions directory exists with proper permissions."""
    uid = str(user_id)
    if not uid or "/" in uid or "\\" in uid or ".." in uid:
        raise ValueError(f"Invalid user_id: {uid!r}")
    sessions_dir = helpers.get_settings().sessions_dir
    target_dir = sessions_dir / uid
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return target_dir


def secure_file_permissions(file_path: Path) -> None:
    """Set file permissions to 600 (owner read/write only)."""
    import os
    import stat

    # chmod 600: owner read/write, no access for group/others
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


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


async def get_account_info_from_session(
    session_path: Path,
) -> dict[str, int | str] | None:
    """Extract account info from a session by connecting to Telegram.

    Args:
        session_path: Path to the session file

    Returns:
        Dict with user_id, phone, first_name, last_name if successful, None otherwise
    """
    from telethon import TelegramClient

    try:
        config = helpers.get_settings().telegram_config
        # Create a temporary client to get account info
        client = TelegramClient(str(session_path), config.api_id, config.api_hash)

        # Connect with a timeout to avoid hanging
        await asyncio.wait_for(client.connect(), timeout=30.0)

        if not await client.is_user_authorized():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
            return None

        # Get user info
        me = await asyncio.wait_for(client.get_me(), timeout=30.0)
        await asyncio.wait_for(client.disconnect(), timeout=30.0)

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
    """Save account info metadata to session directory."""
    metadata_file = session_dir / ".account_info.json"
    metadata_content = json.dumps(account_info, indent=2).encode("utf-8")
    atomic_write(metadata_file, metadata_content)
    secure_file_permissions(metadata_file)


def load_account_info(session_dir: Path) -> dict[str, int | str] | None:
    """Load account info metadata from session directory, or None if not found."""
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


def migrate_legacy_session_dirs() -> dict[str, int]:
    """One-shot migration: move legacy per-user-UUID session dirs to the
    Phase-6 canonical layout (``sessions/admin/<name>`` or
    ``sessions/user_<id>/<name>``).

    Ran from the app lifespan at startup. Idempotent — if a session is
    already at its canonical path it is skipped. If the canonical path
    exists AND a legacy copy also exists, we leave the legacy copy
    alone and log a warning (don't know which is authoritative).

    Returns a stats dict ``{"moved": N, "skipped": N, "conflicts": N}``.
    """
    import shutil as _shutil

    sessions_root = helpers.get_settings().sessions_dir
    stats = {"moved": 0, "skipped": 0, "conflicts": 0}
    if not sessions_root.exists():
        return stats

    canonical_names = {"admin"}
    for sub in sessions_root.iterdir():
        if not sub.is_dir():
            continue
        if sub.name in canonical_names or sub.name.startswith("user_"):
            continue  # already canonical

        # This is a legacy per-UUID dir — look inside for session subdirs.
        for session_dir in list(sub.iterdir()):
            if not session_dir.is_dir():
                continue
            info = load_account_info(session_dir)
            owner = (info or {}).get("owner") if info else None
            # Phase-4 default: missing metadata means this belonged to the
            # admin pool (that's what the Phase-4 migration decided).
            if owner is None or owner == "admin":
                target_scope = "admin"
            elif isinstance(owner, str) and owner.startswith("user:"):
                target_scope = "user_" + owner.split(":", 1)[1]
            else:
                stats["skipped"] += 1
                continue

            target_parent = sessions_root / target_scope
            target_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target = target_parent / session_dir.name

            if target.exists():
                logger.warning(
                    "Legacy session %s conflicts with canonical %s — leaving legacy copy in place",
                    session_dir,
                    target,
                )
                stats["conflicts"] += 1
                continue

            try:
                _shutil.move(str(session_dir), str(target))
                stats["moved"] += 1
                logger.info("Migrated legacy session %s → %s", session_dir, target)
            except Exception:
                logger.exception("Failed to migrate session %s", session_dir)
                stats["skipped"] += 1

        # Remove the now-empty legacy dir (best effort).
        try:
            if not any(sub.iterdir()):
                sub.rmdir()
        except Exception:
            pass

    return stats


def get_session_owner(session_id: str) -> str:
    """Return the pool_key that owns this session.

    Reads the ``owner`` field out of the session's .account_info.json.
    Defaults to ``"admin"`` when missing — that's the behaviour we want
    for every pre-Phase-4 account, all of which belong to the admin
    pool by definition.
    """
    from chatfilter.config import get_settings

    sessions_dir = get_settings().sessions_dir
    info = load_account_info(sessions_dir / session_id)
    if info is None:
        return "admin"
    owner = info.get("owner", "admin")
    return str(owner) if owner else "admin"


def set_session_owner(session_id: str, owner: str) -> None:
    """Persist the pool_key owning this session into .account_info.json."""
    from chatfilter.config import get_settings

    sessions_dir = get_settings().sessions_dir
    session_dir = sessions_dir / session_id
    info = load_account_info(session_dir) or {}
    info["owner"] = owner
    save_account_info(session_dir, info)


def _save_session_to_disk(
    session_dir: Path,
    session_content: bytes,
    proxy_id: str | None,
    account_info: dict[str, int | str] | None,
    source: str = "file",
    web_user_id: str | int | None = None,
) -> None:
    """Save session files to disk with secure credentials.

    Uses atomic transaction pattern:
    1. Write all files to temp directory
    2. On success - rename temp dir to final name (POSIX atomic)
    3. On failure - delete temp dir (no orphaned files)

    Creates:
    - session.session file (atomic write, secure permissions)
    - config.json with proxy_id, source
    - .secure_storage marker
    - .account_info.json if account_info provided

    Also stores proxy_id in secure storage.

    Args:
        session_dir: Session directory path (must NOT exist)
        session_content: Session file content bytes
        proxy_id: Proxy ID (can be None)
        account_info: Account info dict or None
        source: Source of credentials ('file' or 'phone')

    Raises:
        DiskSpaceError: If not enough disk space
        Exception: On other failures (temp dir is cleaned up)
    """
    from chatfilter.security import SecureCredentialManager
    from chatfilter.utils.disk import ensure_space_available

    safe_name = session_dir.name

    marker_text = (
        "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
        "Do not create a plaintext config.json file.\n"
    )

    # Calculate total space needed (session file + marker file)
    total_bytes_needed = len(session_content) + len(marker_text.encode("utf-8"))

    # Check disk space before writing (use parent dir since session_dir doesn't exist yet)
    ensure_space_available(session_dir.parent / ".space_check", total_bytes_needed)

    # Create temporary directory for atomic transaction
    # Use parent directory to ensure same filesystem (for atomic rename)
    temp_dir = None
    try:
        temp_dir = Path(tempfile.mkdtemp(prefix=f".tmp_{safe_name}_", dir=session_dir.parent))

        # Write all files to temp directory
        session_path = temp_dir / "session.session"
        atomic_write(session_path, session_content)
        secure_file_permissions(session_path)

        # Store proxy_id securely (api_id/api_hash come from global ENV)
        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_session_config(safe_name, proxy_id)
        logger.info(f"Stored session config securely for session: {safe_name}")

        # Create per-session config.json
        session_config: dict[str, str | None] = {
            "proxy_id": proxy_id,
            "source": source,
            "web_user_id": str(web_user_id) if web_user_id is not None else None,
        }
        session_config_path = temp_dir / "config.json"
        session_config_content = json.dumps(session_config, indent=2).encode("utf-8")
        atomic_write(session_config_path, session_config_content)
        secure_file_permissions(session_config_path)
        logger.info(f"Created per-session config for session: {safe_name}")

        # Create migration marker to indicate we're using secure storage
        marker_file = temp_dir / ".secure_storage"
        atomic_write(marker_file, marker_text)

        # Save account info if we successfully extracted it
        if account_info:
            save_account_info(temp_dir, account_info)
            # user_id might not be available if get_account_info_from_session failed
            if "user_id" in account_info:
                logger.info(
                    f"Saved account info for session '{safe_name}': "
                    f"user_id={account_info['user_id']}, phone=[REDACTED]"
                )
            else:
                logger.info(
                    f"Saved account info for session '{safe_name}' (user_id not available): "
                    f"phone=[REDACTED]"
                )

        # All writes succeeded → atomic rename (POSIX atomic operation)
        temp_dir.rename(session_dir)
        temp_dir = None  # Prevent cleanup
        logger.info(f"Session '{safe_name}' saved successfully (atomic transaction)")

    except Exception:
        # Cleanup temp directory on any failure
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temp directory after failed write: {temp_dir}")
        raise


def find_duplicate_accounts(
    target_user_id: int,
    exclude_session: str | None = None,
    web_user_id: str | int | None = None,
) -> list[str]:
    """Find all sessions that belong to the same Telegram account (by user_id)."""
    duplicates = []
    data_dir = ensure_data_dir(web_user_id if web_user_id is not None else "default")

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
