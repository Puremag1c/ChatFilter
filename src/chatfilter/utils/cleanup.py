"""Cleanup utilities for orphaned resources after application crashes.

This module handles cleanup of resources that remain after SIGKILL or crashes:
- Temporary files (.*.tmp patterns)
- SQLite journal/WAL/SHM files from unclean shutdowns
- Stale session state
- Old session files

SIGKILL Handling:
    While SIGTERM is handled gracefully via the application's lifespan
    shutdown handlers, SIGKILL immediately terminates the process without
    cleanup. This module provides startup-time recovery for resources
    orphaned by SIGKILL or crashes.

    Resources cleaned:
    - Temp files created during atomic writes
    - SQLite database journal files
    - Session files older than configured threshold

Usage:
    Called automatically during application startup in the lifespan handler.
    Can also be called manually for testing or maintenance:

    ```python
    from chatfilter.utils.cleanup import cleanup_orphaned_resources
    from chatfilter.config import get_settings

    settings = get_settings()
    stats = cleanup_orphaned_resources(
        data_dir=settings.data_dir,
        sessions_dir=settings.sessions_dir,
        session_cleanup_days=settings.session_cleanup_days,
    )
    print(f"Cleaned {stats.temp_files} temp files, {stats.db_journals} journal files")
    ```
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CleanupStats:
    """Statistics from cleanup operation."""

    temp_files: int = 0
    db_journals: int = 0
    old_sessions: int = 0
    errors: int = 0


def cleanup_orphaned_temp_files(data_dir: Path) -> int:
    """Clean up orphaned temporary files from previous application crashes.

    Searches for files matching the pattern `.*.tmp` in the data directory
    and removes them. These are temporary files created during atomic writes
    that were not cleaned up due to SIGKILL or process crashes.

    Args:
        data_dir: Directory to search for orphaned temp files

    Returns:
        Number of temp files removed

    Example:
        >>> cleanup_orphaned_temp_files(Path("/data"))
        3  # Removed 3 orphaned temp files
    """
    if not data_dir.exists() or not data_dir.is_dir():
        return 0

    cleaned = 0

    try:
        # Find all .*.tmp files (hidden temp files)
        for temp_file in data_dir.rglob(".*.tmp"):
            if not temp_file.is_file():
                continue

            try:
                temp_file.unlink()
                logger.debug(f"Removed orphaned temp file: {temp_file.name}")
                cleaned += 1
            except OSError as e:
                logger.warning(f"Failed to remove temp file {temp_file}: {e}")

    except OSError as e:
        logger.warning(f"Error scanning directory {data_dir} for temp files: {e}")

    return cleaned


def cleanup_orphaned_db_journals(db_path: Path) -> int:
    """Clean up orphaned SQLite journal files from unclean shutdowns.

    Removes SQLite journal files that may remain after SIGKILL:
    - .db-journal (rollback journal)
    - .db-wal (write-ahead log)
    - .db-shm (shared memory)

    These files are automatically handled by SQLite on database open, but
    explicit cleanup prevents accumulation and provides clear logging.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        Number of journal files removed

    Note:
        This should only be called when the database is NOT open.
        During normal operation, SQLite manages these files.

    Example:
        >>> cleanup_orphaned_db_journals(Path("/data/tasks.db"))
        2  # Removed tasks.db-wal and tasks.db-shm
    """
    if not db_path.parent.exists():
        return 0

    cleaned = 0
    journal_extensions = ["-journal", "-wal", "-shm"]

    for ext in journal_extensions:
        journal_file = Path(str(db_path) + ext)

        if not journal_file.exists():
            continue

        try:
            journal_file.unlink()
            logger.debug(f"Removed orphaned journal file: {journal_file.name}")
            cleaned += 1
        except OSError as e:
            logger.warning(f"Failed to remove journal file {journal_file}: {e}")

    return cleaned


def cleanup_old_session_files(sessions_dir: Path, cleanup_days: float | None) -> int:
    """Clean up old session files that haven't been accessed recently.

    Removes session directories where the session.session file hasn't been
    modified within the cleanup threshold. Uses secure deletion for sensitive files.

    Args:
        sessions_dir: Directory containing session subdirectories
        cleanup_days: Age threshold in days (None to skip cleanup)

    Returns:
        Number of sessions cleaned up

    Example:
        >>> cleanup_old_session_files(Path("/data/sessions"), cleanup_days=30.0)
        2  # Removed 2 sessions older than 30 days
    """
    if cleanup_days is None:
        return 0

    # Import here to avoid circular dependencies
    from chatfilter.storage.file import cleanup_old_session_files as _cleanup_sessions

    return _cleanup_sessions(sessions_dir, cleanup_days)


def cleanup_orphaned_resources(
    data_dir: Path,
    sessions_dir: Path,
    session_cleanup_days: float | None = None,
    db_name: str = "tasks.db",
) -> CleanupStats:
    """Comprehensive cleanup of all orphaned resources from SIGKILL/crashes.

    This is the main entry point for startup cleanup. It handles all resources
    that may be left in an inconsistent state after SIGKILL or process crashes.

    Resources cleaned:
    1. Temporary files (.*.tmp) from atomic write operations
    1b. Backup session files (.backup) from failed deletion attempts
    2. SQLite journal files from database transactions
    3. Old session files based on age threshold

    Args:
        data_dir: Application data directory
        sessions_dir: Telegram sessions directory
        session_cleanup_days: Age threshold for session cleanup (None to skip)
        db_name: Name of the SQLite database file

    Returns:
        CleanupStats with counts of cleaned resources

    Example:
        >>> stats = cleanup_orphaned_resources(
        ...     data_dir=Path("/data"),
        ...     sessions_dir=Path("/data/sessions"),
        ...     session_cleanup_days=30.0,
        ... )
        >>> print(f"Cleaned {stats.temp_files} temp files")

    Note:
        This function is designed to be safe to call at any time, with
        graceful error handling. Failed cleanup operations are logged
        but don't raise exceptions.
    """
    stats = CleanupStats()

    logger.info("Starting orphaned resource cleanup (SIGKILL recovery)")

    # 1. Clean up orphaned temp files
    try:
        stats.temp_files = cleanup_orphaned_temp_files(data_dir)
        if stats.temp_files > 0:
            logger.info(f"✓ Cleaned {stats.temp_files} orphaned temp file(s)")
    except Exception as e:
        logger.error(f"Error during temp file cleanup: {e}")
        stats.errors += 1

    # 1b. Clean up backup session files (failed deletes)
    try:
        from chatfilter.storage.file import cleanup_backup_session_files
        backup_count = cleanup_backup_session_files(sessions_dir)
        if backup_count > 0:
            logger.info(f"✓ Cleaned {backup_count} backup session file(s)")
    except Exception as e:
        logger.error(f"Error during backup session cleanup: {e}")
        stats.errors += 1

    # 2. Clean up orphaned SQLite journal files
    try:
        db_path = data_dir / db_name
        stats.db_journals = cleanup_orphaned_db_journals(db_path)
        if stats.db_journals > 0:
            logger.info(f"✓ Cleaned {stats.db_journals} orphaned database journal file(s)")
    except Exception as e:
        logger.error(f"Error during database journal cleanup: {e}")
        stats.errors += 1

    # 3. Clean up old session files (if enabled)
    if session_cleanup_days is not None:
        try:
            stats.old_sessions = cleanup_old_session_files(sessions_dir, session_cleanup_days)
            if stats.old_sessions > 0:
                logger.info(
                    f"✓ Cleaned {stats.old_sessions} old session(s) "
                    f"(threshold: {session_cleanup_days} days)"
                )
        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")
            stats.errors += 1

    # Summary
    total_cleaned = stats.temp_files + stats.db_journals + stats.old_sessions
    if total_cleaned > 0:
        logger.info(
            f"Cleanup complete: {total_cleaned} total items cleaned "
            f"(temp={stats.temp_files}, journals={stats.db_journals}, "
            f"sessions={stats.old_sessions})"
        )
    else:
        logger.debug("Cleanup complete: no orphaned resources found")

    if stats.errors > 0:
        logger.warning(f"Cleanup completed with {stats.errors} error(s)")

    return stats
