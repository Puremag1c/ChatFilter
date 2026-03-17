"""Filesystem utilities for ChatFilter configuration.

Utilities for checking file paths, permissions, and managing data directories.
"""

from __future__ import annotations

from pathlib import Path

import platformdirs


def _is_path_in_readonly_location(path: Path) -> tuple[bool, str | None]:
    """Check if path is in a common read-only location.

    Args:
        path: Path to check

    Returns:
        Tuple of (is_readonly, reason_message)
    """
    import os
    import platform

    path_str = str(path.resolve())
    system = platform.system()

    # Common read-only system directories by platform
    readonly_prefixes = []
    if system == "Linux":
        readonly_prefixes = [
            "/usr/",
            "/bin/",
            "/sbin/",
            "/lib/",
            "/lib64/",
            "/boot/",
            "/sys/",
            "/proc/",
        ]
    elif system == "Darwin":  # macOS
        readonly_prefixes = ["/System/", "/usr/", "/bin/", "/sbin/"]
    elif system == "Windows":
        readonly_prefixes = ["C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\"]

    for prefix in readonly_prefixes:
        if path_str.startswith(prefix):
            return True, f"Path is in system directory: {prefix}"

    # Try to detect read-only filesystem using statvfs (Unix-like systems)
    if hasattr(os, "statvfs"):
        try:
            if path.exists():
                import os

                st = os.statvfs(path)
                # ST_RDONLY flag indicates read-only filesystem
                if st.f_flag & 0x0001:  # ST_RDONLY = 1
                    return True, "Filesystem is mounted read-only"
        except (OSError, AttributeError, PermissionError):
            # If we can't check the path, it might be a permission issue
            # but not necessarily a read-only location
            pass

    return False, None


def _format_permission_error_message(path: Path, operation: str, error: Exception) -> str:
    """Format a helpful permission error message with fix suggestions.

    Args:
        path: Path that caused the error
        operation: Operation that failed (e.g., "create", "write to")
        error: The original exception

    Returns:
        Formatted error message with fix suggestions
    """
    is_readonly, readonly_reason = _is_path_in_readonly_location(path)

    msg = f"Cannot {operation} data directory: {path}"

    if is_readonly:
        msg += f"\n  ⚠ {readonly_reason}"
        msg += "\n  → Fix: Use a writable location with --data-dir flag:"
        msg += "\n         chatfilter --data-dir ~/ChatFilter"
    else:
        msg += f"\n  → Error: {error}"
        msg += "\n  → Fix: Grant write permissions or use a different location:"
        msg += "\n         chatfilter --data-dir ~/ChatFilter"

    msg += "\n  → Tip: Use --validate to test configuration without starting the server"

    return msg


def _get_default_data_dir() -> Path:
    """Get platform-appropriate default data directory using platformdirs.

    Uses OS-specific conventions:
    - macOS: ~/Library/Application Support/ChatFilter
    - Windows: %APPDATA%/ChatFilter
    - Linux: ~/.local/share/chatfilter

    Returns:
        Path to platform-specific user data directory
    """
    return Path(platformdirs.user_data_dir("ChatFilter", "ChatFilter"))


def get_user_log_dir() -> Path:
    """Get platform-appropriate user logs directory.

    Uses OS-specific conventions:
    - macOS: ~/Library/Logs/ChatFilter
    - Windows: %LOCALAPPDATA%/ChatFilter/Logs
    - Linux: ~/.local/state/chatfilter/log

    Returns:
        Path to platform-specific logs directory
    """
    return Path(platformdirs.user_log_dir("ChatFilter", "ChatFilter"))


def ensure_config_dir() -> Path:
    """Ensure config directory exists.

    Note: This function imports get_settings() internally to avoid circular imports.
    """
    from chatfilter.config import get_settings

    config_dir = get_settings().config_dir
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir
