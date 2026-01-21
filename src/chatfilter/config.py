"""Configuration management for ChatFilter.

Supports layered configuration with priority: CLI args > ENV vars > .env file > defaults
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any

import platformdirs
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from chatfilter.storage.helpers import atomic_write

logger = logging.getLogger(__name__)


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


def get_user_config_dir() -> Path:
    """Get platform-appropriate user configuration directory.

    Uses OS-specific conventions:
    - macOS: ~/Library/Application Support/ChatFilter
    - Windows: %APPDATA%/ChatFilter
    - Linux: ~/.config/chatfilter

    Returns:
        Path to platform-specific config directory
    """
    return Path(platformdirs.user_config_dir("ChatFilter", "ChatFilter"))


def get_user_cache_dir() -> Path:
    """Get platform-appropriate user cache directory.

    Uses OS-specific conventions:
    - macOS: ~/Library/Caches/ChatFilter
    - Windows: %LOCALAPPDATA%/ChatFilter/Cache
    - Linux: ~/.cache/chatfilter

    Returns:
        Path to platform-specific cache directory
    """
    return Path(platformdirs.user_cache_dir("ChatFilter", "ChatFilter"))


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


class Settings(BaseSettings):
    """Application settings with layered configuration support.

    Configuration is loaded in the following priority (highest to lowest):
    1. CLI arguments (passed directly to Settings())
    2. Environment variables (prefixed with CHATFILTER_)
    3. .env file (if present in current directory)
    4. Default values

    Example:
        ```python
        # Load settings from environment and .env
        settings = get_settings()

        # Override with CLI arguments
        settings = Settings(host="0.0.0.0", port=9000)

        # Access settings
        print(settings.data_dir)
        print(settings.server_host)
        ```

    Environment variables:
        CHATFILTER_HOST: Server host (default: 127.0.0.1)
        CHATFILTER_PORT: Server port (default: 8000)
        CHATFILTER_DEBUG: Enable debug mode (default: false)
        CHATFILTER_DATA_DIR: Data directory path
        CHATFILTER_LOG_LEVEL: Logging level (default: INFO)
    """

    model_config = SettingsConfigDict(
        env_prefix="CHATFILTER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Server settings
    host: str = Field(
        default="127.0.0.1",
        description="Server host to bind to",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Server port to bind to",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode (verbose logging, auto-reload)",
    )

    # Paths
    data_dir: Path = Field(
        default_factory=_get_default_data_dir,
        description="Base directory for application data",
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    log_to_file: bool = Field(
        default=True,
        description="Enable logging to file (in addition to console)",
    )
    log_file_max_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        ge=1024 * 1024,  # Min 1 MB
        le=100 * 1024 * 1024,  # Max 100 MB
        description="Maximum size of each log file before rotation",
    )
    log_file_backup_count: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of backup log files to keep",
    )
    log_format: str = Field(
        default="text",
        description="Log format: 'text' for human-readable, 'json' for structured logging",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose logging (detailed operation logs)",
    )
    log_module_levels: dict[str, str] = Field(
        default_factory=dict,
        description="Per-module log levels (e.g., {'chatfilter.telegram': 'DEBUG'})",
    )

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, v: str) -> str:
        """Validate log format is supported."""
        valid_formats = {"text", "json"}
        v_lower = v.lower()
        if v_lower not in valid_formats:
            raise ValueError(f"Invalid log format: {v}. Must be one of: {', '.join(valid_formats)}")
        return v_lower

    # CORS origins for separated frontend/backend architecture
    # Include common development ports for frontend frameworks
    # In production, override via CHATFILTER_CORS_ORIGINS environment variable
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            # Backend (served UI)
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            # Common frontend development ports
            "http://localhost:3000",  # React, Next.js, Node servers
            "http://127.0.0.1:3000",
            "http://localhost:5173",  # Vite
            "http://127.0.0.1:5173",
            "http://localhost:4200",  # Angular
            "http://127.0.0.1:4200",
        ],
        description="Allowed CORS origins (comma-separated in env var)",
    )

    # Update checking
    update_check_enabled: bool = Field(
        default=True,
        description="Enable automatic update checking",
    )
    update_check_interval: float = Field(
        default=24.0,
        ge=1.0,
        le=168.0,  # Max 1 week
        description="Hours between update checks",
    )
    update_check_on_startup: bool = Field(
        default=True,
        description="Check for updates on application startup",
    )
    update_check_include_prereleases: bool = Field(
        default=False,
        description="Include pre-release versions in update checks",
    )
    update_check_timeout: float = Field(
        default=10.0,
        ge=5.0,
        le=60.0,
        description="Timeout for update check HTTP requests (seconds)",
    )

    # Telegram settings
    max_messages_limit: int = Field(
        default=10_000,
        ge=100,
        le=100_000,
        description="Maximum messages to fetch per chat",
    )

    # Session timeouts (seconds)
    connect_timeout: float = Field(
        default=30.0,
        ge=5.0,
        le=300.0,
        description="Timeout for Telegram connection",
    )
    operation_timeout: float = Field(
        default=60.0,
        ge=10.0,
        le=600.0,
        description="Timeout for Telegram operations",
    )

    # Connection health monitoring
    heartbeat_interval: float = Field(
        default=60.0,
        ge=10.0,
        le=600.0,
        description="Interval between heartbeat checks (seconds)",
    )
    heartbeat_timeout: float = Field(
        default=10.0,
        ge=5.0,
        le=60.0,
        description="Timeout for heartbeat ping operations",
    )
    heartbeat_max_failures: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Max consecutive failures before reconnection",
    )

    # Task recovery settings
    stale_task_threshold_hours: float = Field(
        default=24.0,
        ge=1.0,
        le=168.0,  # Max 1 week
        description="Hours after which in-progress tasks are considered stale on recovery",
    )

    # Session file cleanup settings
    session_cleanup_days: float | None = Field(
        default=None,
        ge=1.0,
        le=365.0,  # Max 1 year
        description="Days after which unused session files are auto-deleted (None=disabled)",
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level is a known level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of: {', '.join(valid_levels)}")
        return v_upper

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        """Parse CORS origins from comma-separated string or list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return list(v)
        return []

    @model_validator(mode="after")
    def ensure_directories(self) -> Settings:
        """Ensure required directories exist after validation."""
        # Don't create directories during validation - they'll be created on demand
        return self

    @property
    def config_dir(self) -> Path:
        """Directory for configuration files."""
        return self.data_dir / "config"

    @property
    def sessions_dir(self) -> Path:
        """Directory for Telegram session files."""
        return self.data_dir / "sessions"

    @property
    def exports_dir(self) -> Path:
        """Directory for exported files."""
        return self.data_dir / "exports"

    @property
    def log_dir(self) -> Path:
        """Directory for log files (uses platform-specific directory)."""
        return get_user_log_dir()

    @property
    def log_file_path(self) -> Path:
        """Path to the main log file."""
        return self.log_dir / "chatfilter.log"

    @property
    def first_run_marker_path(self) -> Path:
        """Path to first-run marker file."""
        return self.data_dir / ".initialized"

    def is_first_run(self) -> bool:
        """Check if this is the first run (marker file does not exist).

        Returns:
            True if first run, False otherwise
        """
        return not self.first_run_marker_path.exists()

    def mark_first_run_complete(self) -> None:
        """Mark first run as complete by creating marker file with timestamp."""
        from datetime import UTC, datetime

        # Atomic write to prevent corruption on crash
        atomic_write(
            self.first_run_marker_path,
            f"ChatFilter initialized at {datetime.now(UTC).isoformat()}\n",
        )

    def ensure_data_dirs(self) -> list[str]:
        """Create data directories if they don't exist.

        Returns:
            List of error messages (empty if all successful)
        """
        errors = []

        # Try to create each directory and collect errors
        dirs_to_create = [
            ("data", self.data_dir),
            ("config", self.config_dir),
            ("sessions", self.sessions_dir),
            ("exports", self.exports_dir),
        ]

        if self.log_to_file:
            dirs_to_create.append(("log", self.log_dir))

        for dir_name, dir_path in dirs_to_create:
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                is_readonly, readonly_reason = _is_path_in_readonly_location(dir_path)
                if is_readonly:
                    errors.append(
                        f"Cannot create {dir_name} directory: {dir_path}\n"
                        f"  ⚠ {readonly_reason}\n"
                        f"  → Use --data-dir flag to specify a writable location"
                    )
                else:
                    errors.append(
                        f"Permission denied creating {dir_name} directory: {dir_path}\n"
                        f"  → Use --data-dir flag or grant write permissions"
                    )
            except OSError as e:
                errors.append(f"Failed to create {dir_name} directory: {dir_path} ({e})")

        return errors

    def check(self) -> list[str]:
        """Validate configuration and return any warnings.

        Returns:
            List of warning messages (empty if all is well)
        """
        warnings = []

        # Check if data directory exists and is writable
        if self.data_dir.exists():
            if not self.data_dir.is_dir():
                warnings.append(
                    f"Data path exists but is not a directory: {self.data_dir}\n"
                    f"  → Use --data-dir to specify a different location"
                )
        else:
            # Check if we can create it
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                self.data_dir.rmdir()  # Remove test directory
            except PermissionError:
                is_readonly, readonly_reason = _is_path_in_readonly_location(self.data_dir)
                if is_readonly:
                    warnings.append(
                        f"Cannot create data directory: {self.data_dir}\n"
                        f"  ⚠ {readonly_reason}\n"
                        f"  → Use --data-dir flag: chatfilter --data-dir ~/ChatFilter"
                    )
                else:
                    warnings.append(
                        f"Cannot create data directory (permission denied): {self.data_dir}\n"
                        f"  → Use --data-dir flag or grant write permissions"
                    )
            except OSError as e:
                warnings.append(
                    f"Cannot create data directory: {self.data_dir} ({e})\n"
                    f"  → Use --data-dir flag to specify a different location"
                )

        # Warn about debug mode in production
        if self.debug and self.host == "0.0.0.0":  # nosec B104
            warnings.append(
                "Debug mode enabled with public host binding - not recommended for production"
            )

        return warnings

    def validate(self) -> list[str]:  # type: ignore[override]
        """Strict validation for startup - fails fast with all errors at once.

        Validates:
        - Port number is valid
        - Data directory is writable
        - Required subdirectories can be created
        - Port is not already in use (basic check)

        Returns:
            List of error messages (empty if validation passes)

        Example:
            ```python
            settings = Settings()
            errors = settings.validate()
            if errors:
                for error in errors:
                    print(f"ERROR: {error}")
                sys.exit(1)
            ```
        """
        errors = []

        # 1. Port validation (already done by pydantic, but double-check)
        if not (1 <= self.port <= 65535):
            errors.append(f"Invalid port number: {self.port} (must be 1-65535)")

        # 2. Data directory writability check
        try:
            dir_exists = self.data_dir.exists()
        except PermissionError as e:
            errors.append(_format_permission_error_message(self.data_dir, "access", e))
            dir_exists = False

        if dir_exists:
            if not self.data_dir.is_dir():
                errors.append(
                    f"Data path exists but is not a directory: {self.data_dir}\n"
                    f"  → Fix: Remove the file or use --data-dir to choose a different location:\n"
                    f"         chatfilter --data-dir ~/ChatFilter"
                )
            else:
                # Check if writable by trying to create a temp file
                import tempfile

                try:
                    with tempfile.NamedTemporaryFile(dir=self.data_dir, delete=True):
                        pass
                except PermissionError as e:
                    errors.append(_format_permission_error_message(self.data_dir, "write to", e))
                except OSError as e:
                    errors.append(
                        f"Cannot write to data directory: {self.data_dir}\n"
                        f"  → Error: {e}\n"
                        f"  → Fix: Check directory permissions and disk space\n"
                        f"  → Tip: Use --data-dir to specify a different location"
                    )
        else:
            # Try to create it
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                # Verify it's writable
                import tempfile

                with tempfile.NamedTemporaryFile(dir=self.data_dir, delete=True):
                    pass
            except PermissionError as e:
                errors.append(_format_permission_error_message(self.data_dir, "create", e))
            except OSError as e:
                errors.append(
                    f"Cannot create data directory: {self.data_dir}\n"
                    f"  → Error: {e}\n"
                    f"  → Fix: Check parent directory exists and has write permissions\n"
                    f"  → Tip: Use --data-dir to specify a different location:\n"
                    f"         chatfilter --data-dir ~/ChatFilter"
                )

        # 3. Port availability check
        from chatfilter.utils.ports import format_port_conflict_message, is_port_available

        if not is_port_available(self.host, self.port):
            errors.append(format_port_conflict_message(self.host, self.port))

        return errors

    def print_config(self) -> None:
        """Print current configuration to stdout."""
        print("ChatFilter Configuration:")
        print(f"  Host: {self.host}")
        print(f"  Port: {self.port}")
        print(f"  Debug: {self.debug}")
        print(f"  Log Level: {self.log_level}")
        print(f"  Log Format: {self.log_format}")
        print(f"  Verbose: {self.verbose}")
        print(f"  Log to File: {self.log_to_file}")
        if self.log_to_file:
            print(f"  Log File: {self.log_file_path}")
            print(f"  Log Max Size: {self.log_file_max_bytes / (1024 * 1024):.1f} MB")
            print(f"  Log Backup Count: {self.log_file_backup_count}")
        if self.log_module_levels:
            print(f"  Module Log Levels: {self.log_module_levels}")
        print(f"  Data Directory: {self.data_dir}")
        print(f"  Config Directory: {self.config_dir}")
        print(f"  Sessions Directory: {self.sessions_dir}")
        print(f"  Exports Directory: {self.exports_dir}")
        print(f"  CORS Origins: {', '.join(self.cors_origins)}")
        print(f"  Max Messages Limit: {self.max_messages_limit}")
        print(f"  Connect Timeout: {self.connect_timeout}s")
        print(f"  Operation Timeout: {self.operation_timeout}s")
        print(f"  Heartbeat Interval: {self.heartbeat_interval}s")
        print(f"  Heartbeat Timeout: {self.heartbeat_timeout}s")
        print(f"  Heartbeat Max Failures: {self.heartbeat_max_failures}")
        print(f"  Stale Task Threshold: {self.stale_task_threshold_hours}h")
        cleanup_str = f"{self.session_cleanup_days}d" if self.session_cleanup_days else "disabled"
        print(f"  Session Cleanup: {cleanup_str}")
        print(f"  Update Check Enabled: {self.update_check_enabled}")
        if self.update_check_enabled:
            print(f"  Update Check Interval: {self.update_check_interval}h")
            print(f"  Update Check on Startup: {self.update_check_on_startup}")
            print(f"  Include Prereleases: {self.update_check_include_prereleases}")


@lru_cache
def get_settings() -> Settings:
    """Get cached application settings.

    Settings are loaded once and cached. To reload settings,
    call get_settings.cache_clear() first.

    Returns:
        Settings instance
    """
    return Settings()


def reset_settings() -> None:
    """Clear settings cache to force reload on next get_settings() call."""
    get_settings.cache_clear()


class ProxyType(str, Enum):
    """Supported proxy types."""

    SOCKS5 = "socks5"
    HTTP = "http"


class ProxyConfig(BaseModel):
    """Proxy configuration settings."""

    enabled: bool = False
    proxy_type: ProxyType = ProxyType.SOCKS5
    host: str = ""
    port: int = Field(default=1080, ge=1, le=65535)
    username: str = ""
    password: str = ""

    def to_telethon_proxy(self) -> tuple[Any, ...] | None:
        """Convert to Telethon proxy format.

        Returns:
            Tuple of (proxy_type, host, port, username, password) or None if disabled
        """
        if not self.enabled or not self.host:
            return None

        import socks

        proxy_type_map = {
            ProxyType.SOCKS5: socks.SOCKS5,
            ProxyType.HTTP: socks.HTTP,
        }

        return (
            proxy_type_map[self.proxy_type],
            self.host,
            self.port,
            True,  # rdns (resolve DNS remotely)
            self.username or None,
            self.password or None,
        )


def ensure_config_dir() -> Path:
    """Ensure config directory exists."""
    config_dir = get_settings().config_dir
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_proxy_config_path() -> Path:
    """Get path to proxy config file."""
    return ensure_config_dir() / "proxy.json"


def load_proxy_config() -> ProxyConfig:
    """Load proxy configuration from file.

    Returns:
        ProxyConfig instance (defaults if file doesn't exist)
    """
    config_path = get_proxy_config_path()

    if not config_path.exists():
        return ProxyConfig()

    try:
        data = json.loads(config_path.read_text())
        return ProxyConfig.model_validate(data)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Failed to load proxy config: {e}, using defaults")
        return ProxyConfig()


def save_proxy_config(config: ProxyConfig) -> None:
    """Save proxy configuration to file.

    Args:
        config: ProxyConfig instance to save
    """
    config_path = get_proxy_config_path()
    # Atomic write to prevent corruption on crash
    atomic_write(config_path, config.model_dump_json(indent=2))
    logger.info("Proxy configuration saved")
