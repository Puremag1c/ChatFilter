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

logger = logging.getLogger(__name__)


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

    # CORS (comma-separated list in env var)
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        description="Allowed CORS origins",
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

    def ensure_data_dirs(self) -> None:
        """Create data directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)

    def check(self) -> list[str]:
        """Validate configuration and return any warnings.

        Returns:
            List of warning messages (empty if all is well)
        """
        warnings = []

        # Check if data directory exists and is writable
        if self.data_dir.exists():
            if not self.data_dir.is_dir():
                warnings.append(f"Data path exists but is not a directory: {self.data_dir}")
        else:
            # Check if we can create it
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                self.data_dir.rmdir()  # Remove test directory
            except PermissionError:
                warnings.append(f"Cannot create data directory (permission denied): {self.data_dir}")
            except OSError as e:
                warnings.append(f"Cannot create data directory: {self.data_dir} ({e})")

        # Warn about debug mode in production
        if self.debug and self.host == "0.0.0.0":
            warnings.append("Debug mode enabled with public host binding - not recommended for production")

        return warnings

    def validate(self) -> list[str]:
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
        except PermissionError:
            errors.append(
                f"Cannot access data directory (permission denied): {self.data_dir}\n"
                f"  → Fix: Grant read permissions to the directory or use a different path"
            )
            dir_exists = False

        if dir_exists:
            if not self.data_dir.is_dir():
                errors.append(
                    f"Data path exists but is not a directory: {self.data_dir}\n"
                    f"  → Fix: Remove the file or choose a different data directory"
                )
            else:
                # Check if writable by trying to create a temp file
                import tempfile
                try:
                    with tempfile.NamedTemporaryFile(dir=self.data_dir, delete=True):
                        pass
                except PermissionError:
                    errors.append(
                        f"Data directory is not writable: {self.data_dir}\n"
                        f"  → Fix: Grant write permissions or choose a different directory"
                    )
                except OSError as e:
                    errors.append(
                        f"Cannot write to data directory: {self.data_dir} ({e})\n"
                        f"  → Fix: Check directory permissions and disk space"
                    )
        else:
            # Try to create it
            try:
                self.data_dir.mkdir(parents=True, exist_ok=True)
                # Verify it's writable
                import tempfile
                with tempfile.NamedTemporaryFile(dir=self.data_dir, delete=True):
                    pass
            except PermissionError:
                errors.append(
                    f"Cannot create data directory (permission denied): {self.data_dir}\n"
                    f"  → Fix: Grant write permissions to parent directory or use a different path"
                )
            except OSError as e:
                errors.append(
                    f"Cannot create data directory: {self.data_dir} ({e})\n"
                    f"  → Fix: Check parent directory exists and has write permissions"
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
        print(f"  Data Directory: {self.data_dir}")
        print(f"  Config Directory: {self.config_dir}")
        print(f"  Sessions Directory: {self.sessions_dir}")
        print(f"  Exports Directory: {self.exports_dir}")
        print(f"  CORS Origins: {', '.join(self.cors_origins)}")
        print(f"  Max Messages Limit: {self.max_messages_limit}")
        print(f"  Connect Timeout: {self.connect_timeout}s")
        print(f"  Operation Timeout: {self.operation_timeout}s")


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
    config_path.write_text(config.model_dump_json(indent=2))
    logger.info("Proxy configuration saved")
