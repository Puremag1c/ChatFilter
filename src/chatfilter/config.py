"""Configuration management for ChatFilter."""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Config directory
CONFIG_DIR = Path.cwd() / "data" / "config"


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

    def to_telethon_proxy(self) -> tuple | None:
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
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


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
