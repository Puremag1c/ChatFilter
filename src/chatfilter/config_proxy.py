"""Proxy configuration settings for ChatFilter."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ProxyType(StrEnum):
    """Supported proxy types."""

    SOCKS5 = "socks5"
    HTTP = "http"


class ProxyStatus(StrEnum):
    """Proxy health status."""

    WORKING = "working"  # Last ping successful
    NO_PING = "no_ping"  # Last ping failed, temporarily disabled
    UNTESTED = "untested"  # Never tested (new proxy)


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
