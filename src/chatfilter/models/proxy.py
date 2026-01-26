"""Proxy pool models for managing multiple proxy configurations."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from chatfilter.config import ProxyType


class ProxyEntry(BaseModel):
    """A proxy configuration entry in the proxy pool.

    Each proxy entry has a unique ID and can be used to connect
    Telegram sessions through different proxies.

    Attributes:
        id: Unique identifier (UUID4, auto-generated).
        name: Human-readable name for the proxy.
        type: Proxy protocol type (socks5 or http).
        host: Proxy server hostname or IP.
        port: Proxy server port (1-65535).
        username: Optional authentication username.
        password: Optional authentication password.

    Example:
        >>> proxy = ProxyEntry(
        ...     name="US Server",
        ...     type=ProxyType.SOCKS5,
        ...     host="proxy.example.com",
        ...     port=1080
        ... )
        >>> proxy.id  # Auto-generated UUID
        'a1b2c3d4-...'
        >>> proxy.has_auth
        False
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, max_length=100)
    type: ProxyType
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    username: str = ""
    password: str = ""

    @field_validator("name")
    @classmethod
    def name_must_be_stripped(cls, v: str) -> str:
        """Validate that name is stripped of whitespace."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("name cannot be empty or whitespace only")
        return stripped

    @field_validator("host")
    @classmethod
    def host_must_be_valid(cls, v: str) -> str:
        """Validate that host is a valid hostname or IP."""
        stripped = v.strip().lower()
        if not stripped:
            raise ValueError("host cannot be empty")
        # Basic validation - no spaces allowed
        if " " in stripped:
            raise ValueError("host cannot contain spaces")
        return stripped

    @field_validator("id")
    @classmethod
    def id_must_be_valid_uuid(cls, v: str) -> str:
        """Validate that id is a valid UUID string."""
        try:
            uuid.UUID(v)
        except ValueError as e:
            raise ValueError("id must be a valid UUID") from e
        return v

    @field_validator("type", mode="before")
    @classmethod
    def coerce_proxy_type(cls, v: str | ProxyType) -> ProxyType:
        """Coerce string to ProxyType enum for JSON deserialization.

        Args:
            v: Either a string ('socks5', 'http') or ProxyType enum.

        Returns:
            ProxyType enum value.

        Raises:
            ValueError: If string doesn't match a valid proxy type.
        """
        if isinstance(v, ProxyType):
            return v
        if isinstance(v, str):
            try:
                return ProxyType(v.lower())
            except ValueError as e:
                raise ValueError(f"Invalid proxy type: {v}. Must be 'socks5' or 'http'.") from e
        raise ValueError(f"type must be a string or ProxyType, got {type(v)}")

    @property
    def has_auth(self) -> bool:
        """Check if proxy has authentication credentials.

        Returns:
            True if username is provided.
        """
        return bool(self.username)

    def to_telethon_proxy(self) -> tuple[int, str, int, bool, str | None, str | None]:
        """Convert to Telethon proxy format.

        Returns:
            Tuple of (proxy_type, host, port, rdns, username, password)
        """
        import socks

        proxy_type_map = {
            ProxyType.SOCKS5: socks.SOCKS5,
            ProxyType.HTTP: socks.HTTP,
        }

        return (
            proxy_type_map[self.type],
            self.host,
            self.port,
            True,  # rdns (resolve DNS remotely)
            self.username or None,
            self.password or None,
        )
