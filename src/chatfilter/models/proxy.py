"""Proxy pool models for managing multiple proxy configurations."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from chatfilter.config import ProxyStatus, ProxyType


def _parse_datetime(v: str | datetime | None) -> datetime | None:
    """Parse ISO string to datetime for JSON deserialization."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    raise ValueError(f"Expected datetime, ISO string, or None, got {type(v)}")


# Type alias for datetime fields that accept ISO strings
FlexibleDatetime = Annotated[datetime | None, BeforeValidator(_parse_datetime)]


class ProxyEntry(BaseModel):
    """A proxy configuration entry in the proxy pool.

    Each proxy entry has a unique ID and can be used to connect
    Telegram sessions through different proxies. Includes health
    monitoring status for automatic availability management.

    Attributes:
        id: Unique identifier (UUID4, auto-generated).
        name: Human-readable name for the proxy.
        type: Proxy protocol type (socks5 or http).
        host: Proxy server hostname or IP.
        port: Proxy server port (1-65535).
        username: Optional authentication username.
        password: Optional authentication password.
        status: Health status (working, no_ping, untested).
        last_ping_at: Timestamp of last health check attempt.
        last_success_at: Timestamp of last successful health check.
        consecutive_failures: Count of consecutive failed health checks.

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
        >>> proxy.is_available
        True
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

    # Health monitoring fields
    status: ProxyStatus = Field(default=ProxyStatus.UNTESTED)
    last_ping_at: FlexibleDatetime = Field(default=None)
    last_success_at: FlexibleDatetime = Field(default=None)
    consecutive_failures: int = Field(default=0, ge=0)

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

    @field_validator("status", mode="before")
    @classmethod
    def coerce_proxy_status(cls, v: str | ProxyStatus) -> ProxyStatus:
        """Coerce string to ProxyStatus enum for JSON deserialization.

        Args:
            v: Either a string ('working', 'no_ping', 'untested') or ProxyStatus enum.

        Returns:
            ProxyStatus enum value.

        Raises:
            ValueError: If string doesn't match a valid proxy status.
        """
        if isinstance(v, ProxyStatus):
            return v
        if isinstance(v, str):
            try:
                return ProxyStatus(v.lower())
            except ValueError as e:
                raise ValueError(
                    f"Invalid proxy status: {v}. Must be 'working', 'no_ping', or 'untested'."
                ) from e
        raise ValueError(f"status must be a string or ProxyStatus, got {type(v)}")

    @property
    def has_auth(self) -> bool:
        """Check if proxy has authentication credentials.

        Returns:
            True if username is provided.
        """
        return bool(self.username)

    @property
    def is_available(self) -> bool:
        """Check if proxy is available for use (working or untested).

        Returns:
            True if proxy can be used for new connections.
        """
        return self.status != ProxyStatus.NO_PING

    def with_health_update(
        self,
        *,
        success: bool,
        ping_time: datetime | None = None,
    ) -> ProxyEntry:
        """Create a new ProxyEntry with updated health status.

        Since ProxyEntry is immutable (frozen=True), this returns a new instance.

        Args:
            success: Whether the ping was successful.
            ping_time: When the ping was performed (defaults to now).

        Returns:
            New ProxyEntry with updated health fields.
        """
        from datetime import UTC

        now = ping_time or datetime.now(UTC)

        if success:
            return ProxyEntry(
                id=self.id,
                name=self.name,
                type=self.type,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                status=ProxyStatus.WORKING,
                last_ping_at=now,
                last_success_at=now,
                consecutive_failures=0,
            )
        else:
            new_failures = self.consecutive_failures + 1
            # Auto-disable after 3 consecutive failures
            # Special case: if proxy was UNTESTED (from retest), 1 failure = NO_PING
            if self.status == ProxyStatus.UNTESTED:
                new_status = ProxyStatus.NO_PING
            elif new_failures >= 3:
                new_status = ProxyStatus.NO_PING
            else:
                new_status = self.status  # Keep WORKING if less than 3 failures

            return ProxyEntry(
                id=self.id,
                name=self.name,
                type=self.type,
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                status=new_status,
                last_ping_at=now,
                last_success_at=self.last_success_at,
                consecutive_failures=new_failures,
            )

    def with_status_reset(self) -> ProxyEntry:
        """Create a new ProxyEntry with reset health status for retesting.

        Returns:
            New ProxyEntry with status reset to UNTESTED and counters cleared.
        """
        return ProxyEntry(
            id=self.id,
            name=self.name,
            type=self.type,
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            status=ProxyStatus.UNTESTED,
            last_ping_at=self.last_ping_at,  # Keep last ping time
            last_success_at=self.last_success_at,  # Keep last success time
            consecutive_failures=0,
        )

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
