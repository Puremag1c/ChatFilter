"""URL validation to prevent SSRF attacks.

Validates external URLs before fetching to block:
- Private IP addresses (RFC1918)
- Localhost / loopback addresses
- Link-local addresses
- Cloud metadata endpoints
- Unauthorized domains
"""

from __future__ import annotations

import ipaddress
import socket
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from collections.abc import Iterable


class URLValidationError(Exception):
    """Raised when URL fails security validation."""


# Allowed domains for external file fetching
DEFAULT_ALLOWED_DOMAINS = {
    "docs.google.com",
    "drive.google.com",
    "sheets.google.com",
    "www.dropbox.com",
    "dropbox.com",
    "dl.dropboxusercontent.com",
}

# Known cloud metadata endpoints to block
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, Azure, GCP metadata service
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
}


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private/internal.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        True if IP is private/internal
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        # Invalid IP address
        return True  # Block invalid IPs


def is_cloud_metadata_ip(ip: str) -> bool:
    """Check if IP is a known cloud metadata endpoint.

    Args:
        ip: IP address string

    Returns:
        True if IP is a cloud metadata endpoint
    """
    return ip in CLOUD_METADATA_IPS


def resolve_hostname(hostname: str) -> list[str]:
    """Resolve hostname to IP addresses.

    Args:
        hostname: Domain name to resolve

    Returns:
        List of IP addresses

    Raises:
        URLValidationError: If DNS resolution fails
    """
    try:
        # Get all IP addresses for this hostname
        addr_info = socket.getaddrinfo(hostname, None)
        # Extract unique IPs (addr_info returns tuples)
        ips = {info[4][0] for info in addr_info}
        return list(ips)
    except (socket.gaierror, OSError) as e:
        raise URLValidationError(f"DNS resolution failed for {hostname}: {e}") from e


def validate_url(
    url: str,
    allowed_domains: Iterable[str] | None = None,
    allow_private_ips: bool = False,
) -> None:
    """Validate URL for security before fetching.

    Blocks:
    - Non-HTTP(S) schemes
    - Private IP addresses (RFC1918, loopback, link-local)
    - Cloud metadata endpoints
    - Domains not in allowlist (if provided)

    Args:
        url: URL to validate
        allowed_domains: Set of allowed domains (None = use defaults)
        allow_private_ips: Allow private IPs (default: False, for testing only)

    Raises:
        URLValidationError: If URL fails validation
    """
    if not url:
        raise URLValidationError("URL cannot be empty")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise URLValidationError(f"Invalid URL format: {e}") from e

    # Validate scheme
    if parsed.scheme not in ("http", "https"):
        raise URLValidationError(
            f"Unsupported URL scheme: {parsed.scheme}. Only HTTP(S) allowed."
        )

    # Extract hostname
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL must have a hostname")

    # Check domain allowlist
    if allowed_domains is None:
        allowed_domains = get_allowed_domains()
    else:
        # Convert to set if needed
        allowed_domains = set(allowed_domains)

    if allowed_domains and hostname not in allowed_domains:
        raise URLValidationError(
            f"Domain not allowed: {hostname}. Allowed domains: {', '.join(sorted(allowed_domains))}"
        )

    # Skip IP validation if explicitly allowed (for testing)
    if allow_private_ips:
        return

    # Check if hostname is already an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        ip_str = str(ip)

        # Block cloud metadata endpoints
        if is_cloud_metadata_ip(ip_str):
            raise URLValidationError(
                f"Blocked cloud metadata endpoint: {ip_str}"
            )

        # Block private IPs
        if is_private_ip(ip_str):
            raise URLValidationError(
                f"Private IP address not allowed: {ip_str}"
            )

        return
    except ValueError:
        # Not an IP address, need to resolve hostname
        pass

    # Resolve hostname to IPs and validate each
    try:
        resolved_ips = resolve_hostname(hostname)
    except URLValidationError:
        # Re-raise DNS errors
        raise

    if not resolved_ips:
        raise URLValidationError(f"Could not resolve hostname: {hostname}")

    # Check all resolved IPs
    for ip_str in resolved_ips:
        # Block cloud metadata
        if is_cloud_metadata_ip(ip_str):
            raise URLValidationError(
                f"Hostname {hostname} resolves to blocked cloud metadata endpoint: {ip_str}"
            )

        # Block private IPs
        if is_private_ip(ip_str):
            raise URLValidationError(
                f"Hostname {hostname} resolves to private IP address: {ip_str}"
            )


def get_allowed_domains() -> set[str]:
    """Get current list of allowed domains.

    Combines default allowed domains with user-configured additional domains.

    Returns:
        Set of allowed domain names
    """
    from chatfilter.config import get_settings

    allowed = set(DEFAULT_ALLOWED_DOMAINS)

    # Add user-configured domains
    try:
        settings = get_settings()
        if settings.allowed_file_domains:
            allowed.update(settings.allowed_file_domains)
    except Exception:
        # Fallback to defaults if config unavailable
        pass

    return allowed
