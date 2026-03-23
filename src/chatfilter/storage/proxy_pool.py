"""CRUD functions for proxy pool management.

Provides load/save operations for the proxy pool stored in user's config directory.
Uses platform-specific paths via settings.config_dir (not relative to app bundle).
All write operations use atomic writes to prevent data corruption.
"""

from __future__ import annotations

import logging
from pathlib import Path

from chatfilter.config import get_settings
from chatfilter.models.proxy import ProxyEntry
from chatfilter.storage.errors import StorageNotFoundError
from chatfilter.storage.helpers import load_json, save_json

logger = logging.getLogger(__name__)


def _get_proxies_path(user_id: str) -> Path:
    """Get the path to the per-user proxies file.

    Args:
        user_id: Web application user ID for data isolation.

    Returns:
        Path to proxies_{user_id}.json in user's config directory.
    """
    return get_settings().config_dir / f"proxies_{user_id}.json"


def load_proxy_pool(user_id: str) -> list[ProxyEntry]:
    """Load all proxies from the pool for a specific user.

    Automatically migrates legacy proxy.json on first call if needed.

    Args:
        user_id: Web application user ID for data isolation.

    Returns:
        List of ProxyEntry objects. Empty list if file doesn't exist.

    Raises:
        StorageCorruptedError: If JSON is invalid.
        pydantic.ValidationError: If proxy data is invalid.
    """
    path = _get_proxies_path(user_id)

    if not path.exists():
        return []

    data = load_json(path)

    if not isinstance(data, list):
        logger.warning(f"Invalid proxy pool format (expected list): {path}")
        return []

    proxies = [ProxyEntry.model_validate(item) for item in data]
    logger.debug(f"Loaded {len(proxies)} proxies from pool")
    return proxies


def save_proxy_pool(proxies: list[ProxyEntry], user_id: str) -> None:
    """Save all proxies to the pool for a specific user.

    Uses atomic write to prevent data corruption.

    Args:
        proxies: List of ProxyEntry objects to save.
        user_id: Web application user ID for data isolation.

    Raises:
        StorageValidationError: If data cannot be serialized.
        StoragePermissionError: If write permission denied.
    """
    path = _get_proxies_path(user_id)

    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert to list of dicts for JSON serialization
    # mode='json' ensures datetime objects are serialized as ISO strings
    data = [proxy.model_dump(mode="json") for proxy in proxies]

    save_json(path, data)
    logger.debug(f"Saved {len(proxies)} proxies to pool")


def get_proxy_by_id(proxy_id: str, user_id: str) -> ProxyEntry:
    """Get a proxy by its ID.

    Args:
        proxy_id: UUID of the proxy to find.
        user_id: Web application user ID for data isolation.

    Returns:
        ProxyEntry with matching ID.

    Raises:
        StorageNotFoundError: If proxy not found.
    """
    proxies = load_proxy_pool(user_id)

    for proxy in proxies:
        if proxy.id == proxy_id:
            return proxy

    raise StorageNotFoundError(f"Proxy not found: {proxy_id}")


def add_proxy(proxy: ProxyEntry, user_id: str) -> ProxyEntry:
    """Add a new proxy to the pool.

    Args:
        proxy: ProxyEntry to add.
        user_id: Web application user ID for data isolation.

    Returns:
        The added proxy.

    Raises:
        ValueError: If proxy with same ID already exists.
    """
    proxies = load_proxy_pool(user_id)

    # Check for duplicate ID
    for existing in proxies:
        if existing.id == proxy.id:
            raise ValueError(f"Proxy with ID {proxy.id} already exists")

    proxies.append(proxy)
    save_proxy_pool(proxies, user_id)

    logger.info(f"Added proxy to pool: {proxy.name} ({proxy.id})")
    return proxy


def remove_proxy(proxy_id: str, user_id: str) -> None:
    """Remove a proxy from the pool.

    Args:
        proxy_id: UUID of the proxy to remove.
        user_id: Web application user ID for data isolation.

    Raises:
        StorageNotFoundError: If proxy not found.
    """
    proxies = load_proxy_pool(user_id)
    original_count = len(proxies)

    proxies = [p for p in proxies if p.id != proxy_id]

    if len(proxies) == original_count:
        raise StorageNotFoundError(f"Proxy not found: {proxy_id}")

    save_proxy_pool(proxies, user_id)
    logger.info(f"Removed proxy from pool: {proxy_id}")


def update_proxy(proxy_id: str, updated_proxy: ProxyEntry, user_id: str) -> ProxyEntry:
    """Update an existing proxy in the pool.

    Args:
        proxy_id: UUID of the proxy to update.
        updated_proxy: New ProxyEntry data (must have same ID).
        user_id: Web application user ID for data isolation.

    Returns:
        The updated proxy entry.

    Raises:
        StorageNotFoundError: If proxy not found.
        ValueError: If proxy_id doesn't match updated_proxy.id.
    """
    if proxy_id != updated_proxy.id:
        raise ValueError("proxy_id must match updated_proxy.id")

    proxies = load_proxy_pool(user_id)
    found = False

    for i, proxy in enumerate(proxies):
        if proxy.id == proxy_id:
            proxies[i] = updated_proxy
            found = True
            break

    if not found:
        raise StorageNotFoundError(f"Proxy not found: {proxy_id}")

    save_proxy_pool(proxies, user_id)
    logger.debug(f"Updated proxy in pool: {updated_proxy.name} ({proxy_id})")
    return updated_proxy
