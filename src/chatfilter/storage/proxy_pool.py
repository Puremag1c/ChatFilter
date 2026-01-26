"""CRUD functions for proxy pool management.

Provides load/save operations for the proxy pool stored in data/config/proxies.json.
All write operations use atomic writes to prevent data corruption.
"""

from __future__ import annotations

import logging
from pathlib import Path

from chatfilter.models.proxy import ProxyEntry
from chatfilter.storage.errors import StorageNotFoundError
from chatfilter.storage.helpers import load_json, save_json
from chatfilter.utils.paths import get_application_path

logger = logging.getLogger(__name__)

PROXIES_FILE = "data/config/proxies.json"


def _get_proxies_path() -> Path:
    """Get the path to the proxies.json file.

    Returns:
        Path to data/config/proxies.json relative to application root.
    """
    return get_application_path() / PROXIES_FILE


def load_proxy_pool() -> list[ProxyEntry]:
    """Load all proxies from the pool.

    Returns:
        List of ProxyEntry objects. Empty list if file doesn't exist.

    Raises:
        StorageCorruptedError: If JSON is invalid.
        pydantic.ValidationError: If proxy data is invalid.
    """
    path = _get_proxies_path()

    if not path.exists():
        return []

    data = load_json(path)

    if not isinstance(data, list):
        logger.warning(f"Invalid proxy pool format (expected list): {path}")
        return []

    proxies = [ProxyEntry.model_validate(item) for item in data]
    logger.debug(f"Loaded {len(proxies)} proxies from pool")
    return proxies


def save_proxy_pool(proxies: list[ProxyEntry]) -> None:
    """Save all proxies to the pool.

    Uses atomic write to prevent data corruption.

    Args:
        proxies: List of ProxyEntry objects to save.

    Raises:
        StorageValidationError: If data cannot be serialized.
        StoragePermissionError: If write permission denied.
    """
    path = _get_proxies_path()

    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Convert to list of dicts for JSON serialization
    data = [proxy.model_dump() for proxy in proxies]

    save_json(path, data)
    logger.debug(f"Saved {len(proxies)} proxies to pool")


def get_proxy_by_id(proxy_id: str) -> ProxyEntry:
    """Get a proxy by its ID.

    Args:
        proxy_id: UUID of the proxy to find.

    Returns:
        ProxyEntry with matching ID.

    Raises:
        StorageNotFoundError: If proxy not found.
    """
    proxies = load_proxy_pool()

    for proxy in proxies:
        if proxy.id == proxy_id:
            return proxy

    raise StorageNotFoundError(f"Proxy not found: {proxy_id}")


def add_proxy(proxy: ProxyEntry) -> ProxyEntry:
    """Add a new proxy to the pool.

    Args:
        proxy: ProxyEntry to add.

    Returns:
        The added proxy.

    Raises:
        ValueError: If proxy with same ID already exists.
    """
    proxies = load_proxy_pool()

    # Check for duplicate ID
    for existing in proxies:
        if existing.id == proxy.id:
            raise ValueError(f"Proxy with ID {proxy.id} already exists")

    proxies.append(proxy)
    save_proxy_pool(proxies)

    logger.info(f"Added proxy to pool: {proxy.name} ({proxy.id})")
    return proxy


def remove_proxy(proxy_id: str) -> None:
    """Remove a proxy from the pool.

    Args:
        proxy_id: UUID of the proxy to remove.

    Raises:
        StorageNotFoundError: If proxy not found.
    """
    proxies = load_proxy_pool()
    original_count = len(proxies)

    proxies = [p for p in proxies if p.id != proxy_id]

    if len(proxies) == original_count:
        raise StorageNotFoundError(f"Proxy not found: {proxy_id}")

    save_proxy_pool(proxies)
    logger.info(f"Removed proxy from pool: {proxy_id}")
