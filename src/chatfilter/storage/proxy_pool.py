"""CRUD functions for proxy pool management.

Provides load/save operations for the proxy pool stored in user's config directory.
Uses platform-specific paths via settings.config_dir (not relative to app bundle).
All write operations use atomic writes to prevent data corruption.
"""

from __future__ import annotations

import logging
from pathlib import Path

from chatfilter.config import ProxyType, get_settings
from chatfilter.models.proxy import ProxyEntry
from chatfilter.storage.errors import StorageNotFoundError
from chatfilter.storage.helpers import load_json, save_json
from chatfilter.utils.paths import get_application_path

logger = logging.getLogger(__name__)

PROXIES_FILENAME = "proxies.json"
LEGACY_PROXY_FILENAME = "proxy.json"


def _get_proxies_path() -> Path:
    """Get the path to the proxies.json file.

    Returns:
        Path to proxies.json in user's config directory.
        On macOS: ~/Library/Application Support/ChatFilter/config/proxies.json
        On Windows: %APPDATA%/ChatFilter/config/proxies.json
        On Linux: ~/.local/share/chatfilter/config/proxies.json
    """
    return get_settings().config_dir / PROXIES_FILENAME


def _get_legacy_proxy_path() -> Path:
    """Get the path to the legacy proxy.json file (for migration only).

    Checks both old location (app bundle) and new location (user config dir).

    Returns:
        Path to legacy proxy.json if found, otherwise path in config_dir.
    """
    # First check old location (app bundle) for migration
    old_path = get_application_path() / "data" / "config" / LEGACY_PROXY_FILENAME
    if old_path.exists():
        return old_path
    # Fallback to config_dir
    return get_settings().config_dir / LEGACY_PROXY_FILENAME


def _migrate_legacy_proxy() -> None:
    """Migrate legacy proxy.json to proxies.json format.

    If proxy.json exists but proxies.json does not, creates a new proxy pool
    with a single entry from the legacy config, named "Default".

    This runs automatically on first load_proxy_pool() call.
    """
    proxies_path = _get_proxies_path()
    legacy_path = _get_legacy_proxy_path()

    # Only migrate if legacy exists and new doesn't
    if not legacy_path.exists() or proxies_path.exists():
        return

    try:
        legacy_data = load_json(legacy_path)
    except Exception as e:
        logger.warning(f"Failed to read legacy proxy.json during migration: {e}")
        return

    if not isinstance(legacy_data, dict):
        logger.warning("Invalid legacy proxy.json format (expected dict), skipping migration")
        return

    # Map legacy proxy_type to ProxyType enum
    proxy_type_str = legacy_data.get("proxy_type", "socks5")
    try:
        proxy_type = ProxyType(proxy_type_str)
    except ValueError:
        logger.warning(f"Unknown proxy type '{proxy_type_str}', defaulting to socks5")
        proxy_type = ProxyType.SOCKS5

    # Create ProxyEntry from legacy data
    try:
        proxy = ProxyEntry(
            name="Default",
            type=proxy_type,
            host=legacy_data.get("host", "127.0.0.1"),
            port=legacy_data.get("port", 1080),
            username=legacy_data.get("username", ""),
            password=legacy_data.get("password", ""),
        )
    except Exception as e:
        logger.warning(f"Failed to create ProxyEntry from legacy config: {e}")
        return

    # Save to new format
    proxies_path.parent.mkdir(parents=True, exist_ok=True)
    save_json(proxies_path, [proxy.model_dump()])

    logger.info(f"Migrated legacy proxy.json to proxies.json: {proxy.name} ({proxy.id})")


def load_proxy_pool() -> list[ProxyEntry]:
    """Load all proxies from the pool.

    Automatically migrates legacy proxy.json on first call if needed.

    Returns:
        List of ProxyEntry objects. Empty list if file doesn't exist.

    Raises:
        StorageCorruptedError: If JSON is invalid.
        pydantic.ValidationError: If proxy data is invalid.
    """
    # Migrate legacy config if needed
    _migrate_legacy_proxy()

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


def update_proxy(proxy_id: str, updated_proxy: ProxyEntry) -> ProxyEntry:
    """Update an existing proxy in the pool.

    Args:
        proxy_id: UUID of the proxy to update.
        updated_proxy: New ProxyEntry data (must have same ID).

    Returns:
        The updated proxy entry.

    Raises:
        StorageNotFoundError: If proxy not found.
        ValueError: If proxy_id doesn't match updated_proxy.id.
    """
    if proxy_id != updated_proxy.id:
        raise ValueError("proxy_id must match updated_proxy.id")

    proxies = load_proxy_pool()
    found = False

    for i, proxy in enumerate(proxies):
        if proxy.id == proxy_id:
            proxies[i] = updated_proxy
            found = True
            break

    if not found:
        raise StorageNotFoundError(f"Proxy not found: {proxy_id}")

    save_proxy_pool(proxies)
    logger.info(f"Updated proxy in pool: {updated_proxy.name} ({proxy_id})")
    return updated_proxy
