"""Active Telethon client registry for safe user data cleanup.

Tracks live TelegramClient instances by user_id so that disconnect_user_clients()
can cleanly stop all sessions before file deletion (e.g., admin user delete flow).
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

# user_id (str) -> list of active TelegramClient instances
_registry: dict[str, list[TelegramClient]] = {}


def register_client(user_id: str, client: TelegramClient) -> None:
    """Register an active TelegramClient for a user."""
    uid = str(user_id)
    if uid not in _registry:
        _registry[uid] = []
    if client not in _registry[uid]:
        _registry[uid].append(client)


def unregister_client(user_id: str, client: TelegramClient) -> None:
    """Remove a TelegramClient from the registry (called on normal disconnect)."""
    uid = str(user_id)
    clients = _registry.get(uid)
    if clients:
        with contextlib.suppress(ValueError):
            clients.remove(client)
        if not clients:
            del _registry[uid]


async def disconnect_user_clients(user_id: str) -> None:
    """Disconnect all active Telethon clients for user_id and clear registry entry.

    Call this before deleting user session files to prevent file-in-use errors.
    Safe to call even if user has no active clients.
    """
    uid = str(user_id)
    clients = _registry.pop(uid, [])
    for client in clients:
        try:
            if client.is_connected():
                await client.disconnect()
        except Exception:
            logger.warning("Failed to disconnect client for user %s", uid, exc_info=True)
