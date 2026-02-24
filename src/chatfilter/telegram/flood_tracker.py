"""FloodWaitTracker: global registry of FloodWait account lockouts.

Tracks which accounts are rate-limited by Telegram FloodWait errors and when they expire.
Thread-safe in-memory storage.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class FloodWaitTracker:
    """Tracks FloodWait lockouts for Telegram accounts.

    Maintains in-memory registry of {account_id: expiry_timestamp}.
    Thread-safe for concurrent access from multiple workers.
    """

    def __init__(self) -> None:
        self._lockouts: Dict[str, float] = {}
        self._lock = threading.Lock()

    def record_flood_wait(self, account_id: str, seconds: int) -> None:
        """Record FloodWait for account.

        Args:
            account_id: Telegram account identifier
            seconds: FloodWait duration from Telegram API
        """
        expiry = time.time() + seconds
        with self._lock:
            self._lockouts[account_id] = expiry
        logger.info(f"FloodWait recorded: account '{account_id}' blocked for {seconds}s (until {expiry})")

    def is_blocked(self, account_id: str) -> bool:
        """Check if account is currently blocked by FloodWait.

        Args:
            account_id: Account to check

        Returns:
            True if account is blocked, False otherwise
        """
        with self._lock:
            if account_id not in self._lockouts:
                return False
            expiry = self._lockouts[account_id]
            if time.time() < expiry:
                return True
            # Expired — remove entry
            del self._lockouts[account_id]
            logger.info(f"FloodWait expired: account '{account_id}' now available")
            return False

    def get_wait_until(self, account_id: str) -> Optional[float]:
        """Get expiry timestamp for account's FloodWait.

        Args:
            account_id: Account to check

        Returns:
            Expiry timestamp (time.time() format) or None if not blocked
        """
        with self._lock:
            return self._lockouts.get(account_id)

    def get_earliest_available(self) -> Optional[float]:
        """Get earliest expiry time across all blocked accounts.

        Returns:
            Earliest expiry timestamp or None if no accounts blocked
        """
        with self._lock:
            if not self._lockouts:
                return None
            return min(self._lockouts.values())

    def get_blocked_accounts(self) -> Dict[str, float]:
        """Get all blocked accounts with their expiry times.

        Returns:
            Dict of {account_id: expiry_timestamp}
        """
        with self._lock:
            # Remove expired entries
            current_time = time.time()
            expired = [aid for aid, exp in self._lockouts.items() if current_time >= exp]
            for aid in expired:
                del self._lockouts[aid]
                logger.info(f"FloodWait expired: account '{aid}' now available")
            return dict(self._lockouts)

    def clear_expired(self) -> int:
        """Remove expired FloodWait entries.

        Returns:
            Number of entries cleared
        """
        with self._lock:
            current_time = time.time()
            expired = [aid for aid, exp in self._lockouts.items() if current_time >= exp]
            for aid in expired:
                del self._lockouts[aid]
            if expired:
                logger.info(f"Cleared {len(expired)} expired FloodWait entries: {expired}")
            return len(expired)

    def clear_account(self, account_id: str) -> bool:
        """Clear FloodWait entry for specific account (e.g., when account is deleted).

        Args:
            account_id: Account to clear

        Returns:
            True if entry was removed, False if account wasn't blocked
        """
        with self._lock:
            if account_id in self._lockouts:
                del self._lockouts[account_id]
                logger.info(f"FloodWait cleared for account '{account_id}'")
                return True
            return False

    def clear_all(self) -> int:
        """Clear all FloodWait entries (for testing/cleanup).

        Returns:
            Number of entries cleared
        """
        with self._lock:
            count = len(self._lockouts)
            self._lockouts.clear()
            if count:
                logger.info(f"Cleared all {count} FloodWait entries")
            return count


# Global singleton
_global_tracker: Optional[FloodWaitTracker] = None
_tracker_lock = threading.Lock()


def get_flood_tracker() -> FloodWaitTracker:
    """Get global FloodWaitTracker singleton.

    Returns:
        Global FloodWaitTracker instance
    """
    global _global_tracker
    if _global_tracker is None:
        with _tracker_lock:
            if _global_tracker is None:
                _global_tracker = FloodWaitTracker()
    return _global_tracker
