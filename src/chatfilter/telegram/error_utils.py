"""Utility functions for error handling in Telegram operations."""

from __future__ import annotations

import re

from chatfilter.i18n import ngettext


def _format_duration(seconds: int) -> str:
    """Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Human-readable duration string (e.g., "5 minutes", "1 hour")

    Examples:
        >>> _format_duration(30)
        '30 seconds'
        >>> _format_duration(120)
        '2 minutes'
        >>> _format_duration(3600)
        '1 hour'
        >>> _format_duration(7200)
        '2 hours'
    """
    if seconds < 60:
        return ngettext("%(num)d second", "%(num)d seconds", seconds) % {"num": seconds}
    elif seconds < 3600:
        minutes = seconds // 60
        return ngettext("%(num)d minute", "%(num)d minutes", minutes) % {"num": minutes}
    else:
        hours = seconds // 3600
        return ngettext("%(num)d hour", "%(num)d hours", hours) % {"num": hours}


def _extract_wait_time(error: BaseException) -> int | None:
    """Extract wait time from FloodWaitError.

    Args:
        error: Exception that might contain wait time info

    Returns:
        Wait time in seconds, or None if not found

    Examples:
        >>> from telethon.errors import FloodWaitError
        >>> err = FloodWaitError(request=None, capture=3600)
        >>> _extract_wait_time(err)
        3600
    """
    # FloodWaitError stores wait time in the 'seconds' attribute
    if hasattr(error, "seconds"):
        return int(error.seconds)

    # Fallback: try to extract from error message
    error_msg = str(error)
    match = re.search(r"(\d+)\s*seconds?", error_msg, re.IGNORECASE)
    if match:
        return int(match.group(1))

    return None
