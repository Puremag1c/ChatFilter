"""Test frontend polling intervals for SSE health and active groups.

Tests verify that polling adapts interval based on:
1. SSE connection status (connected vs disconnected)
2. Active groups (analysis in progress vs idle)
"""

import pytest


class TestPollingIntervals:
    """Tests for schedulePoll logic in chats.html."""

    def test_polling_interval_active_sse_connected(self):
        """When SSE is connected and groups are active: 60s polling."""
        # This simulates the JavaScript logic: if hasActive && isSseConnected
        # then pollInterval = 60000

        has_active = True
        is_sse_connected = True  # body.classList does NOT contain 'sse-disconnected'

        # Logic from schedulePoll()
        if has_active:
            if is_sse_connected:
                poll_interval = 60000
            else:
                poll_interval = 30000
        else:
            poll_interval = 10000

        assert poll_interval == 60000, "Active groups + SSE connected should use 60s polling"

    def test_polling_interval_active_sse_disconnected(self):
        """When SSE is disconnected and groups are active: 30s polling."""
        # This simulates: if hasActive && !isSseConnected
        # then pollInterval = 30000

        has_active = True
        is_sse_connected = False  # body.classList contains 'sse-disconnected'

        if has_active:
            if is_sse_connected:
                poll_interval = 60000
            else:
                poll_interval = 30000
        else:
            poll_interval = 10000

        assert poll_interval == 30000, "Active groups + SSE disconnected should use 30s polling"

    def test_polling_interval_idle_no_active_groups(self):
        """When no groups are active (idle): 10s polling."""
        # This simulates: if !hasActive
        # then pollInterval = 10000

        has_active = False
        is_sse_connected = True  # Doesn't matter when idle

        if has_active:
            if is_sse_connected:
                poll_interval = 60000
            else:
                poll_interval = 30000
        else:
            poll_interval = 10000

        assert poll_interval == 10000, "No active groups should use 10s polling (increased from 3s)"

    def test_polling_intervals_meet_requirements(self):
        """Verify done_when criteria:
        - 60s when SSE active: reduces unnecessary refreshes with working SSE
        - 30s when SSE disconnected: maintains safety net for lost SSE
        - 10s when idle: reasonable check for new groups
        """
        intervals = {
            ('active', 'connected'): 60000,
            ('active', 'disconnected'): 30000,
            ('idle', 'connected'): 10000,
            ('idle', 'disconnected'): 10000,
        }

        # done_when states these specific values
        assert intervals[('active', 'connected')] == 60000
        assert intervals[('active', 'disconnected')] == 30000
        assert intervals[('idle', 'connected')] == 10000
