"""Regression tests for SSE duplicate group cards bug.

Verifies the fix that prevents duplicate group cards on /chats page.

Root cause: HTMX innerHTML swap + settle processing + request-dedup
interactions caused exponential card duplication during polling.
Fix: replaced HTMX polling with vanilla JS fetch + innerHTML on
#groups-container. Action buttons use hx-swap="none" + HX-Trigger
headers to trigger the JS-based refresh.

Regression for: ChatFilter-4ig52, ChatFilter-x778t
"""

from __future__ import annotations

import io
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _get_csrf(client: TestClient) -> str:
    """Extract CSRF token from /chats page."""
    resp = client.get("/chats")
    for pattern in [
        r'<meta\s+name="csrf-token"\s+content="([^"]+)"',
        r'<input\s+type="hidden"\s+name="csrf_token"\s+value="([^"]+)"',
        r'data-csrf-token="([^"]+)"',
    ]:
        m = re.search(pattern, resp.text)
        if m:
            return m.group(1)
    raise ValueError("No CSRF token found")


def _create_group(client: TestClient, name: str = "Test Group") -> str:
    """Create a group and return its ID."""
    csrf = _get_csrf(client)
    csv_content = b"url\nhttps://t.me/test_chat_1\nhttps://t.me/test_chat_2"
    resp = client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf},
        files={"file_upload": ("chats.csv", io.BytesIO(csv_content), "text/csv")},
        data={"name": name, "source_type": "file_upload"},
    )
    assert resp.status_code == 200
    m = re.search(r'id="group-([^"]+)"', resp.text)
    if not m:
        m = re.search(r'/api/groups/([^/"]+)/start', resp.text)
    assert m, f"Could not extract group ID from response: {resp.text[:300]}"
    return m.group(1)


class TestHXTriggerPattern:
    """Verify action endpoints return HX-Trigger headers, not card HTML."""

    def test_start_returns_hx_trigger_header(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Start endpoint must return HX-Trigger: refreshGroups, not card HTML."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        group_id = _create_group(fastapi_test_client)
        csrf = _get_csrf(fastapi_test_client)

        resp = fastapi_test_client.post(
            f"/api/groups/{group_id}/start",
            headers={"X-CSRF-Token": csrf},
        )

        if resp.status_code == 204:
            # Success path: 204 No Content + HX-Trigger
            assert resp.headers.get("HX-Trigger") == "refreshGroups"
            assert resp.text == "" or resp.content == b""
        elif resp.status_code == 200:
            # Error path (no Telegram accounts): 200 + empty body + HX-Trigger with showToast
            hx_trigger = resp.headers.get("HX-Trigger", "")
            assert "showToast" in hx_trigger, (
                f"Expected HX-Trigger with showToast, got: {hx_trigger}"
            )
            assert resp.text == "" or resp.content == b""
        else:
            pytest.fail(f"Unexpected status {resp.status_code}")

    def test_stop_returns_hx_trigger_header(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Stop endpoint must return HX-Trigger: refreshGroups, not card HTML."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        group_id = _create_group(fastapi_test_client)
        csrf = _get_csrf(fastapi_test_client)

        resp = fastapi_test_client.post(
            f"/api/groups/{group_id}/stop",
            headers={"X-CSRF-Token": csrf},
        )

        if resp.status_code == 204:
            assert resp.headers.get("HX-Trigger") == "refreshGroups"
            assert resp.text == "" or resp.content == b""
        else:
            # 400/404 are acceptable in test environment
            assert resp.status_code in (400, 404)

    def test_delete_returns_hx_trigger_header(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Delete endpoint must return HX-Trigger: refreshGroups header."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        group_id = _create_group(fastapi_test_client)
        csrf = _get_csrf(fastapi_test_client)

        resp = fastapi_test_client.delete(
            f"/api/groups/{group_id}",
            headers={"X-CSRF-Token": csrf},
        )

        assert resp.status_code == 200
        assert resp.headers.get("HX-Trigger") == "refreshGroups"


class TestGroupListNoDuplicates:
    """Verify /api/groups returns exactly one card per group."""

    def test_list_returns_unique_cards(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """GET /api/groups must return exactly one card per group."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        # Create 3 groups
        ids = []
        for i in range(3):
            gid = _create_group(fastapi_test_client, name=f"Group {i}")
            ids.append(gid)

        # Fetch group list
        resp = fastapi_test_client.get("/api/groups")
        assert resp.status_code == 200

        # Each group ID should appear exactly once
        for gid in ids:
            count = resp.text.count(f'id="group-{gid}"')
            assert count == 1, (
                f"Group {gid} appears {count} times in response (expected 1)"
            )

    def test_repeated_list_calls_return_stable_count(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Multiple calls to /api/groups must return the same card count (no growth)."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        _create_group(fastapi_test_client, name="Polling Test Group")

        counts = []
        for _ in range(5):
            resp = fastapi_test_client.get("/api/groups")
            assert resp.status_code == 200
            count = len(re.findall(r'class="group-card"', resp.text))
            counts.append(count)

        # All responses must have the same count (no accumulation)
        assert len(set(counts)) == 1, (
            f"Card count changed across 5 requests: {counts} — duplicates accumulating"
        )


class TestGroupCardTemplate:
    """Verify group_card.html template has correct hx-swap attributes."""

    def test_action_buttons_use_swap_none(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Action buttons in group card must use hx-swap='none'."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        group_id = _create_group(fastapi_test_client)

        # Get the groups list which includes rendered cards
        resp = fastapi_test_client.get("/api/groups")
        html = resp.text

        # Check start/stop button
        start_match = re.search(
            rf'hx-post="/api/groups/{re.escape(group_id)}/start"[^>]*>', html
        )
        if start_match:
            button_html = start_match.group(0)
            assert 'hx-swap="none"' in button_html, (
                f"Start button missing hx-swap='none': {button_html}"
            )
            assert 'hx-swap="outerHTML"' not in button_html, (
                "Start button has outerHTML swap — will cause duplicates"
            )

        # Check delete button
        delete_match = re.search(
            rf'hx-delete="/api/groups/{re.escape(group_id)}"[^>]*>', html
        )
        if delete_match:
            button_html = delete_match.group(0)
            assert 'hx-swap="none"' in button_html, (
                f"Delete button missing hx-swap='none': {button_html}"
            )
            assert 'hx-swap="outerHTML"' not in button_html, (
                "Delete button has outerHTML swap — will cause duplicates"
            )

    def test_no_inline_export_script_in_card(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Group card must NOT contain inline handleExportDownload script."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        _create_group(fastapi_test_client)

        resp = fastapi_test_client.get("/api/groups")
        # The handleExportDownload function should be in groups.js, not inline
        assert "window.handleExportDownload" not in resp.text, (
            "Inline handleExportDownload in card HTML causes re-execution on swap"
        )


class TestChatsPageNoDuplicatePolling:
    """Verify /chats page uses vanilla JS polling, not HTMX polling."""

    def test_groups_container_no_htmx_polling(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """#groups-container must NOT have hx-get or hx-trigger attributes."""
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        resp = fastapi_test_client.get("/chats")
        assert resp.status_code == 200

        container_match = re.search(r'id="groups-container"[^>]*>', resp.text)
        assert container_match, "groups-container not found in /chats page"
        container_html = container_match.group(0)
        assert "hx-get" not in container_html, (
            "groups-container has hx-get — HTMX polling causes duplicate cards"
        )
        assert "hx-trigger" not in container_html, (
            "groups-container has hx-trigger — HTMX polling causes duplicate cards"
        )

    def test_chats_page_has_vanilla_js_polling(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Chats page must include vanilla JS fetch-based polling script.

        The polling logic lives in static/js/chats-page.js (extracted from
        inline HTML). The page must load this script, and the script must
        contain the fetch-based polling implementation.
        """
        import os
        os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

        resp = fastapi_test_client.get("/chats")
        assert resp.status_code == 200

        # The external JS file must be loaded by the page
        assert "chats-page.js" in resp.text, (
            "Chats page missing chats-page.js script tag"
        )

        # Verify the JS file itself contains the polling implementation
        js_resp = fastapi_test_client.get("/static/js/chats-page.js")
        assert js_resp.status_code == 200, (
            "chats-page.js not served (static file serving broken)"
        )
        assert "fetch('/api/groups')" in js_resp.text, (
            "chats-page.js missing vanilla JS fetch polling for groups"
        )
        assert "refreshGroups" in js_resp.text, (
            "chats-page.js missing refreshGroups event listener"
        )
