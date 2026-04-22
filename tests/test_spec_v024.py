"""Tests for SPEC.md v0.24.0 requirements coverage.

Covers:
- Must Have #1: Non-blocking start/resume/reanalyze endpoints
- Must Have #3: No elapsed timer in group_card.html
- Must Have #4: No network-status indicator in base.html
"""

from __future__ import annotations

import inspect
import io
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_csrf(client: TestClient) -> str:
    resp = client.get("/chats")
    for pattern in [
        r'<meta\s+name="csrf-token"\s+content="([^"]+)"',
        r'data-csrf-token="([^"]+)"',
    ]:
        m = re.search(pattern, resp.text)
        if m:
            return m.group(1)
    return ""


def _create_group(client: TestClient, tmp_path: Path) -> str:
    os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")
    csrf_token = _get_csrf(client)

    csv_bytes = b"username\n@test_chat_1\n@test_chat_2\n"
    files = {"file_upload": ("chats.csv", io.BytesIO(csv_bytes), "text/csv")}
    data = {"name": "Test Group v024", "source_type": "file_upload"}

    create_resp = client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert create_resp.status_code == 200, f"Group creation failed: {create_resp.text[:300]}"

    for pattern in [
        r'id="group-([^"]+)"',
        r'data-group-id="([^"]+)"',
        r'/api/groups/([^/"]+)/start',
    ]:
        m = re.search(pattern, create_resp.text)
        if m:
            return m.group(1)

    pytest.fail(f"Could not extract group ID: {create_resp.text[:500]}")


# ---------------------------------------------------------------------------
# Must Have #3: No elapsed timer
# ---------------------------------------------------------------------------


class TestNoElapsedTimer:
    """Verify elapsed timer elements removed from group_card.html (SPEC Must Have #3)."""

    def test_group_card_template_no_elapsed_element(self) -> None:
        """group_card.html must not contain elapsed-{id} element."""
        template_path = Path("src/chatfilter/templates/partials/group_card.html")
        assert template_path.exists()
        content = template_path.read_text()

        assert "elapsed-" not in content, (
            "group_card.html still has elapsed timer element — remove it (SPEC #3)"
        )

    def test_group_card_template_no_data_started_at(self) -> None:
        """group_card.html must not contain data-started-at attribute."""
        template_path = Path("src/chatfilter/templates/partials/group_card.html")
        content = template_path.read_text()

        assert "data-started-at" not in content, (
            "group_card.html still has data-started-at — timer data attr must be removed (SPEC #3)"
        )

    def test_group_card_template_no_start_elapsed_timer_call(self) -> None:
        """group_card.html must not call startElapsedTimer."""
        template_path = Path("src/chatfilter/templates/partials/group_card.html")
        content = template_path.read_text()

        assert "startElapsedTimer" not in content, (
            "group_card.html still calls startElapsedTimer (SPEC #3)"
        )

    def test_rendered_group_card_no_elapsed_element(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """Rendered group card API response must not contain elapsed timer element."""
        group_id = _create_group(fastapi_test_client, tmp_path)

        resp = fastapi_test_client.get("/api/groups")
        assert resp.status_code == 200

        assert f'id="elapsed-{group_id}"' not in resp.text, (
            "Rendered group card still has elapsed timer element (SPEC #3)"
        )
        assert "data-started-at" not in resp.text, (
            "Rendered group card still has data-started-at attribute (SPEC #3)"
        )


# ---------------------------------------------------------------------------
# Must Have #4: No network-status indicator
# ---------------------------------------------------------------------------


class TestNoNetworkStatusIndicator:
    """Verify network-status indicator removed from base.html (SPEC Must Have #4)."""

    def test_base_template_no_network_status_div(self) -> None:
        """base.html must not contain id='network-status' div."""
        base_path = Path("src/chatfilter/templates/base.html")
        assert base_path.exists()
        content = base_path.read_text()

        assert 'id="network-status"' not in content, (
            "base.html still has network-status div (SPEC #4)"
        )
        assert 'class="network-status"' not in content, (
            "base.html still has .network-status element (SPEC #4)"
        )

    def test_base_template_no_network_status_script(self) -> None:
        """base.html must not load network-status.js."""
        base_path = Path("src/chatfilter/templates/base.html")
        content = base_path.read_text()

        assert "network-status.js" not in content, (
            "base.html still loads network-status.js (SPEC #4)"
        )

    def test_network_status_js_file_deleted(self) -> None:
        """network-status.js must be deleted from static/js/."""
        js_path = Path("src/chatfilter/static/js/network-status.js")
        assert not js_path.exists(), "network-status.js still exists — must be deleted (SPEC #4)"

    def test_rendered_chats_page_no_network_status(self, fastapi_test_client: TestClient) -> None:
        """Rendered /chats page must not contain network-status elements."""
        resp = fastapi_test_client.get("/chats")
        assert resp.status_code == 200

        assert 'id="network-status"' not in resp.text, (
            "Rendered /chats page still has network-status element (SPEC #4)"
        )
        assert "network-status.js" not in resp.text, (
            "Rendered /chats page still loads network-status.js (SPEC #4)"
        )


# ---------------------------------------------------------------------------
# Must Have #1: Non-blocking analysis endpoints
# ---------------------------------------------------------------------------


class TestNonBlockingAnalysisEndpoints:
    """Verify start/reanalyze/resume use background tasks (SPEC Must Have #1)."""

    def test_group_service_start_analysis_uses_create_task(self) -> None:
        """GroupService.start_analysis must fire asyncio.create_task, not await."""
        from chatfilter.service.group_service import GroupService

        source = inspect.getsource(GroupService.start_analysis)
        assert "create_task" in source, (
            "GroupService.start_analysis must use create_task for non-blocking execution (SPEC #1)"
        )
        assert "await self._run_analysis" not in source, (
            "GroupService.start_analysis must not directly await _run_analysis (SPEC #1)"
        )

    def test_group_service_reanalyze_uses_create_task(self) -> None:
        """GroupService.reanalyze must fire asyncio.create_task, not await."""
        from chatfilter.service.group_service import GroupService

        source = inspect.getsource(GroupService.reanalyze)
        assert "create_task" in source, (
            "GroupService.reanalyze must use create_task for non-blocking execution (SPEC #1)"
        )
        assert "await self._run_analysis" not in source, (
            "GroupService.reanalyze must not directly await _run_analysis (SPEC #1)"
        )

    def test_router_start_does_not_await_service(self) -> None:
        """start_group_analysis router hands off to the persistent queue.

        Redesign: instead of running analyze_group in-process, /start
        writes rows into analysis_queue via engine.enqueue_group_analysis.
        The endpoint must return quickly — no `await engine.enqueue*`
        either, since enqueue is a synchronous DB write.
        """
        from chatfilter.web.routers.groups.analysis import start_group_analysis

        source = inspect.getsource(start_group_analysis)
        assert "enqueue_group_analysis(" in source, (
            "start_group_analysis must call engine.enqueue_group_analysis"
        )
        assert "await engine.enqueue_group_analysis" not in source, (
            "enqueue_group_analysis is synchronous — endpoint must not await it"
        )

    def test_router_reanalyze_does_not_await_service(self) -> None:
        """reanalyze_group also uses enqueue_group_analysis."""
        from chatfilter.web.routers.groups.analysis import reanalyze_group

        source = inspect.getsource(reanalyze_group)
        assert "enqueue_group_analysis(" in source, (
            "reanalyze_group must call engine.enqueue_group_analysis"
        )
        assert "await engine.enqueue_group_analysis" not in source, (
            "enqueue_group_analysis is synchronous — endpoint must not await it"
        )

    def test_router_resume_calls_service_start_analysis(self) -> None:
        """resume_group_analysis router must delegate to service.start_analysis."""
        from chatfilter.web.routers.groups.analysis import resume_group_analysis

        source = inspect.getsource(resume_group_analysis)
        assert "service.start_analysis(" in source, (
            "resume_group_analysis must call service.start_analysis (SPEC #1)"
        )
        assert "await service.start_analysis" not in source, (
            "resume_group_analysis must not await service.start_analysis (SPEC #1)"
        )

    def test_start_endpoint_returns_204_or_error_immediately(
        self, fastapi_test_client: TestClient, tmp_path: Path
    ) -> None:
        """POST /api/groups/{id}/start must return HTTP response without blocking."""
        group_id = _create_group(fastapi_test_client, tmp_path)
        csrf_token = _get_csrf(fastapi_test_client)

        resp = fastapi_test_client.post(
            f"/api/groups/{group_id}/start",
            headers={"X-CSRF-Token": csrf_token},
        )

        # 204 = started successfully, 200 = error with toast (no accounts), 409 = already running
        assert resp.status_code in (200, 204, 409), (
            f"Unexpected status {resp.status_code} from start endpoint: {resp.text[:300]}"
        )
