"""Tests for groups API endpoints with CSRF protection.

This module tests the groups API endpoints to ensure they properly
handle CSRF tokens and reject requests without valid tokens.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient


def extract_csrf_token(html: str) -> str:
    """Extract CSRF token from HTML page.

    Looks for meta tag with csrf-token name or hidden input field.

    Args:
        html: HTML content to extract token from

    Returns:
        CSRF token string

    Raises:
        ValueError: If no CSRF token found
    """
    # Try meta tag first (common pattern)
    import re

    meta_pattern = r'<meta\s+name="csrf-token"\s+content="([^"]+)"'
    match = re.search(meta_pattern, html)
    if match:
        return match.group(1)

    # Try hidden input field
    input_pattern = r'<input\s+type="hidden"\s+name="csrf_token"\s+value="([^"]+)"'
    match = re.search(input_pattern, html)
    if match:
        return match.group(1)

    # Try data attribute
    data_pattern = r'data-csrf-token="([^"]+)"'
    match = re.search(data_pattern, html)
    if match:
        return match.group(1)

    raise ValueError("No CSRF token found in HTML")


def get_csrf_token(client: TestClient) -> str:
    """Get CSRF token from the application.

    Makes a GET request to /chats page and extracts the CSRF token.

    Args:
        client: FastAPI test client

    Returns:
        CSRF token string
    """
    response = client.get("/chats")
    assert response.status_code == 200
    return extract_csrf_token(response.text)


@pytest.fixture
def sample_csv_content() -> bytes:
    """Sample CSV file content for testing."""
    return b"""Chat Title,Chat Link
Test Group,https://t.me/test_group
Test Channel,https://t.me/test_channel"""


@pytest.fixture
def empty_csv_content() -> bytes:
    """Empty CSV file content for testing."""
    return b"""Chat Title,Chat Link"""


def test_create_group_endpoint_accepts_file(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that create group endpoint accepts file upload with CSRF token."""
    # Get CSRF token
    csrf_token = get_csrf_token(fastapi_test_client)

    # Create file upload
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group",
        "source_type": "file_upload",
    }

    # Make POST request with CSRF token
    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )

    # Should succeed with valid token
    assert response.status_code == 200
    assert "Test Group" in response.text


def test_create_group_without_csrf_fails(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that create group endpoint rejects requests without CSRF token."""
    # Create file upload
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group",
        "source_type": "file_upload",
    }

    # Make POST request WITHOUT CSRF token
    response = fastapi_test_client.post(
        "/api/groups",
        files=files,
        data=data,
    )

    # Should fail with 403
    assert response.status_code == 403
    assert "CSRF" in response.text or "csrf" in response.text


def test_empty_csv_file(
    fastapi_test_client: TestClient,
    empty_csv_content: bytes,
) -> None:
    """Test handling of CSV with only headers (no data rows)."""
    # Get CSRF token
    csrf_token = get_csrf_token(fastapi_test_client)

    # Create file upload with truly empty content (no rows at all)
    files = {
        "file_upload": ("empty.csv", io.BytesIO(b""), "text/csv")
    }
    data = {
        "name": "Empty Group",
        "source_type": "file_upload",
    }

    # Make POST request with CSRF token
    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )

    # Should return error about no valid chats or parsing error
    assert response.status_code == 200  # Returns HTML error partial
    assert "error" in response.text.lower() or "failed" in response.text.lower()


def test_start_analysis_endpoint(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
    tmp_path: Path,
) -> None:
    """Test start analysis endpoint with CSRF protection."""
    # Set up test data directory so groups persist
    import os
    os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

    # First create a group
    csrf_token = get_csrf_token(fastapi_test_client)

    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group for Analysis",
        "source_type": "file_upload",
    }

    create_response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert create_response.status_code == 200

    # Extract group ID from response (simple approach - look for data-group-id or id attribute)
    import re
    # Try id="group-XXX" pattern first
    match = re.search(r'id="group-([^"]+)"', create_response.text)
    if not match:
        # Try data-group-id pattern
        match = re.search(r'data-group-id="([^"]+)"', create_response.text)
    if not match:
        # Try URL pattern
        match = re.search(r'/api/groups/([^/"]+)/start', create_response.text)

    assert match, f"Could not find group ID in response. Response text: {create_response.text[:500]}"
    group_id = match.group(1)

    # Get fresh CSRF token for start request
    csrf_token = get_csrf_token(fastapi_test_client)

    # Start analysis with CSRF token
    response = fastapi_test_client.post(
        f"/api/groups/{group_id}/start",
        headers={"X-CSRF-Token": csrf_token},
    )

    # Should succeed (204 No Content with HX-Trigger header), return 404 if group not found,
    # or 200 with HX-Trigger showToast if no connected Telegram accounts (expected in test environment)
    assert response.status_code in (204, 200, 404)
    # If 200, it should have HX-Trigger header with showToast (NoConnectedAccountsError)
    if response.status_code == 200:
        assert "HX-Trigger" in response.headers
        import json
        trigger = json.loads(response.headers["HX-Trigger"])
        assert "showToast" in trigger
        assert trigger["showToast"]["type"] == "error"
        assert "account" in trigger["showToast"]["message"].lower()


def test_stop_analysis_endpoint(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
    tmp_path: Path,
) -> None:
    """Test stop analysis endpoint with CSRF protection."""
    # Set up test data directory so groups persist
    import os
    os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

    # First create a group
    csrf_token = get_csrf_token(fastapi_test_client)

    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group for Stop",
        "source_type": "file_upload",
    }

    create_response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert create_response.status_code == 200

    # Extract group ID
    import re
    # Try id="group-XXX" pattern first
    match = re.search(r'id="group-([^"]+)"', create_response.text)
    if not match:
        # Try data-group-id pattern
        match = re.search(r'data-group-id="([^"]+)"', create_response.text)
    if not match:
        # Try URL pattern
        match = re.search(r'/api/groups/([^/"]+)/stop', create_response.text)

    assert match, f"Could not find group ID in response. Response text: {create_response.text[:500]}"
    group_id = match.group(1)

    # Get fresh CSRF token for stop request
    csrf_token = get_csrf_token(fastapi_test_client)

    # Stop analysis with CSRF token
    response = fastapi_test_client.post(
        f"/api/groups/{group_id}/stop",
        headers={"X-CSRF-Token": csrf_token},
    )

    # Should succeed (204 No Content with HX-Trigger header), return 404 if group not found,
    # or 400 if no connected Telegram accounts (expected in test environment)
    assert response.status_code in (204, 400, 404)


def test_nonexistent_group_operations(
    fastapi_test_client: TestClient,
) -> None:
    """Test operations on non-existent group."""
    # Get CSRF token
    csrf_token = get_csrf_token(fastapi_test_client)

    nonexistent_id = "group_nonexistent_12345"

    # Try to start analysis on non-existent group
    response = fastapi_test_client.post(
        f"/api/groups/{nonexistent_id}/start",
        headers={"X-CSRF-Token": csrf_token},
    )

    # Should return 404 or error
    assert response.status_code in (404, 200)  # 200 if returns HTML error partial
    if response.status_code == 200:
        assert "not found" in response.text.lower() or "error" in response.text.lower()


def test_update_group_settings(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
    tmp_path: Path,
) -> None:
    """Test updating group settings endpoint."""
    # Set up test data directory
    import os
    os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

    # First create a group
    csrf_token = get_csrf_token(fastapi_test_client)

    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group for Settings",
        "source_type": "file_upload",
    }

    create_response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert create_response.status_code == 200

    # Extract group ID
    import re
    match = re.search(r'id="group-([^"]+)"', create_response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', create_response.text)
    if not match:
        match = re.search(r'/api/groups/([^/"]+)/settings', create_response.text)

    assert match, f"Could not find group ID in response. Response text: {create_response.text[:500]}"
    group_id = match.group(1)

    # Get fresh CSRF token for update request
    csrf_token = get_csrf_token(fastapi_test_client)

    # Update settings with new format
    settings_data = {
        "detect_chat_type": True,
        "detect_subscribers": False,
        "detect_activity": True,
        "detect_unique_authors": False,
        "detect_moderation": True,
        "detect_captcha": False,
        "time_window": 48,
    }

    response = fastapi_test_client.put(
        f"/api/groups/{group_id}/settings",
        headers={"X-CSRF-Token": csrf_token},
        data=settings_data,
    )

    # Should succeed
    assert response.status_code == 200
    # Response should contain updated group card
    assert "group" in response.text.lower() or group_id in response.text


def test_update_settings_all_disabled(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
    tmp_path: Path,
) -> None:
    """Test updating settings with all metrics disabled."""
    import os
    os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

    # Create a group
    csrf_token = get_csrf_token(fastapi_test_client)

    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group All Disabled",
        "source_type": "file_upload",
    }

    create_response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert create_response.status_code == 200

    # Extract group ID
    import re
    match = re.search(r'id="group-([^"]+)"', create_response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', create_response.text)

    assert match
    group_id = match.group(1)

    # Get fresh CSRF token
    csrf_token = get_csrf_token(fastapi_test_client)

    # Update with all disabled (Form defaults to False)
    response = fastapi_test_client.put(
        f"/api/groups/{group_id}/settings",
        headers={"X-CSRF-Token": csrf_token},
        data={"time_window": 24},
    )

    # Should succeed
    assert response.status_code == 200


def test_update_settings_invalid_time_window(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
    tmp_path: Path,
) -> None:
    """Test updating settings with invalid time_window value."""
    import os
    os.environ["CHATFILTER_DATA_DIR"] = str(tmp_path / "data")

    # Create a group
    csrf_token = get_csrf_token(fastapi_test_client)

    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Group Invalid Time",
        "source_type": "file_upload",
    }

    create_response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert create_response.status_code == 200

    # Extract group ID
    import re
    match = re.search(r'id="group-([^"]+)"', create_response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', create_response.text)

    assert match
    group_id = match.group(1)

    # Get fresh CSRF token
    csrf_token = get_csrf_token(fastapi_test_client)

    # Try invalid time_window (exceeds MAX_TIME_WINDOW=168)
    response = fastapi_test_client.put(
        f"/api/groups/{group_id}/settings",
        headers={"X-CSRF-Token": csrf_token},
        data={"time_window": 8760},  # 1 year - way over limit!
    )

    # Should return error (200 with error partial or 400)
    assert response.status_code in (200, 400)
    if response.status_code == 200:
        assert "error" in response.text.lower() or "exceeds maximum" in response.text.lower()


def test_export_group_results_returns_csv(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that export endpoint returns CSV with correct Content-Disposition header."""
    # Create group
    csrf_token = get_csrf_token(fastapi_test_client)
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Export Test Group",
        "source_type": "file_upload",
    }
    
    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert response.status_code == 200
    
    # Extract group_id from response
    import re
    match = re.search(r'id="group-([^"]+)"', response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', response.text)
    if not match:
        match = re.search(r'/api/groups/([^/"]+)/export', response.text)
    assert match, f"Could not find group_id in response. Response text: {response.text[:500]}"
    group_id = match.group(1)
    
    # Export results (empty results is OK - we test the endpoint)
    export_response = fastapi_test_client.get(f"/api/groups/{group_id}/export")
    
    # Should return 200 with CSV content-type
    assert export_response.status_code == 200
    assert export_response.headers["content-type"] == "text/csv; charset=utf-8"
    
    # Check Content-Disposition header has filename
    content_disposition = export_response.headers.get("content-disposition", "")
    assert "attachment" in content_disposition
    assert "filename=" in content_disposition
    assert ".csv" in content_disposition
    
    # Verify filename format: {group_name}.csv (sanitized)
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
    assert filename_match, "Filename not found in Content-Disposition"
    filename = filename_match.group(1)
    # Group name "Export Test Group" → "Export_Test_Group.csv"
    assert filename == "Export_Test_Group.csv"
    
    # Check CSV content is valid (has headers)
    csv_text = export_response.text
    # Remove BOM if present
    if csv_text.startswith('\ufeff'):
        csv_text = csv_text[1:]
    
    lines = csv_text.strip().split('\n')
    assert len(lines) >= 1, "CSV should have at least header row"
    
    # Check header row contains expected columns
    header = lines[0]
    assert "chat_ref" in header
    assert "title" in header
    assert "status" in header


def test_export_nonexistent_group_returns_404(
    fastapi_test_client: TestClient,
) -> None:
    """Test that exporting non-existent group returns 404."""
    response = fastapi_test_client.get("/api/groups/nonexistent-id/export")
    assert response.status_code == 404


def test_export_reads_from_group_chats_columns(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that export reads metrics from group_chats columns via service.get_results().

    New data model: metrics are stored directly in group_chats columns,
    not in a separate group_results table. Export goes through service.get_results().
    """
    import re

    # Create group
    csrf_token = get_csrf_token(fastapi_test_client)
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "Test Export Group",
        "source_type": "file_upload",
    }

    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert response.status_code == 200

    # Extract group_id
    match = re.search(r'id="group-([^"]+)"', response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', response.text)
    if not match:
        match = re.search(r'/api/groups/([^/"]+)/export', response.text)
    assert match, f"Could not find group_id in response"
    group_id = match.group(1)

    # Simulate analysis: mark chat as done with metrics in group_chats columns
    from chatfilter.web.routers.groups import _get_group_service

    service = _get_group_service()
    chats = service._db.load_chats(group_id)
    assert len(chats) >= 1, "Group should have at least one chat"

    # Mark first chat as done with a chat_type
    service._db.save_chat(
        group_id=group_id,
        chat_ref=chats[0]["chat_ref"],
        chat_type="group",
        status="done",
        chat_id=chats[0]["id"],
    )

    # Verify service.get_results() returns data from group_chats
    results = service.get_results(group_id)
    assert len(results) >= 1, "service.get_results() should return chats"
    assert results[0]["chat_ref"] == chats[0]["chat_ref"]
    assert results[0]["status"] == "done"

    # Export should return CSV with data rows from group_chats
    export_response = fastapi_test_client.get(f"/api/groups/{group_id}/export")
    assert export_response.status_code == 200
    assert export_response.headers["content-type"] == "text/csv; charset=utf-8"

    csv_text = export_response.text
    if csv_text.startswith('\ufeff'):
        csv_text = csv_text[1:]

    lines = csv_text.strip().split('\n')
    assert len(lines) >= 2, (
        f"CSV should have header + at least 1 data row, got {len(lines)} lines: {lines}"
    )


def test_export_sanitizes_path_traversal_attack(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that path traversal attempts in group name are sanitized."""
    import re

    # Create group with path traversal in name
    csrf_token = get_csrf_token(fastapi_test_client)
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "../../../etc/passwd",
        "source_type": "file_upload",
    }

    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert response.status_code == 200

    # Extract group_id
    match = re.search(r'id="group-([^"]+)"', response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', response.text)
    if not match:
        match = re.search(r'/api/groups/([^/"]+)/export', response.text)
    assert match, "Could not find group_id in response"
    group_id = match.group(1)

    # Export and check filename is sanitized
    export_response = fastapi_test_client.get(f"/api/groups/{group_id}/export")
    assert export_response.status_code == 200

    content_disposition = export_response.headers.get("content-disposition", "")
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
    assert filename_match, "Filename not found in Content-Disposition"
    filename = filename_match.group(1)

    # Path traversal should be sanitized to just "etcpasswd.csv"
    # (../ and / removed, leaving "etcpasswd")
    assert filename == "etcpasswd.csv"
    assert ".." not in filename
    assert "/" not in filename
    assert "\\" not in filename


def test_export_sanitizes_http_response_splitting(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that newline injection in group name is sanitized."""
    import re

    # Create group with newline injection attempt
    csrf_token = get_csrf_token(fastapi_test_client)
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "test\\nLocation: evil.com",
        "source_type": "file_upload",
    }

    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert response.status_code == 200

    # Extract group_id
    match = re.search(r'id="group-([^"]+)"', response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', response.text)
    if not match:
        match = re.search(r'/api/groups/([^/"]+)/export', response.text)
    assert match, "Could not find group_id in response"
    group_id = match.group(1)

    # Export and check filename has no control chars
    export_response = fastapi_test_client.get(f"/api/groups/{group_id}/export")
    assert export_response.status_code == 200

    content_disposition = export_response.headers.get("content-disposition", "")
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
    assert filename_match, "Filename not found in Content-Disposition"
    filename = filename_match.group(1)

    # Control chars (including literal \n) should be removed
    assert "\\n" not in filename
    assert "\n" not in filename
    assert "\r" not in filename
    # Should be sanitized to "testLocation_evilcom.csv"
    assert filename == "testnLocation_evilcom.csv"


def test_export_empty_name_fallback(
    fastapi_test_client: TestClient,
    sample_csv_content: bytes,
) -> None:
    """Test that export falls back to sanitized_export_{timestamp}.csv when name is empty after sanitization."""
    import re

    # Create group with only special chars that will all be stripped
    csrf_token = get_csrf_token(fastapi_test_client)
    files = {
        "file_upload": ("test_chats.csv", io.BytesIO(sample_csv_content), "text/csv")
    }
    data = {
        "name": "../../../",
        "source_type": "file_upload",
    }

    response = fastapi_test_client.post(
        "/api/groups",
        headers={"X-CSRF-Token": csrf_token},
        files=files,
        data=data,
    )
    assert response.status_code == 200

    # Extract group_id
    match = re.search(r'id="group-([^"]+)"', response.text)
    if not match:
        match = re.search(r'data-group-id="([^"]+)"', response.text)
    if not match:
        match = re.search(r'/api/groups/([^/"]+)/export', response.text)
    assert match, "Could not find group_id in response"
    group_id = match.group(1)

    # Export and check filename falls back to timestamped name
    export_response = fastapi_test_client.get(f"/api/groups/{group_id}/export")
    assert export_response.status_code == 200

    content_disposition = export_response.headers.get("content-disposition", "")
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
    assert filename_match, "Filename not found in Content-Disposition"
    filename = filename_match.group(1)

    # Should match pattern: sanitized_export_YYYYMMDD_HHMMSS.csv
    assert filename.startswith("sanitized_export_")
    assert filename.endswith(".csv")
    assert len(filename) > len("sanitized_export_20260216_000000.csv") - 5  # Allow some variance


# ==========================================================================
# Router-Service delegation tests (new model verification)
# ==========================================================================


def test_router_delegates_start_to_service() -> None:
    """Verify start_analysis router delegates to service.start_analysis().

    done_when criteria: no direct DB status writes from router.
    The router should NOT call service.update_status() — the service/engine
    handles status transitions internally.
    """
    import ast
    import inspect

    from chatfilter.web.routers.groups import start_group_analysis

    source = inspect.getsource(start_group_analysis)
    tree = ast.parse(source)

    # Collect all attribute access chains in the function
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # Get the full call chain (e.g. "service.start_analysis")
            parts = []
            obj = node.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            parts.reverse()
            calls.append(".".join(parts))

    # Verify: router calls service.start_analysis
    assert any("start_analysis" in c for c in calls), (
        f"start_group_analysis should call service.start_analysis(). Found calls: {calls}"
    )

    # Verify: router does NOT directly call service.update_status
    status_update_calls = [c for c in calls if "update_status" in c]
    assert not status_update_calls, (
        f"Router should NOT call service.update_status() — "
        f"service/engine handles status internally. Found: {status_update_calls}"
    )

    # Verify: router does NOT directly create asyncio.Task for engine
    assert "create_task" not in source, (
        "Router should NOT call asyncio.create_task() for engine — "
        "service.start_analysis() handles task creation internally"
    )


def test_router_delegates_stop_to_service() -> None:
    """Verify stop_analysis router delegates to service.stop_analysis().

    The router should NOT call engine.stop_analysis() directly or
    update GroupStatus.PAUSED manually.
    """
    import inspect

    from chatfilter.web.routers.groups import stop_group_analysis

    source = inspect.getsource(stop_group_analysis)

    # Verify: calls service.stop_analysis
    assert "service.stop_analysis" in source, (
        "stop_group_analysis should call service.stop_analysis()"
    )

    # Verify: does NOT call engine.stop_analysis directly
    assert "engine.stop_analysis" not in source, (
        "Router should NOT call engine.stop_analysis() directly — use service"
    )

    # Verify: does NOT write GroupStatus.PAUSED
    assert "GroupStatus.PAUSED" not in source, (
        "Router should NOT set GroupStatus.PAUSED — service handles it"
    )


def test_router_delegates_reanalyze_to_service() -> None:
    """Verify reanalyze router delegates to service.reanalyze().

    The router should NOT call engine.start_analysis() directly or
    manage status rollbacks.
    """
    import inspect

    from chatfilter.web.routers.groups import reanalyze_group

    source = inspect.getsource(reanalyze_group)

    # Verify: calls service.reanalyze
    assert "service.reanalyze" in source, (
        "reanalyze_group should call service.reanalyze()"
    )

    # Verify: does NOT call engine.start_analysis directly
    assert "engine.start_analysis" not in source, (
        "Router should NOT call engine.start_analysis() directly — use service.reanalyze()"
    )

    # Verify: does NOT create asyncio.Task for engine
    assert "create_task" not in source, (
        "Router should NOT call asyncio.create_task() — service handles it"
    )


def test_router_export_uses_service_get_results() -> None:
    """Verify export endpoints use service.get_results() instead of _db.load_results().

    New data model: metrics are in group_chats columns, accessed via service.get_results().
    """
    import inspect

    from chatfilter.web.routers.groups import (
        export_group_results,
        get_export_modal,
        preview_export_count,
    )

    for fn in [export_group_results, preview_export_count, get_export_modal]:
        source = inspect.getsource(fn)
        fn_name = fn.__name__

        # Verify: uses service.get_results()
        assert "service.get_results" in source or "get_results" in source, (
            f"{fn_name} should use service.get_results() for new data model"
        )

        # Verify: does NOT use _db.load_results (old pattern)
        assert "_db.load_results" not in source, (
            f"{fn_name} should NOT use _db.load_results() — "
            f"use service.get_results() for new model"
        )


def test_router_sse_uses_progress_tracker() -> None:
    """Verify SSE endpoint uses ProgressTracker.subscribe() instead of engine.subscribe()."""
    import inspect

    from chatfilter.web.routers.groups import _generate_group_sse_events

    source = inspect.getsource(_generate_group_sse_events)

    # Verify: uses tracker.subscribe
    assert "tracker.subscribe" in source or "_get_progress_tracker" in source, (
        "SSE should use ProgressTracker.subscribe(), not engine.subscribe()"
    )

    # Verify: does NOT use engine.subscribe
    assert "engine.subscribe" not in source, (
        "SSE should NOT use engine.subscribe() — use ProgressTracker"
    )
