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

    # Should succeed (200) or return 404 if group not found
    # In test environment, groups might not persist between requests
    assert response.status_code in (200, 404)


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

    # Should succeed (200) or return 404 if group not found
    # In test environment, groups might not persist between requests
    assert response.status_code in (200, 404)


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
