"""Security tests for XSS protection in proxy pool HTML rendering.

Tests verify that user-controlled fields (proxy name, host, username) are properly
HTML-escaped when rendered in HTML responses to prevent XSS attacks.
"""

from __future__ import annotations

import re
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.config import ProxyConfig, ProxyType
from chatfilter.web.app import create_app


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag."""
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


@pytest.fixture
def client() -> TestClient:
    """Create test client."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def csrf_token(client: TestClient) -> str:
    """Get CSRF token from home page."""
    response = client.get("/")
    token = extract_csrf_token(response.text)
    assert token is not None, "CSRF token not found"
    return token


def test_proxy_retest_escapes_malicious_name(
    client: TestClient,
    csrf_token: str,
) -> None:
    """Test that proxy name with XSS payload is HTML-escaped in retest response.

    SECURITY: Verifies SPEC.md Must Have #3 - HTML escaping of user input.
    If proxy name contains '<script>alert(1)</script>', it should be rendered
    as '&lt;script&gt;alert(1)&lt;/script&gt;' in HTML, preventing XSS execution.
    """
    from chatfilter.models.proxy import ProxyEntry, ProxyStatus

    # Create proxy with XSS payload in name
    xss_payload = "<script>alert('XSS')</script>"
    proxy_id = str(uuid.uuid4())
    malicious_proxy = ProxyEntry(
        id=proxy_id,
        name=xss_payload,  # User-controlled field
        type=ProxyType.SOCKS5,
        host="127.0.0.1",
        port=1080,
        status=ProxyStatus.UNTESTED,
    )

    # Mock health check to return working proxy with XSS name
    updated_proxy = ProxyEntry(
        id=malicious_proxy.id,
        name=malicious_proxy.name,  # XSS payload preserved
        type=malicious_proxy.type,
        host=malicious_proxy.host,
        port=malicious_proxy.port,
        status=ProxyStatus.WORKING,
    )

    # Mock retest_proxy function from service layer
    async def mock_retest(pid: str):
        return updated_proxy if pid == proxy_id else None

    with patch("chatfilter.service.proxy_health.retest_proxy", side_effect=mock_retest):
        with patch("chatfilter.web.routers.proxy_pool._get_sessions_using_proxy", return_value=[]):
            # Call retest endpoint (returns HTML <tr>)
            response = client.post(
                f"/api/proxies/{proxy_id}/retest",
                headers={"X-CSRF-Token": csrf_token},
            )

    assert response.status_code == 200
    html = response.text

    # Verify XSS payload is escaped, not executed
    assert "<script>" not in html, "Raw <script> tag found - XSS vulnerability!"
    assert "&lt;script&gt;" in html, "Expected HTML-escaped <script> tag"

    # Verify proxy name content is present (but escaped)
    assert "XSS" in html, "Proxy name content missing from response"


def test_proxy_list_escapes_malicious_fields(
    client: TestClient,
) -> None:
    """Test that all user-controlled fields are HTML-escaped in proxy list.

    Verifies escaping for:
    - proxy.name
    - proxy.host
    - proxy.username
    """
    from chatfilter.models.proxy import ProxyEntry, ProxyStatus

    # Create proxy with XSS payloads in multiple fields
    malicious_proxy = ProxyEntry(
        id=str(uuid.uuid4()),
        name="<img src=x onerror=alert(1)>",  # User input
        type=ProxyType.HTTP,
        host="<script>alert(2)</script>",  # User input
        port=8080,
        username="<svg/onload=alert(3)>",  # User input
        status=ProxyStatus.UNTESTED,
    )

    # Mock load_proxy_pool to return malicious proxy
    with patch("chatfilter.web.routers.proxy_pool.load_proxy_pool", return_value=[malicious_proxy]):
        with patch("chatfilter.web.routers.proxy_pool._get_sessions_using_proxy", return_value=[]):
            # Call list endpoint
            response = client.get("/api/proxies/list")

    assert response.status_code == 200
    html = response.text

    # Verify ALL XSS payloads are escaped
    assert "<img src=x" not in html, "Image XSS vulnerability in name field"
    assert "<script>" not in html, "Script XSS vulnerability in host field"
    assert "<svg/onload=" not in html, "SVG XSS vulnerability in username field"

    # Verify content is present (but escaped)
    assert "alert(1)" in html  # Name payload content (escaped)
    assert "alert(2)" in html  # Host payload content (escaped)
    assert "alert(3)" in html  # Username payload content (escaped)


def test_proxy_row_macro_uses_auto_escaping() -> None:
    """Verify that proxy_row macro template uses Jinja2 auto-escaping.

    Static analysis test - checks that template doesn't use '| safe' filter
    which would disable auto-escaping.
    """
    from pathlib import Path

    template_path = Path("src/chatfilter/templates/partials/proxy_pool_list.html")
    template_content = template_path.read_text()

    # Verify no unsafe rendering
    assert "| safe" not in template_content, \
        "Template uses '| safe' filter which disables XSS protection"

    # Verify user-controlled fields use standard {{ }} (auto-escaped)
    assert "{{ proxy.name }}" in template_content
    assert "{{ proxy.host }}" in template_content
    assert "{{ proxy.username }}" in template_content


def test_json_responses_use_generic_error_messages(
    client: TestClient,
    csrf_token: str,
) -> None:
    """Test that JSON responses use generic error messages (no exception details).

    SECURITY BEST PRACTICE: Don't expose exception details in error responses
    because exceptions may contain user-controlled data (proxy.name, host, etc.).

    Using generic messages like "Failed to load proxies. Please try again."
    prevents XSS without needing HTML escaping in JSON responses.
    """
    xss_payload = "<script>alert('XSS')</script>"

    # Mock load_proxy_pool to raise exception with XSS payload
    def raise_with_xss():
        raise ValueError(f"Failed to load proxy: {xss_payload}")

    with patch("chatfilter.web.routers.proxy_pool.load_proxy_pool", side_effect=raise_with_xss):
        # Call API endpoint that catches exception and returns JSON error
        response = client.get("/api/proxies")

    assert response.status_code == 500
    error_detail = response.json().get("detail", "")

    # Verify generic error message (no exception details leaked)
    assert xss_payload not in error_detail, "Exception details leaked in error message"
    assert "Please try again" in error_detail, "Expected generic error message"


def test_html_endpoint_exception_escaping(
    client: TestClient,
) -> None:
    """Test that HTML endpoint error responses escape exception text.

    Verifies /api/proxies/list endpoint (returns HTML) properly escapes
    exception messages that may contain user data.
    """
    xss_payload = "<img src=x onerror=alert(1)>"

    # Mock to raise exception with XSS in message
    def raise_with_xss():
        raise RuntimeError(f"Database error: {xss_payload}")

    with patch("chatfilter.web.routers.proxy_pool.load_proxy_pool", side_effect=raise_with_xss):
        response = client.get("/api/proxies/list")

    assert response.status_code == 500
    html = response.text

    # Verify XSS payload is escaped in HTML error message
    assert "<img src=x" not in html, "Raw <img> tag in HTML error - XSS vulnerability!"
    assert "&lt;img" in html or "onerror=" not in html, \
        "Exception message in HTML response not properly escaped"


def test_create_proxy_uses_generic_errors(
    client: TestClient,
    csrf_token: str,
) -> None:
    """Test that create proxy uses generic error messages for exceptions.

    Verifies that when proxy creation fails with exception,
    the response uses generic error message instead of exposing exception details.
    """
    xss_payload = "<svg/onload=alert(1)>"

    # Mock add_proxy to raise exception with XSS
    # Note: ValueError is passed through directly, but Exception is generic
    def raise_with_xss(*args, **kwargs):
        raise RuntimeError(f"Database error: {xss_payload}")

    with patch("chatfilter.web.routers.proxy_pool.add_proxy", side_effect=raise_with_xss):
        response = client.post(
            "/api/proxies",
            json={
                "name": "Test Proxy",
                "type": "http",
                "host": "127.0.0.1",
                "port": 8080,
            },
            headers={"X-CSRF-Token": csrf_token},
        )

    assert response.status_code == 200  # Returns ProxyCreateResponse
    json_data = response.json()
    error_msg = json_data.get("error", "")

    # Verify generic error message (no exception details)
    assert xss_payload not in error_msg, "Exception details leaked in error message"
    assert "Please check your configuration" in error_msg, "Expected generic error message"
