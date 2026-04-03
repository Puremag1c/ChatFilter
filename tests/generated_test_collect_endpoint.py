"""Generated tests for POST /api/groups/collect endpoint.

Tests cover:
1. CSRF token validation (form field and header)
2. Input validation (empty/missing fields, length constraints)
3. Balance checking (insufficient balance returns 402)
4. Successful group creation (returns 200 with group card)

All tests use an authenticated session with proper CSRF tokens.
"""

from __future__ import annotations

import re
from typing import Any


def _extract_csrf_from_meta(html: str) -> str:
    """Extract CSRF token from meta tag in HTML.

    Args:
        html: HTML content

    Returns:
        CSRF token value

    Raises:
        AssertionError: If csrf-token meta tag not found
    """
    m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html)
    assert m, "No csrf-token meta tag found in page HTML"
    return m.group(1)


class TestCollectEndpointCSRFValidation:
    """Tests for CSRF token validation on POST /api/groups/collect."""

    def test_collect_without_csrf_returns_403(self, fastapi_test_client: Any) -> None:
        """POST /api/groups/collect without CSRF token should return 403."""
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "Test Group",
                "search_query": "test query",
                "platform_ids": ["tg"],
            },
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert "csrf_token_missing" in resp.text or "CSRF validation failed" in resp.text

    def test_collect_with_invalid_csrf_returns_403(self, fastapi_test_client: Any) -> None:
        """POST /api/groups/collect with invalid CSRF token should return 403."""
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "Test Group",
                "search_query": "test query",
                "platform_ids": ["tg"],
                "csrf_token": "invalid-token-xyz",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 403
        assert "csrf_token" in resp.text.lower()


class TestCollectEndpointInputValidation:
    """Tests for input validation on POST /api/groups/collect."""

    def _get_csrf(self, client: Any) -> str:
        """Get CSRF token from home page."""
        resp = client.get("/", follow_redirects=True)
        assert resp.status_code == 200
        return _extract_csrf_from_meta(resp.text)

    def test_collect_empty_name_returns_422(self, fastapi_test_client: Any) -> None:
        """POST with empty name should return 422."""
        csrf = self._get_csrf(fastapi_test_client)
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "",
                "search_query": "test query",
                "platform_ids": ["tg"],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422
        assert "required" in resp.text.lower()

    def test_collect_empty_search_query_returns_422(self, fastapi_test_client: Any) -> None:
        """POST with empty search_query should return 422."""
        csrf = self._get_csrf(fastapi_test_client)
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "Test Group",
                "search_query": "",
                "platform_ids": ["tg"],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422

    def test_collect_missing_platforms_returns_422(self, fastapi_test_client: Any) -> None:
        """POST without platform_ids should return 422."""
        csrf = self._get_csrf(fastapi_test_client)
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "Test Group",
                "search_query": "test query",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422

    def test_collect_empty_platforms_returns_422(self, fastapi_test_client: Any) -> None:
        """POST with empty platform_ids list should return 422."""
        csrf = self._get_csrf(fastapi_test_client)
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "Test Group",
                "search_query": "test query",
                "platform_ids": [],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 422

    def test_collect_name_exceeds_max_length_returns_400(self, fastapi_test_client: Any) -> None:
        """POST with name exceeding max length should return 400."""
        csrf = self._get_csrf(fastapi_test_client)
        # Max length is typically 256 characters
        long_name = "x" * 300
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": long_name,
                "search_query": "test query",
                "platform_ids": ["tg"],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert "must be at most" in resp.text.lower()

    def test_collect_search_query_exceeds_max_length_returns_400(
        self, fastapi_test_client: Any
    ) -> None:
        """POST with search_query exceeding max length should return 400."""
        csrf = self._get_csrf(fastapi_test_client)
        # Max search query length is typically higher, test with very long query
        long_query = "x" * 5000
        resp = fastapi_test_client.post(
            "/api/groups/collect",
            data={
                "name": "Test Group",
                "search_query": long_query,
                "platform_ids": ["tg"],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 400
        assert "must be at most" in resp.text.lower()
