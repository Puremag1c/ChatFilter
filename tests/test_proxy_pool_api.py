"""Tests for proxy pool REST API endpoints."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.config import ProxyType
from chatfilter.models.proxy import ProxyEntry
from chatfilter.web.app import create_app


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag.

    Args:
        html: HTML content containing meta tag with csrf-token

    Returns:
        CSRF token string or None if not found
    """
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


class TestListProxies:
    """Tests for GET /api/proxies endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app()
        return TestClient(app)

    def test_list_proxies_empty(self, client: TestClient):
        """Test listing proxies when pool is empty."""
        with patch("chatfilter.web.routers.proxy_pool.load_proxy_pool", return_value=[]):
            response = client.get("/api/proxies")

        assert response.status_code == 200
        data = response.json()
        assert data["proxies"] == []
        assert data["count"] == 0

    def test_list_proxies_returns_all(self, client: TestClient):
        """Test listing proxies returns all proxies."""
        mock_proxy_pool = [
            ProxyEntry(
                id="11111111-1111-1111-1111-111111111111",
                name="Test Proxy 1",
                type=ProxyType.SOCKS5,
                host="proxy1.example.com",
                port=1080,
            ),
            ProxyEntry(
                id="22222222-2222-2222-2222-222222222222",
                name="Test Proxy 2",
                type=ProxyType.HTTP,
                host="proxy2.example.com",
                port=8080,
                username="user",
                password="pass",
            ),
        ]

        with patch(
            "chatfilter.web.routers.proxy_pool.load_proxy_pool", return_value=mock_proxy_pool
        ):
            response = client.get("/api/proxies")

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 2
        assert len(data["proxies"]) == 2

        # Verify first proxy
        proxy1 = data["proxies"][0]
        assert proxy1["id"] == "11111111-1111-1111-1111-111111111111"
        assert proxy1["name"] == "Test Proxy 1"
        assert proxy1["type"] == "socks5"
        assert proxy1["host"] == "proxy1.example.com"
        assert proxy1["port"] == 1080
        assert proxy1["has_auth"] is False

        # Verify second proxy with auth
        proxy2 = data["proxies"][1]
        assert proxy2["id"] == "22222222-2222-2222-2222-222222222222"
        assert proxy2["name"] == "Test Proxy 2"
        assert proxy2["type"] == "http"
        assert proxy2["has_auth"] is True
        assert proxy2["username"] == "user"
        # Password should not be returned in response
        assert "password" not in proxy2


class TestCreateProxy:
    """Tests for POST /api/proxies endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app()
        return TestClient(app)

    @pytest.fixture
    def csrf_token(self, client: TestClient) -> str:
        """Get CSRF token from home page."""
        response = client.get("/")
        token = extract_csrf_token(response.text)
        assert token is not None, "CSRF token not found"
        return token

    def test_create_proxy_success(self, client: TestClient, csrf_token: str):
        """Test creating a new proxy."""
        created_proxy = ProxyEntry(
            name="New Proxy",
            type=ProxyType.SOCKS5,
            host="newproxy.example.com",
            port=1080,
        )

        with patch("chatfilter.web.routers.proxy_pool.add_proxy", return_value=created_proxy):
            response = client.post(
                "/api/proxies",
                json={
                    "name": "New Proxy",
                    "type": "socks5",
                    "host": "newproxy.example.com",
                    "port": 1080,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["proxy"]["name"] == "New Proxy"
        assert data["proxy"]["type"] == "socks5"

    def test_create_proxy_with_auth(self, client: TestClient, csrf_token: str):
        """Test creating a proxy with authentication."""
        created_proxy = ProxyEntry(
            name="Auth Proxy",
            type=ProxyType.HTTP,
            host="authproxy.example.com",
            port=8080,
            username="user",
            password="pass",
        )

        with patch("chatfilter.web.routers.proxy_pool.add_proxy", return_value=created_proxy):
            response = client.post(
                "/api/proxies",
                json={
                    "name": "Auth Proxy",
                    "type": "http",
                    "host": "authproxy.example.com",
                    "port": 8080,
                    "username": "user",
                    "password": "pass",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["proxy"]["has_auth"] is True

    def test_create_proxy_invalid_type(self, client: TestClient, csrf_token: str):
        """Test creating a proxy with invalid type returns error."""
        response = client.post(
            "/api/proxies",
            json={
                "name": "Bad Proxy",
                "type": "invalid",
                "host": "proxy.example.com",
                "port": 1080,
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Invalid proxy type" in data["error"]

    def test_create_proxy_invalid_port(self, client: TestClient, csrf_token: str):
        """Test creating a proxy with invalid port returns 422."""
        response = client.post(
            "/api/proxies",
            json={
                "name": "Bad Proxy",
                "type": "socks5",
                "host": "proxy.example.com",
                "port": 99999,  # Invalid port
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 422  # Validation error


class TestUpdateProxy:
    """Tests for PUT /api/proxies/{proxy_id} endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app()
        return TestClient(app)

    @pytest.fixture
    def csrf_token(self, client: TestClient) -> str:
        """Get CSRF token from home page."""
        response = client.get("/")
        token = extract_csrf_token(response.text)
        assert token is not None, "CSRF token not found"
        return token

    def test_update_proxy_success(self, client: TestClient, csrf_token: str):
        """Test updating an existing proxy."""
        proxy_id = "11111111-1111-1111-1111-111111111111"
        existing_proxy = ProxyEntry(
            id=proxy_id,
            name="Old Name",
            type=ProxyType.SOCKS5,
            host="old.example.com",
            port=1080,
            password="old_pass",
        )
        updated_proxy = ProxyEntry(
            id=proxy_id,
            name="New Name",
            type=ProxyType.HTTP,
            host="new.example.com",
            port=8080,
            password="old_pass",  # Password preserved when not provided
        )

        with (
            patch(
                "chatfilter.web.routers.proxy_pool.get_proxy_by_id",
                return_value=existing_proxy,
            ),
            patch(
                "chatfilter.web.routers.proxy_pool.update_proxy",
                return_value=updated_proxy,
            ) as mock_update,
        ):
            response = client.put(
                f"/api/proxies/{proxy_id}",
                json={
                    "name": "New Name",
                    "type": "http",
                    "host": "new.example.com",
                    "port": 8080,
                    "username": "",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["proxy"]["name"] == "New Name"
        assert data["proxy"]["type"] == "http"
        assert data["proxy"]["host"] == "new.example.com"
        assert data["proxy"]["port"] == 8080
        mock_update.assert_called_once()

    def test_update_proxy_with_new_password(self, client: TestClient, csrf_token: str):
        """Test updating a proxy with new password."""
        proxy_id = "11111111-1111-1111-1111-111111111111"
        existing_proxy = ProxyEntry(
            id=proxy_id,
            name="Test Proxy",
            type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
            password="old_pass",
        )
        updated_proxy = ProxyEntry(
            id=proxy_id,
            name="Test Proxy",
            type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
            password="new_pass",
        )

        with (
            patch(
                "chatfilter.web.routers.proxy_pool.get_proxy_by_id",
                return_value=existing_proxy,
            ),
            patch(
                "chatfilter.web.routers.proxy_pool.update_proxy",
                return_value=updated_proxy,
            ) as mock_update,
        ):
            response = client.put(
                f"/api/proxies/{proxy_id}",
                json={
                    "name": "Test Proxy",
                    "type": "socks5",
                    "host": "proxy.example.com",
                    "port": 1080,
                    "password": "new_pass",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        # Verify the password was passed to update
        call_args = mock_update.call_args
        updated_entry = call_args[0][1]
        assert updated_entry.password == "new_pass"

    def test_update_proxy_not_found(self, client: TestClient, csrf_token: str):
        """Test updating a non-existent proxy returns 404."""
        from chatfilter.storage.errors import StorageNotFoundError

        proxy_id = "nonexistent-id-1234-5678-abcdefabcdef"

        with patch(
            "chatfilter.web.routers.proxy_pool.get_proxy_by_id",
            side_effect=StorageNotFoundError(f"Proxy not found: {proxy_id}"),
        ):
            response = client.put(
                f"/api/proxies/{proxy_id}",
                json={
                    "name": "New Name",
                    "type": "socks5",
                    "host": "proxy.example.com",
                    "port": 1080,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 404

    def test_update_proxy_invalid_type(self, client: TestClient, csrf_token: str):
        """Test updating a proxy with invalid type returns error."""
        proxy_id = "11111111-1111-1111-1111-111111111111"

        response = client.put(
            f"/api/proxies/{proxy_id}",
            json={
                "name": "Test Proxy",
                "type": "invalid",
                "host": "proxy.example.com",
                "port": 1080,
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "Invalid proxy type" in data["error"]


class TestDeleteProxy:
    """Tests for DELETE /api/proxies/{proxy_id} endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app()
        return TestClient(app)

    @pytest.fixture
    def csrf_token(self, client: TestClient) -> str:
        """Get CSRF token from home page."""
        response = client.get("/")
        token = extract_csrf_token(response.text)
        assert token is not None, "CSRF token not found"
        return token

    def test_delete_proxy_success(self, client: TestClient, csrf_token: str):
        """Test deleting a proxy that is not in use."""
        proxy_id = "11111111-1111-1111-1111-111111111111"

        with (
            patch(
                "chatfilter.web.routers.proxy_pool._get_sessions_using_proxy",
                return_value=[],
            ),
            patch("chatfilter.web.routers.proxy_pool.remove_proxy") as mock_remove,
        ):
            response = client.delete(
                f"/api/proxies/{proxy_id}",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        mock_remove.assert_called_once_with(proxy_id)

    def test_delete_proxy_in_use(self, client: TestClient, csrf_token: str):
        """Test deleting a proxy that is in use succeeds (with warning)."""
        proxy_id = "11111111-1111-1111-1111-111111111111"

        with (
            patch(
                "chatfilter.web.routers.proxy_pool._get_sessions_using_proxy",
                return_value=["session1", "session2"],
            ),
            patch("chatfilter.web.routers.proxy_pool.remove_proxy") as mock_remove,
        ):
            response = client.delete(
                f"/api/proxies/{proxy_id}",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        mock_remove.assert_called_once_with(proxy_id)

    def test_delete_proxy_not_found(self, client: TestClient, csrf_token: str):
        """Test deleting a non-existent proxy returns 404."""
        from chatfilter.storage.errors import StorageNotFoundError

        proxy_id = "nonexistent-id-1234-5678-abcdefabcdef"

        with (
            patch(
                "chatfilter.web.routers.proxy_pool._get_sessions_using_proxy",
                return_value=[],
            ),
            patch(
                "chatfilter.web.routers.proxy_pool.remove_proxy",
                side_effect=StorageNotFoundError(f"Proxy not found: {proxy_id}"),
            ),
        ):
            response = client.delete(
                f"/api/proxies/{proxy_id}",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 404


class TestGetSessionsUsingProxy:
    """Tests for _get_sessions_using_proxy helper function."""

    def test_get_sessions_using_proxy_finds_match(self):
        """Test finding sessions that use a specific proxy."""
        from chatfilter.web.routers.proxy_pool import _get_sessions_using_proxy

        with tempfile.TemporaryDirectory() as tmpdir:
            sessions_dir = Path(tmpdir) / "sessions"
            sessions_dir.mkdir()

            # Create a session that uses the proxy
            session1_dir = sessions_dir / "session1"
            session1_dir.mkdir()
            config1 = {"api_id": 123, "api_hash": "abc", "proxy_id": "target-proxy-id"}
            (session1_dir / "config.json").write_text(json.dumps(config1))

            # Create a session that uses a different proxy
            session2_dir = sessions_dir / "session2"
            session2_dir.mkdir()
            config2 = {"api_id": 123, "api_hash": "abc", "proxy_id": "other-proxy-id"}
            (session2_dir / "config.json").write_text(json.dumps(config2))

            # Create a session with no proxy
            session3_dir = sessions_dir / "session3"
            session3_dir.mkdir()
            config3 = {"api_id": 123, "api_hash": "abc", "proxy_id": None}
            (session3_dir / "config.json").write_text(json.dumps(config3))

            with patch("chatfilter.web.routers.proxy_pool.get_settings") as mock_settings:
                mock_settings.return_value.sessions_dir = sessions_dir

                result = _get_sessions_using_proxy("target-proxy-id")

            assert result == ["session1"]

    def test_get_sessions_using_proxy_no_match(self):
        """Test when no sessions use the proxy."""
        from chatfilter.web.routers.proxy_pool import _get_sessions_using_proxy

        with tempfile.TemporaryDirectory() as tmpdir:
            sessions_dir = Path(tmpdir) / "sessions"
            sessions_dir.mkdir()

            # Create a session that uses a different proxy
            session_dir = sessions_dir / "session1"
            session_dir.mkdir()
            config = {"api_id": 123, "api_hash": "abc", "proxy_id": "other-proxy-id"}
            (session_dir / "config.json").write_text(json.dumps(config))

            with patch("chatfilter.web.routers.proxy_pool.get_settings") as mock_settings:
                mock_settings.return_value.sessions_dir = sessions_dir

                result = _get_sessions_using_proxy("target-proxy-id")

            assert result == []
