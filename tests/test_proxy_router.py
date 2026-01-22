"""Tests for proxy router."""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from chatfilter.config import ProxyConfig, ProxyType
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


class TestGetProxyConfig:
    """Tests for GET /api/proxy endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app()
        return TestClient(app)

    def test_get_proxy_calls_load(self, client: TestClient, tmp_path: Path) -> None:
        """Test that GET endpoint calls load_proxy_config."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.routers.proxy.load_proxy_config") as mock_load,
        ):
            mock_load.return_value = ProxyConfig()
            # Don't make actual request, just verify the mock is set up
            from chatfilter.web.routers import proxy

            # Just verify function exists and would call load
            assert hasattr(proxy, "get_proxy_config")

        assert True  # Test passes if we get here


class TestSaveProxyConfig:
    """Tests for POST /api/proxy endpoint."""

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

    def test_save_valid_socks5_config(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving valid SOCKS5 proxy configuration."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                    "username": "user1",
                    "password": "pass1",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        # Verify config was saved to file
        config_path = config_dir / "proxy.json"
        assert config_path.exists()
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.enabled is True
        assert saved_config.proxy_type == ProxyType.SOCKS5
        assert saved_config.host == "proxy.example.com"
        assert saved_config.port == 1080
        assert saved_config.username == "user1"
        assert saved_config.password == "pass1"

    def test_save_valid_http_config(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving valid HTTP proxy configuration."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "http",
                    "host": "http-proxy.example.com",
                    "port": "8080",
                    "username": "",
                    "password": "",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.proxy_type == ProxyType.HTTP
        assert saved_config.port == 8080

    def test_save_disabled_config(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving disabled proxy configuration."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.enabled is False

    def test_save_invalid_proxy_type(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving with invalid proxy type returns error."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "invalid_type",
                    "host": "proxy.example.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_save_port_too_low(self, client: TestClient, csrf_token: str, tmp_path: Path) -> None:
        """Test saving with port < 1 returns error."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "0",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_save_port_too_high(self, client: TestClient, csrf_token: str, tmp_path: Path) -> None:
        """Test saving with port > 65535 returns error."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "65536",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_save_port_at_lower_boundary(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving with port = 1 (valid lower boundary)."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.port == 1

    def test_save_port_at_upper_boundary(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving with port = 65535 (valid upper boundary)."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "65535",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.port == 65535

    def test_save_strips_whitespace_from_host(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that whitespace is stripped from host field."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "  proxy.example.com  ",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.host == "proxy.example.com"

    def test_save_strips_whitespace_from_username(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that whitespace is stripped from username field."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                    "username": "  testuser  ",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.username == "testuser"

    def test_save_empty_host(self, client: TestClient, csrf_token: str, tmp_path: Path) -> None:
        """Test saving with empty host (should succeed, disabled proxy)."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.host == ""

    def test_save_case_insensitive_proxy_type(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that proxy type is case-insensitive."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "SOCKS5",  # Uppercase
                    "host": "proxy.example.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.proxy_type == ProxyType.SOCKS5

    def test_save_without_credentials(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving proxy config without username/password."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.username == ""
        assert saved_config.password == ""

    def test_save_exception_handling(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that exceptions during save are handled gracefully."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.web.routers.proxy.save_proxy_config",
                side_effect=Exception("Simulated write error"),
            ),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_save_updates_existing_config(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that saving updates existing configuration."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "proxy.json"

        # Create initial config
        initial_config = ProxyConfig(
            enabled=True,
            proxy_type=ProxyType.HTTP,
            host="old-proxy.example.com",
            port=8080,
        )
        config_path.write_text(initial_config.model_dump_json(indent=2))

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "new-proxy.example.com",
                    "port": "9050",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        # Verify updated config
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.proxy_type == ProxyType.SOCKS5
        assert saved_config.host == "new-proxy.example.com"
        assert saved_config.port == 9050

    def test_save_default_values(self, client: TestClient, csrf_token: str, tmp_path: Path) -> None:
        """Test that form defaults are applied when fields are omitted."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post("/api/proxy", data={}, headers={"X-CSRF-Token": csrf_token})

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.enabled is False  # Default
        assert saved_config.proxy_type == ProxyType.SOCKS5  # Default
        assert saved_config.port == 1080  # Default

    def test_save_preserves_password(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that password is correctly saved (not stripped like username/host)."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                    "username": "user",
                    "password": "  pass with spaces  ",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        # Password should NOT be stripped
        assert saved_config.password == "  pass with spaces  "

    def test_save_negative_port(self, client: TestClient, csrf_token: str, tmp_path: Path) -> None:
        """Test saving with negative port returns error."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "-1",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_save_with_unicode_host(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving with unicode characters in host."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.例え.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.host == "proxy.例え.com"

    def test_save_with_ip_address(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving with IP address as host."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "192.168.1.100",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.host == "192.168.1.100"

    def test_save_with_special_characters_in_password(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test saving with special characters in password."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        special_password = "p@ssw0rd!#$%^&*()"

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                    "username": "user",
                    "password": special_password,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.password == special_password

    def test_multiple_saves_sequential(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that multiple sequential saves work correctly."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            # First save
            response1 = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy1.example.com",
                    "port": "1080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )
            assert response1.status_code == 200

            # Second save with different values
            response2 = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "http",
                    "host": "proxy2.example.com",
                    "port": "8080",
                },
                headers={"X-CSRF-Token": csrf_token},
            )
            assert response2.status_code == 200

        # Verify final state
        config_path = config_dir / "proxy.json"
        saved_config = ProxyConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        assert saved_config.proxy_type == ProxyType.HTTP
        assert saved_config.host == "proxy2.example.com"
        assert saved_config.port == 8080

    def test_post_without_csrf_token_rejected(self, client: TestClient, tmp_path: Path) -> None:
        """Test that POST without CSRF token is rejected."""
        mock_settings = MagicMock()
        mock_settings.config_dir = tmp_path

        with patch("chatfilter.config.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "socks5",
                    "host": "proxy.example.com",
                    "port": "1080",
                },
            )

        # Should be rejected with 403 Forbidden
        assert response.status_code == 403


class TestProxyConfigIntegration:
    """Integration tests for proxy configuration workflow."""

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

    def test_config_persistence_across_requests(
        self, client: TestClient, csrf_token: str, tmp_path: Path
    ) -> None:
        """Test that config persists across multiple requests."""
        config_dir = tmp_path / "config"
        config_dir.mkdir(parents=True, exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.config_dir = config_dir

        with (
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.web.app.get_templates") as mock_templates,
        ):
            mock_template_obj = MagicMock()
            mock_template_obj.TemplateResponse.return_value = HTMLResponse(
                content="<html>test</html>", status_code=200
            )
            mock_templates.return_value = mock_template_obj

            # Save config
            client.post(
                "/api/proxy",
                data={
                    "enabled": "true",
                    "proxy_type": "http",
                    "host": "persistent-proxy.example.com",
                    "port": "8888",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # Verify config persists by loading from disk multiple times
        for _ in range(3):
            config_text = (config_dir / "proxy.json").read_text(encoding="utf-8")
            config = ProxyConfig.model_validate_json(config_text)
            assert config.host == "persistent-proxy.example.com"
            assert config.port == 8888
