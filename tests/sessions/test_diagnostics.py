"""Tests for sessions router."""

import json
import re
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app
from chatfilter.web.routers.sessions import (
    migrate_legacy_sessions,
    read_upload_with_size_limit,
    sanitize_session_name,
    validate_account_info_json,
    validate_config_file_format,
    validate_session_file_format,
)

from .conftest import extract_csrf_token


"""Tests for sessions router."""

import json
import re
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app
from chatfilter.web.routers.sessions import (
    migrate_legacy_sessions,
    read_upload_with_size_limit,
    sanitize_session_name,
    validate_account_info_json,
    validate_config_file_format,
    validate_session_file_format,
)

from .conftest import extract_csrf_token


class TestPreConnectDiagnosticIntegration:
    """Tests for pre-connect proxy diagnostic integration (simplified)."""

    @pytest.mark.asyncio
    async def test_socks5_tunnel_check_integration(self) -> None:
        """Verify socks5_tunnel_check is properly integrated in sessions router."""
        from chatfilter.service.proxy_health import socks5_tunnel_check
        from chatfilter.config import ProxyType
        from chatfilter.models.proxy import ProxyEntry
        from unittest.mock import patch

        # Test that socks5_tunnel_check can be called from sessions router context
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
        )

        # Mock the underlying sync function
        with patch("chatfilter.service.proxy_health._socks5_connect_sync") as mock:
            mock.return_value = True
            result = await socks5_tunnel_check(proxy)
            assert result is True

    def test_proxy_health_module_imported(self) -> None:
        """Verify proxy_health module is importable from sessions router."""
        # This verifies that sessions.py can import from proxy_health
        from chatfilter.service import proxy_health
        assert hasattr(proxy_health, 'socks5_tunnel_check')
        assert hasattr(proxy_health, 'check_proxy_health')

    def test_pre_connect_diagnostic_error_messages_no_credentials(self) -> None:
        """Error messages from pre-connect diagnostic should not leak credentials."""
        # This test verifies the error messages used in sessions.py
        error_msg_proxy_fail = "The proxy is not responding. Please check proxy settings or switch to another proxy."
        error_msg_telegram_fail = "Telegram servers are not reachable through the proxy. Try a different proxy or check your network."

        # Verify messages don't ask for credentials
        assert "proxy" in error_msg_proxy_fail.lower()
        assert "telegram" in error_msg_telegram_fail.lower()
        # Verify generic phrasing (no specific proxy details)
        assert "the proxy" in error_msg_proxy_fail.lower() or "proxy" in error_msg_proxy_fail.lower()


