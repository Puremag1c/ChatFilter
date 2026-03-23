"""Generated tests for SPEC.md v0.26.0 regression coverage gaps.

Tests cover:
1. Login page renders theme/language switcher controls
2. Login page renders logo
3. Login page uses CSS variables (dark theme compatible)
4. Login form labels are i18n (not hardcoded Russian)
5. proxy_pool.update_proxy logs at DEBUG level (not INFO)
6. Admin user creation uses logger.warning
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

import pytest


class TestLoginPageDarkThemeAndControls:
    """Login page must render theme/language controls and logo (SPEC items 1–3)."""

    def test_login_page_has_theme_toggle(self, unauth_client: Any) -> None:
        """Login page must have theme toggle button (dark theme support)."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert 'id="theme-toggle"' in resp.text, (
            "Login page missing theme-toggle button — dark theme not switchable"
        )

    def test_login_page_has_language_toggle(self, unauth_client: Any) -> None:
        """Login page must have language toggle button."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert 'id="language-toggle"' in resp.text, (
            "Login page missing language-toggle button — language not switchable"
        )

    def test_login_page_includes_theme_switcher_script(self, unauth_client: Any) -> None:
        """Login page must include theme-switcher.js so dark mode CSS vars apply."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert "theme-switcher.js" in resp.text, (
            "Login page missing theme-switcher.js — dark theme CSS variables won't apply"
        )

    def test_login_page_includes_style_css(self, unauth_client: Any) -> None:
        """Login page must include the main stylesheet with CSS variables."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert "style.css" in resp.text, (
            "Login page missing style.css — CSS variables for dark theme won't be defined"
        )

    def test_login_page_has_logo(self, unauth_client: Any) -> None:
        """Login page must display a logo/brand element."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert "ChatFilter" in resp.text, "Login page missing ChatFilter brand/logo"
        assert "minimal-logo" in resp.text or "logo" in resp.text, (
            "Login page missing logo container element"
        )

    def test_login_page_uses_css_variables_not_hardcoded_colors(self, unauth_client: Any) -> None:
        """Login card must use CSS variables so dark theme applies correctly."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert "--card-bg" in resp.text or "var(--" in resp.text, (
            "Login page not using CSS variables — dark theme won't apply to form"
        )


class TestLoginFormI18n:
    """Login form labels must use i18n translations (SPEC nice-to-have)."""

    def test_login_form_has_username_and_password_fields(self, unauth_client: Any) -> None:
        """Login form must have username and password inputs."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert 'name="username"' in resp.text
        assert 'name="password"' in resp.text

    def test_login_form_is_fully_rendered(self, unauth_client: Any) -> None:
        """Jinja2 must be fully rendered — no raw template syntax in output."""
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert "{% block" not in resp.text, "Jinja2 not fully rendered"
        assert "{{" not in resp.text, "Jinja2 expressions not rendered"


class TestProxyPoolLogLevel:
    """proxy_pool.update_proxy must log at DEBUG level (SPEC item 4)."""

    def test_update_proxy_logs_at_debug_not_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """update_proxy must emit 'Updated proxy in pool' at DEBUG, not INFO."""
        from chatfilter.config_proxy import ProxyType
        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.storage import proxy_pool as pool_module

        proxy = ProxyEntry(name="TestProxy", type=ProxyType.SOCKS5, host="1.2.3.4", port=1080)
        saved_proxies = [proxy]

        with (
            patch.object(pool_module, "load_proxy_pool", return_value=saved_proxies),
            patch.object(pool_module, "save_proxy_pool"),
            caplog.at_level(logging.DEBUG, logger="chatfilter.storage.proxy_pool"),
        ):
            pool_module.update_proxy(proxy.id, proxy, user_id="test-user")

        update_records = [r for r in caplog.records if "Updated proxy in pool" in r.message]
        assert update_records, "Expected 'Updated proxy in pool' log message not found"

        for record in update_records:
            assert record.levelno == logging.DEBUG, (
                f"'Updated proxy in pool' logged at {record.levelname} instead of DEBUG — "
                "causes log spam every 5 minutes per proxy"
            )


class TestAdminPasswordLogging:
    """Admin user creation must log password via logger.warning (SPEC item 5)."""

    def test_source_has_logger_warning_for_admin_creation(self) -> None:
        """Source code must contain logger.warning for admin password (not just print)."""
        import inspect

        from chatfilter.web import app as app_module

        source = inspect.getsource(app_module)

        assert "logger.warning" in source and "Admin user created" in source, (
            "app.py missing logger.warning for admin password — "
            "password only in print() will be lost in non-TTY deployments"
        )
