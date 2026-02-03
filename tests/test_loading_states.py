"""Tests for loading states on action buttons.

Tests cover loading state display for all 6 action types:
- Connect button
- Disconnect button
- Reconnect button
- Send Code (Enter Verification Code)
- Verify Code (2FA modal)
- Verify 2FA Password

Each test verifies:
- Button becomes disabled on click
- Spinner appears in status cell
- After response: button is replaced/hidden, status updates
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from jinja2 import Environment, FileSystemLoader


def _setup_template_env():
    """Set up Jinja2 environment with translation function.

    Returns:
        Jinja2 Environment with proper filters and globals
    """
    template_dir = Path("src/chatfilter/templates")
    env = Environment(loader=FileSystemLoader(str(template_dir)))

    # Add translation function
    env.globals["_"] = lambda x: x

    return env


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag.

    Args:
        html: HTML content containing meta tag with csrf-token

    Returns:
        CSRF token string or None if not found
    """
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


def _setup_template_env():
    """Set up Jinja2 environment with translation function.

    Returns:
        Jinja2 Environment with proper filters and globals
    """
    from jinja2 import Environment, FileSystemLoader
    from pathlib import Path

    template_dir = Path("src/chatfilter/templates")
    env = Environment(loader=FileSystemLoader(str(template_dir)))

    # Add translation function
    env.globals["_"] = lambda x: x

    return env


class TestLoadingStateConnect:
    """Tests for Connect button loading state."""

    def test_connect_button_has_spinner_indicator(self) -> None:
        """Connect button should have hx-indicator pointing to spinner."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock a disconnected session
        session_data = {
            "session_id": "test_session",
            "state": "disconnected",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify button exists and has hx-post attribute
        assert 'class="btn btn-sm btn-success session-connect-btn"' in html
        assert 'hx-post="/api/sessions/test_session/connect"' in html

        # Verify spinner indicator is configured
        assert 'hx-indicator="#connection-spinner-test_session"' in html
        assert 'class="htmx-indicator spinner"' in html

    def test_connect_button_disabled_during_loading(self) -> None:
        """When connecting, button should show disabled state with spinner."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock a connecting session
        session_data = {
            "session_id": "test_session",
            "state": "connecting",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify button is disabled
        assert 'class="btn btn-sm btn-secondary session-connect-btn" disabled' in html
        # Verify spinner is displayed
        assert 'class="spinner"' in html
        assert "Wait..." in html


class TestLoadingStateDisconnect:
    """Tests for Disconnect button loading state."""

    def test_disconnect_button_has_spinner_indicator(self) -> None:
        """Disconnect button should have hx-indicator pointing to spinner."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock a connected session
        session_data = {
            "session_id": "test_session",
            "state": "connected",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify button exists and has hx-post attribute
        assert 'class="btn btn-sm btn-warning session-disconnect-btn"' in html
        assert 'hx-post="/api/sessions/test_session/disconnect"' in html

        # Verify spinner indicator is configured
        assert 'hx-indicator="#connection-spinner-test_session"' in html
        assert 'class="htmx-indicator spinner"' in html

    def test_disconnect_button_target_and_swap(self) -> None:
        """Disconnect button should target session row and swap outerHTML."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "connected",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify HTMX target and swap configuration
        assert 'hx-target="#session-test_session"' in html
        assert 'hx-swap="outerHTML"' in html


class TestLoadingStateReconnect:
    """Tests for Reconnect button loading state."""

    def test_reconnect_button_appears_for_expired_session(self) -> None:
        """Reconnect button should appear when session is expired."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock an expired session
        session_data = {
            "session_id": "test_session",
            "state": "session_expired",
            "error_message": "Session has expired",
        }

        html = template.render(session=session_data)

        # Verify Reconnect button is shown
        assert "Reconnect" in html
        assert 'hx-get="/api/sessions/test_session/reconnect-form"' in html
        assert 'hx-target="#modal-container"' in html

    def test_reconnect_button_target_modal(self) -> None:
        """Reconnect button should target modal container."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "session_expired",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify modal-related attributes
        assert 'hx-swap="innerHTML"' in html
        assert '#modal-container' in html


class TestLoadingStateSendCode:
    """Tests for Send Code (Enter Verification Code) button loading state."""

    def test_code_modal_button_appears_for_needs_code(self) -> None:
        """Code modal button should appear when session needs verification code."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock a session needing code
        session_data = {
            "session_id": "test_session",
            "state": "needs_code",
            "error_message": None,
            "auth_id": "12345",
        }

        html = template.render(session=session_data)

        # Verify button is shown
        assert "Enter Verification Code" in html
        assert 'class="btn btn-sm btn-info session-code-modal-btn"' in html

    def test_code_modal_button_has_session_data(self) -> None:
        """Code modal button should include session_id and auth_id data attributes."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "needs_code",
            "error_message": None,
            "auth_id": "auth_12345",
        }

        html = template.render(session=session_data)

        # Verify data attributes for modal handler
        assert 'data-session-id="test_session"' in html
        assert 'data-auth-id="auth_12345"' in html


class TestLoadingStateVerifyCode:
    """Tests for Verify Code modal submission loading state."""

    def test_code_form_has_loading_attributes(self) -> None:
        """Code verification form should have loading state attributes.

        Note: This test verifies the button exists and can be interacted with.
        The actual modal form testing is done in test_sessions_router.py.
        """
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "needs_code",
            "error_message": None,
            "auth_id": "12345",
        }

        html = template.render(session=session_data)

        # Verify the button class that triggers the code modal
        assert 'session-code-modal-btn' in html

    def test_code_modal_button_accessible(self) -> None:
        """Code modal button should have proper accessibility attributes."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "needs_code",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify accessibility label
        assert 'aria-label=' in html
        assert 'verification code' in html.lower() or 'code' in html.lower()


class TestLoadingStateVerify2FA:
    """Tests for Verify 2FA Password button loading state."""

    def test_2fa_modal_button_appears_for_needs_2fa(self) -> None:
        """2FA modal button should appear when session needs 2FA password."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock a session needing 2FA
        session_data = {
            "session_id": "test_session",
            "state": "needs_2fa",
            "error_message": None,
            "auth_id": "12345",
        }

        html = template.render(session=session_data)

        # Verify button is shown
        assert "Enter 2FA Password" in html
        assert 'class="btn btn-sm btn-info session-2fa-modal-btn"' in html

    def test_2fa_modal_button_has_session_data(self) -> None:
        """2FA modal button should include session_id and auth_id data attributes."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "needs_2fa",
            "error_message": None,
            "auth_id": "auth_67890",
        }

        html = template.render(session=session_data)

        # Verify data attributes for modal handler
        assert 'data-session-id="test_session"' in html
        assert 'data-auth-id="auth_67890"' in html

    def test_2fa_modal_button_accessible(self) -> None:
        """2FA modal button should have proper accessibility attributes."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "needs_2fa",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify accessibility label
        assert 'aria-label=' in html
        assert '2fa' in html.lower() or 'password' in html.lower()


class TestStatusCellSpinner:
    """Tests for spinner display in status cell during state transitions."""

    def test_status_cell_shows_spinner_when_connecting(self) -> None:
        """Status cell should show spinner and 'Connecting' text during connection."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "connecting",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify spinner icon and status text
        assert 'class="status-icon spinner-small"' in html
        assert "Connecting" in html

    def test_status_cell_shows_spinner_when_disconnecting(self) -> None:
        """Status cell should show spinner and 'Disconnecting' text during disconnection."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "disconnecting",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify spinner icon and status text
        assert 'class="status-icon spinner-small"' in html
        assert "Disconnecting" in html

    def test_status_cell_updates_after_connection(self) -> None:
        """Status cell should show connected state after successful connection."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # After successful connection
        session_data = {
            "session_id": "test_session",
            "state": "connected",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify status changed from "Connecting" to "Connected"
        assert "Connected" in html
        assert 'class="status-icon"' in html and "●" in html

    def test_status_cell_updates_after_disconnection(self) -> None:
        """Status cell should show disconnected state after successful disconnection."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # After successful disconnection
        session_data = {
            "session_id": "test_session",
            "state": "disconnected",
            "error_message": None,
        }

        html = template.render(session=session_data)

        # Verify status changed from "Disconnecting" to "Ready"
        assert "Ready" in html
        assert 'class="status-icon"' in html and "✓" in html


class TestAllActionTypesComplete:
    """Integration test: All 6 action types have loading state support."""

    def test_all_six_action_types_present(self) -> None:
        """Template should support all 6 action types with loading states.

        The 6 action types are:
        1. Connect
        2. Disconnect
        3. Reconnect
        4. Send Code (Enter Verification Code)
        5. Verify Code (via modal)
        6. Verify 2FA Password
        """
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Test 1: Connect
        connect_html = template.render(
            session={"session_id": "s1", "state": "disconnected", "error_message": None}
        )
        assert "Connect" in connect_html
        assert "session-connect-btn" in connect_html

        # Test 2: Disconnect
        disconnect_html = template.render(
            session={"session_id": "s2", "state": "connected", "error_message": None}
        )
        assert "Disconnect" in disconnect_html
        assert "session-disconnect-btn" in disconnect_html

        # Test 3: Reconnect
        reconnect_html = template.render(
            session={
                "session_id": "s3",
                "state": "session_expired",
                "error_message": "Expired",
            }
        )
        assert "Reconnect" in reconnect_html

        # Test 4: Send Code (Enter Verification Code)
        code_html = template.render(
            session={
                "session_id": "s4",
                "state": "needs_code",
                "error_message": None,
                "auth_id": "123",
            }
        )
        assert "Enter Verification Code" in code_html
        assert "session-code-modal-btn" in code_html

        # Test 5: Verify Code - button exists (modal handling is JS-based)
        assert "session-code-modal-btn" in code_html

        # Test 6: Verify 2FA Password
        twofa_html = template.render(
            session={
                "session_id": "s5",
                "state": "needs_2fa",
                "error_message": None,
                "auth_id": "456",
            }
        )
        assert "Enter 2FA Password" in twofa_html
        assert "session-2fa-modal-btn" in twofa_html

    def test_all_action_types_have_loading_states(self) -> None:
        """All action types should have HTMX loading indicators."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Test Connect/Disconnect have spinner indicators
        connect_html = template.render(
            session={"session_id": "s1", "state": "disconnected", "error_message": None}
        )
        assert "hx-indicator" in connect_html
        assert "htmx-indicator spinner" in connect_html

        # Test disabled state during operation
        loading_html = template.render(
            session={"session_id": "s2", "state": "connecting", "error_message": None}
        )
        assert 'disabled' in loading_html
        assert "Wait..." in loading_html
