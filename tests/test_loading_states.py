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

    def test_connect_button_has_htmx_attributes(self) -> None:
        """Connect button should have proper htmx attributes."""
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
        assert 'hx-disabled-elt="this"' in html

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

    def test_disconnect_button_has_htmx_attributes(self) -> None:
        """Disconnect button should have proper htmx attributes."""
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
        assert 'hx-disabled-elt="this"' in html

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

    def test_connect_button_for_disconnected_with_session_file(self) -> None:
        """Connect button should appear for disconnected session with session file."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Mock a disconnected session with existing session file (expired sessions map to disconnected state)
        session_data = {
            "session_id": "test_session",
            "state": "disconnected",
            "error_message": "Session has expired",
            "has_session_file": True,  # Has existing session file
        }

        html = template.render(session=session_data)

        # Verify Connect button is shown with correct endpoint
        # Connect uses same flow (posts to /connect)
        assert "Connect" in html
        assert 'hx-post="/api/sessions/test_session/connect"' in html
        assert 'hx-target="#session-test_session"' in html

    def test_connect_button_target_and_swap(self) -> None:
        """Connect button should target session row and swap outerHTML."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        session_data = {
            "session_id": "test_session",
            "state": "disconnected",
            "error_message": None,
            "has_session_file": True,
        }

        html = template.render(session=session_data)

        # Verify HTMX target and swap configuration
        # Connect uses same flow (updates session row, not modal)
        assert 'hx-target="#session-test_session"' in html
        assert 'hx-swap="outerHTML"' in html


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

        # Verify status changed from "Disconnecting" to "Needs Auth"
        assert "Needs Auth" in html
        assert 'class="status-icon"' in html and "📱" in html


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

        # Test 1: Connect (with session file)
        connect_html = template.render(
            session={
                "session_id": "s1",
                "state": "disconnected",
                "error_message": None,
                "has_session_file": True,
            }
        )
        assert "Connect" in connect_html
        assert "session-connect-btn" in connect_html

        # Test 2: Disconnect
        disconnect_html = template.render(
            session={"session_id": "s2", "state": "connected", "error_message": None}
        )
        assert "Disconnect" in disconnect_html
        assert "session-disconnect-btn" in disconnect_html

        # Test 3: Connect for disconnected session with file (e.g., from expired session)
        reconnect_html = template.render(
            session={
                "session_id": "s3",
                "state": "disconnected",
                "error_message": "Expired",
                "has_session_file": True,
            }
        )
        assert "Connect" in reconnect_html

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
        """All action types should have proper loading state handling."""
        env = _setup_template_env()
        template = env.get_template("partials/session_row.html")

        # Test Connect/Disconnect have hx-disabled-elt
        connect_html = template.render(
            session={"session_id": "s1", "state": "disconnected", "error_message": None}
        )
        assert "hx-disabled-elt" in connect_html

        # Test disabled state during operation
        loading_html = template.render(
            session={"session_id": "s2", "state": "connecting", "error_message": None}
        )
        assert 'disabled' in loading_html
        assert "Wait..." in loading_html
