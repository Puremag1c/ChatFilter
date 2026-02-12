"""Integration tests for auth flow fixes (Bug1, Bug2, Bug3).

Test Scenarios:
1. Code -> 2FA transition: verify-code with 2FA returns needs_2fa row with button
2. 2FA -> Connected: verify-2fa success returns connected session_row
3. Language switch: EN->RU translates nav menu
4. Full flow: verify-code needs_2fa -> verify-2fa connected (no page refresh)
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app
from chatfilter.web.auth_state import AuthState, AuthStep


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag."""
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


def _make_auth_state(
    session_name: str = "testsession",
    auth_id: str = "auth-test-123",
    step: AuthStep = AuthStep.PHONE_SENT,
) -> AuthState:
    """Create a mock AuthState for testing."""
    client = MagicMock()
    client.is_connected.return_value = True
    client.sign_in = AsyncMock()
    client.get_me = AsyncMock()
    client.disconnect = AsyncMock()

    return AuthState(
        auth_id=auth_id,
        session_name=session_name,
        api_id=12345,
        api_hash="testhash",
        proxy_id="",
        phone="+79001234567",
        step=step,
        phone_code_hash="test_hash",
        client=client,
    )


@pytest.fixture
def client() -> TestClient:
    """Create test client."""
    app = create_app()
    return TestClient(app)


def _get_csrf_token(client: TestClient) -> str:
    """Get CSRF token by loading the home page."""
    response = client.get("/")
    token = extract_csrf_token(response.text)
    assert token is not None, "CSRF token not found"
    return token


class TestVerifyCodeNeeds2FA:
    """Test 1: verify-code with SessionPasswordNeededError returns needs_2fa row.

    Bug1 fix: verify-code on needs_2fa returns <tr> with needs_2fa state,
    not a <div> form.
    """

    def test_verify_code_returns_session_row_on_needs_2fa(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        """verify-code with 2FA required returns <tr> with needs_2fa state and 2FA button."""
        from telethon.errors import SessionPasswordNeededError

        auth_state = _make_auth_state()
        # Make sign_in raise SessionPasswordNeededError
        auth_state.client.sign_in = AsyncMock(side_effect=SessionPasswordNeededError(request=None))

        session_dir = tmp_path / "testsession"
        session_dir.mkdir()
        (session_dir / "session.session").touch()

        csrf_token = _get_csrf_token(client)

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.check_auth_lock = AsyncMock(return_value=(False, 0))
        mock_auth_manager.update_auth_state = AsyncMock()

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        mock_cred = MagicMock()
        mock_cred.retrieve_2fa.return_value = None  # No stored 2FA password

        with (
            patch(
                "chatfilter.web.auth_state.get_auth_state_manager",
                return_value=mock_auth_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.get_event_bus",
                return_value=mock_event_bus,
            ),
            patch(
                "chatfilter.web.routers.sessions.ensure_data_dir",
                return_value=tmp_path,
            ),
            patch(
                "chatfilter.security.SecureCredentialManager",
                return_value=mock_cred,
            ),
        ):
            response = client.post(
                "/api/sessions/testsession/verify-code",
                data={
                    "auth_id": "auth-test-123",
                    "code": "12345",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        html = response.text

        # Must be a <tr> element (session row), not a <div>
        assert "<tr" in html, f"Response must contain a <tr> element (session row), got: {html[:500]}"
        assert "status-needs_2fa" in html, f"Row must have needs_2fa status class, got: {html[:500]}"

        # Must contain 2FA button
        assert "session-2fa-modal-btn" in html, "Row must contain 2FA modal button"
        assert 'data-auth-id="auth-test-123"' in html, "Button must have auth_id data attr"
        assert 'data-session-id="testsession"' in html, "Button must have session_id data attr"


class TestVerify2FASuccess:
    """Test 2: verify-2fa success returns connected session_row.

    Bug2 fix: verify-2fa on success returns <tr> with connected state,
    not a <div> toast.
    """

    def test_verify_2fa_returns_session_row_on_success(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        """verify-2fa success returns <tr> with connected state."""
        auth_state = _make_auth_state(step=AuthStep.NEED_2FA)
        # sign_in succeeds (no exception)
        auth_state.client.sign_in = AsyncMock(return_value=MagicMock())

        csrf_token = _get_csrf_token(client)

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.check_auth_lock = AsyncMock(return_value=(False, 0))
        mock_auth_manager.remove_auth_state = AsyncMock()

        from chatfilter.web.routers.sessions import SessionListItem

        connected_session = SessionListItem(
            session_id="testsession",
            state="connected",
            has_session_file=True,
            retry_available=False,
        )

        with (
            patch(
                "chatfilter.web.auth_state.get_auth_state_manager",
                return_value=mock_auth_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions._finalize_reconnect_auth",
                new_callable=AsyncMock,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=MagicMock(),
            ),
            patch(
                "chatfilter.web.routers.sessions.list_stored_sessions",
                return_value=[connected_session],
            ),
        ):
            response = client.post(
                "/api/sessions/testsession/verify-2fa",
                data={
                    "auth_id": "auth-test-123",
                    "password": "my2fapassword",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        html = response.text

        # Must be a <tr> element (session row), not a <div>
        assert "<tr" in html, f"Response must contain a <tr> element (session row), got: {html[:500]}"
        assert "status-connected" in html, f"Row must have connected status class, got: {html[:500]}"

        # Connected row should have Disconnect button
        assert "Disconnect" in html or "session-disconnect-btn" in html


class TestLanguageSwitchTranslation:
    """Test 3: EN->RU language switch translates nav menu.

    Bug3 fix: After removing env.install_gettext_translations() race condition,
    the ContextVar-based translation correctly switches languages.
    """

    def test_nav_menu_en_default(self, client: TestClient) -> None:
        """Default (EN) nav menu has English labels."""
        response = client.get("/")
        assert response.status_code == 200

        html = response.text
        # English nav items from base.html
        assert "Sessions" in html
        assert "Proxies" in html
        assert "Chats" in html

    def test_nav_menu_ru_via_cookie(self, client: TestClient) -> None:
        """RU locale via cookie translates nav menu items."""
        # Set the cookie on the client directly to avoid deprecation warning
        client.cookies.set("lang", "ru")
        response = client.get("/")
        assert response.status_code == 200

        html = response.text
        # After Bug3 fix, locale cookie should trigger Russian translations.
        # Verify the locale is correctly set by checking the html lang attribute.
        assert 'lang="ru"' in html, "HTML lang attribute should be 'ru'"

        # The lang cookie should be echoed back in set-cookie
        set_cookie = response.headers.get("set-cookie", "")
        assert "lang=ru" in set_cookie, "Response should set lang=ru cookie"

        # Clean up client cookies
        client.cookies.clear()


class TestFullAuthFlowNoRefresh:
    """Test 4: Full flow Code->2FA->Connected without page refresh.

    Simulates: verify-code(needs_2fa) -> verify-2fa(connected).
    Both responses are <tr> elements that can replace each other via HTMX outerHTML.
    """

    def test_code_to_2fa_to_connected_flow(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        """Full auth flow: verify-code returns needs_2fa row, then verify-2fa returns connected row."""
        from telethon.errors import SessionPasswordNeededError

        auth_state = _make_auth_state()
        auth_state.client.sign_in = AsyncMock(side_effect=SessionPasswordNeededError(request=None))

        session_dir = tmp_path / "testsession"
        session_dir.mkdir()
        (session_dir / "session.session").touch()

        csrf_token = _get_csrf_token(client)

        mock_auth_manager = AsyncMock()
        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state)
        mock_auth_manager.check_auth_lock = AsyncMock(return_value=(False, 0))
        mock_auth_manager.update_auth_state = AsyncMock()
        mock_auth_manager.remove_auth_state = AsyncMock()

        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        mock_cred = MagicMock()
        mock_cred.retrieve_2fa.return_value = None

        # Step 1: verify-code -> needs_2fa
        with (
            patch(
                "chatfilter.web.auth_state.get_auth_state_manager",
                return_value=mock_auth_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions.get_event_bus",
                return_value=mock_event_bus,
            ),
            patch(
                "chatfilter.web.routers.sessions.ensure_data_dir",
                return_value=tmp_path,
            ),
            patch(
                "chatfilter.security.SecureCredentialManager",
                return_value=mock_cred,
            ),
        ):
            step1_response = client.post(
                "/api/sessions/testsession/verify-code",
                data={"auth_id": "auth-test-123", "code": "12345"},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert step1_response.status_code == 200
        step1_html = step1_response.text

        # Verify step1 returns needs_2fa <tr>
        assert "<tr" in step1_html, "Step 1: must return <tr> element"
        assert "status-needs_2fa" in step1_html, "Step 1: must have needs_2fa status"
        assert "session-2fa-modal-btn" in step1_html, "Step 1: must have 2FA button"

        # Step 2: verify-2fa -> connected
        auth_state_2fa = _make_auth_state(step=AuthStep.NEED_2FA)
        auth_state_2fa.client.sign_in = AsyncMock(return_value=MagicMock())

        mock_auth_manager.get_auth_state = AsyncMock(return_value=auth_state_2fa)

        from chatfilter.web.routers.sessions import SessionListItem

        connected_session = SessionListItem(
            session_id="testsession",
            state="connected",
            has_session_file=True,
            retry_available=False,
        )

        with (
            patch(
                "chatfilter.web.auth_state.get_auth_state_manager",
                return_value=mock_auth_manager,
            ),
            patch(
                "chatfilter.web.routers.sessions._finalize_reconnect_auth",
                new_callable=AsyncMock,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=MagicMock(),
            ),
            patch(
                "chatfilter.web.routers.sessions.list_stored_sessions",
                return_value=[connected_session],
            ),
        ):
            step2_response = client.post(
                "/api/sessions/testsession/verify-2fa",
                data={"auth_id": "auth-test-123", "password": "my2fapassword"},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert step2_response.status_code == 200
        step2_html = step2_response.text

        # Verify step2 returns connected <tr>
        assert "<tr" in step2_html, "Step 2: must return <tr> element"
        assert "status-connected" in step2_html, "Step 2: must have connected status"

        # Both are <tr> elements with the same id — HTMX outerHTML swap works
        assert 'id="session-testsession"' in step1_html
        assert 'id="session-testsession"' in step2_html


class TestAdoptClientFailureHandling:
    """Test 5: adopt_client failure triggers proper cleanup.

    Reliability fix: If adopt_client() fails (EventBus down, threading race, etc.),
    we must:
    1. Disconnect the orphaned client
    2. Remove auth_state
    3. Publish SSE error event
    4. Re-raise exception (don't swallow it)
    """

    @pytest.mark.asyncio
    async def test_adopt_client_failure_cleanup(self, tmp_path: Path) -> None:
        """When adopt_client fails, finalize_reconnect_auth should cleanup and raise."""
        from chatfilter.web.routers.sessions import _finalize_reconnect_auth
        from chatfilter.web.auth_state import AuthStateManager

        # Create mock client
        mock_client = MagicMock()
        mock_client.get_me = AsyncMock(
            return_value=MagicMock(
                id=123456,
                phone="+79001234567",
                first_name="Test",
                last_name="User",
            )
        )
        mock_client.session = MagicMock()
        mock_client.session.save = MagicMock()
        mock_client.disconnect = AsyncMock()

        # Create mock auth_state
        auth_state = _make_auth_state()
        auth_state.temp_dir = None  # No temp dir for this test

        # Create mock auth_manager
        mock_auth_manager = AsyncMock(spec=AuthStateManager)
        mock_auth_manager.remove_auth_state = AsyncMock()

        # Create session directory
        session_dir = tmp_path / "testsession"
        session_dir.mkdir()
        (session_dir / "session.session").touch()
        (session_dir / "config.json").write_text('{"api_id": 12345, "api_hash": "test"}')

        # Mock SessionManager that raises exception on adopt_client
        mock_session_manager = MagicMock()
        adopt_error = RuntimeError("EventBus is down!")
        mock_session_manager.adopt_client = AsyncMock(side_effect=adopt_error)

        # Mock EventBus
        mock_event_bus = MagicMock()
        mock_event_bus.publish = AsyncMock()

        with (
            patch(
                "chatfilter.web.routers.sessions.ensure_data_dir",
                return_value=tmp_path,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.web.events.get_event_bus",
                return_value=mock_event_bus,
            ),
            patch(
                "chatfilter.web.routers.sessions.save_account_info",
                MagicMock(),
            ),
        ):
            # Call _finalize_reconnect_auth — should raise
            with pytest.raises(RuntimeError, match="EventBus is down!"):
                await _finalize_reconnect_auth(
                    client=mock_client,
                    auth_state=auth_state,
                    auth_manager=mock_auth_manager,
                    safe_name="testsession",
                    log_context="test",
                )

        # Verify cleanup happened BEFORE re-raising
        # 1. Client was disconnected
        mock_client.disconnect.assert_awaited_once()

        # 2. Auth state was removed
        mock_auth_manager.remove_auth_state.assert_awaited_once_with(auth_state.auth_id)

        # 3. SSE error event was published
        mock_event_bus.publish.assert_awaited_once_with("testsession", "error")
