"""Debug test to see what verify_code actually calls."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
import tempfile
import shutil


async def test_verify_code_debug():
    """Debug: verify_code call chain."""
    from chatfilter.web.auth_state import AuthState
    from chatfilter.web.routers.sessions import verify_code

    session_id = "test_session"
    auth_id = "auth_123"
    code = "12345"

    # Track all calls
    call_log = []

    # Create temp directory for session
    temp_dir = tempfile.mkdtemp()
    session_dir = Path(temp_dir) / session_id
    session_dir.mkdir(parents=True)

    # Create minimal required files
    (session_dir / "config.json").write_text('{"session_name": "test_session"}')

    try:
        # Mock dependencies
        with (
            patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_auth_manager_getter,
            patch("chatfilter.web.routers.sessions.get_event_bus") as mock_bus_getter,
            patch("chatfilter.web.routers.sessions.ensure_data_dir") as mock_ensure_data_dir,
            patch("chatfilter.web.routers.sessions.save_account_info") as mock_save_account_info,
            patch("chatfilter.web.routers.sessions.secure_file_permissions") as mock_secure_perms,
            patch("chatfilter.web.routers.sessions.secure_delete_dir") as mock_secure_delete,
            patch("chatfilter.web.routers.sessions.get_templates") as mock_get_templates,
        ):
            # Setup mocks
            mock_client = AsyncMock()
            mock_client.is_user_authorized = AsyncMock(return_value=True)
            mock_client.sign_in = AsyncMock()  # Success, no 2FA needed
            mock_client.is_connected = MagicMock(return_value=True)
            mock_client.get_me = AsyncMock(return_value=MagicMock(
                id=123456,
                phone="+1234567890",
                first_name="Test",
                last_name="User"
            ))
            mock_client.disconnect = AsyncMock()

            # Create temp session file
            temp_auth_dir = Path(tempfile.mkdtemp())
            temp_session_file = temp_auth_dir / "auth_session.session"
            temp_session_file.write_text("fake_session_data")

            mock_auth_state = MagicMock(spec=AuthState)
            mock_auth_state.session_name = session_id
            mock_auth_state.auth_id = auth_id
            mock_auth_state.phone = "+1234567890"
            mock_auth_state.phone_code_hash = "hash123"
            mock_auth_state.client = mock_client
            mock_auth_state.temp_dir = str(temp_auth_dir)

            mock_auth_manager = MagicMock()
            mock_auth_manager.get_auth_state = AsyncMock(return_value=mock_auth_state)
            mock_auth_manager.remove_auth_state = AsyncMock()
            mock_auth_manager.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_auth_manager_getter.return_value = mock_auth_manager

            # Event bus mock - track calls
            async def track_publish(session, status):
                call_log.append(("publish", session, status))

            mock_bus = MagicMock()
            mock_publish = AsyncMock(side_effect=track_publish)
            mock_bus.publish = mock_publish
            mock_bus_getter.return_value = mock_bus

            # Mock ensure_data_dir to return our temp dir
            mock_ensure_data_dir.return_value = Path(temp_dir)

            # Mock templates
            mock_templates = MagicMock()
            mock_templates.TemplateResponse = MagicMock(return_value="<html>Success</html>")
            mock_get_templates.return_value = mock_templates

            # Mock Request object
            mock_request = MagicMock()

            # Execute
            print("\n=== Executing verify_code ===")
            result = await verify_code(mock_request, session_id, auth_id, code)
            print(f"Result: {result}")

            # Print call log
            print("\n=== Call Log ===")
            for call in call_log:
                print(f"  {call}")

            print("\n=== mock_publish.call_args_list ===")
            for call in mock_publish.call_args_list:
                print(f"  {call}")

            # Check if event was published
            connected_published = any(
                call[0][1] == "connected" for call in mock_publish.call_args_list
            )
            print(f"\n'connected' event published: {connected_published}")

            # Cleanup temp auth dir
            shutil.rmtree(temp_auth_dir, ignore_errors=True)

    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(test_verify_code_debug())
