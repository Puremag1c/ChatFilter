"""Debug test with proper path mocking."""
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock
from pathlib import Path
import tempfile
import shutil
import sys
sys.path.insert(0, '/Users/m/Zen/Code/ChatFilter/src')

async def main():
    from chatfilter.web.auth_state import AuthState
    from chatfilter.web.routers.sessions import verify_code

    session_id = "test_session"
    auth_id = "auth_123"
    code = "12345"

    # Create real temp dir for session
    temp_base = tempfile.mkdtemp()
    session_dir = Path(temp_base) / session_id
    session_dir.mkdir(parents=True)
    (session_dir / "config.json").write_text('{}')

    try:
        with (
            patch("chatfilter.web.auth_state.get_auth_state_manager") as mock_auth_manager_getter,
            patch("chatfilter.web.events.get_event_bus") as mock_bus_getter,
            patch("chatfilter.web.dependencies.get_session_manager") as mock_manager_getter,
            patch("chatfilter.web.routers.sessions.ensure_data_dir") as mock_ensure_data_dir,
            patch("chatfilter.web.routers.sessions.save_account_info") as mock_save_account_info,
            patch("chatfilter.web.routers.sessions.secure_file_permissions") as mock_secure_file,
            patch("chatfilter.web.routers.sessions.secure_delete_dir") as mock_secure_delete,
        ):
            # Return real path
            mock_ensure_data_dir.return_value = Path(temp_base)

            # Setup mocks
            mock_client = AsyncMock()
            mock_client.is_user_authorized = AsyncMock(return_value=True)
            mock_client.sign_in = AsyncMock()  # Success
            mock_client.is_connected = MagicMock(return_value=True)
            mock_client.get_me = AsyncMock(return_value=MagicMock(
                id=123456,
                phone="+1234567890",
                first_name="Test",
                last_name="User"
            ))
            mock_client.disconnect = AsyncMock()

            mock_auth_state = MagicMock(spec=AuthState)
            mock_auth_state.session_name = session_id
            mock_auth_state.auth_id = auth_id
            mock_auth_state.phone = "+1234567890"
            mock_auth_state.phone_code_hash = "test_hash"
            mock_auth_state.client = mock_client
            mock_auth_state.temp_dir = None

            mock_auth_manager = MagicMock()
            mock_auth_manager.get_auth_state = AsyncMock(return_value=mock_auth_state)
            mock_auth_manager.remove_auth_state = AsyncMock()
            mock_auth_manager.check_auth_lock = AsyncMock(return_value=(False, 0))
            mock_auth_manager_getter.return_value = mock_auth_manager

            # Track all publishes
            publish_calls = []

            async def track_publish(session_id, event):
                publish_calls.append((session_id, event))
                print(f"✅ Published: session_id='{session_id}', event='{event}'")

            mock_bus = MagicMock()
            mock_bus.publish = track_publish
            mock_bus_getter.return_value = mock_bus

            mock_manager = MagicMock()
            mock_manager._add_session = MagicMock()
            mock_manager_getter.return_value = mock_manager

            # Mock Request with templates
            mock_templates = MagicMock()
            mock_templates.TemplateResponse.return_value = MagicMock()

            mock_request = MagicMock()

            with patch("chatfilter.web.routers.sessions.get_templates", return_value=mock_templates):
                # Execute
                print("Starting verify_code...")
                print(f"Session dir exists: {session_dir.exists()}")
                result = await verify_code(mock_request, session_id, auth_id, code)

                print(f"\n📊 Total publish calls: {len(publish_calls)}")
                if publish_calls:
                    for i, (sid, event) in enumerate(publish_calls):
                        print(f"  {i+1}. session_id='{sid}', event='{event}'")
                else:
                    print("  ⚠️  NO PUBLISH CALLS!")

                print(f"\n🔍 Mock calls:")
                print(f"  sign_in called: {mock_client.sign_in.called}")
                print(f"  get_me called: {mock_client.get_me.called}")
                print(f"  disconnect called: {mock_client.disconnect.called}")
                print(f"  remove_auth_state called: {mock_auth_manager.remove_auth_state.called}")
                print(f"  save_account_info called: {mock_save_account_info.called}")
    finally:
        # Cleanup
        shutil.rmtree(temp_base, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(main())
