"""Comprehensive tests for MonitoringService."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.models import Message
from chatfilter.models.monitoring import (
    ChatMonitorState,
    GrowthMetrics,
    MonitoringSummary,
    SyncSnapshot,
)
from chatfilter.service.monitoring import (
    MonitoringError,
    MonitoringService,
    MonitorNotFoundError,
    get_monitoring_service,
    reset_monitoring_service,
)
from chatfilter.telegram.session_manager import SessionManager

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_data_dir(tmp_path: Path) -> Path:
    """Create a temporary data directory for testing."""
    data_dir = tmp_path / "data" / "sessions"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Create a temporary database path."""
    return tmp_path / "test_monitoring.db"


@pytest.fixture
def mock_session_manager() -> SessionManager:
    """Provide a mock session manager."""
    return MagicMock(spec=SessionManager)


@pytest.fixture
def monitoring_service(
    mock_session_manager: SessionManager,
    temp_data_dir: Path,
    temp_db_path: Path,
) -> MonitoringService:
    """Provide a MonitoringService instance for testing."""
    return MonitoringService(
        session_manager=mock_session_manager,
        data_dir=temp_data_dir,
        db_path=temp_db_path,
    )


@pytest.fixture
def session_with_files(temp_data_dir: Path) -> tuple[str, Path]:
    """Create a test session with required files."""
    session_id = "test-session"
    session_dir = temp_data_dir / session_id
    session_dir.mkdir()
    (session_dir / "session.session").touch()
    (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')
    return session_id, session_dir


@pytest.fixture
def fake_messages() -> list[Message]:
    """Create fake messages for testing."""
    now = datetime.now(UTC)
    return [
        Message(
            id=i,
            chat_id=123456,
            author_id=100 + (i % 5),  # 5 unique authors
            text=f"Message {i}",
            timestamp=now - timedelta(hours=10 - i),
        )
        for i in range(1, 11)
    ]


# ============================================================================
# Tests for MonitoringError Exceptions
# ============================================================================


class TestMonitoringExceptions:
    """Tests for monitoring exception classes."""

    def test_monitoring_error_base_exception(self) -> None:
        """Test MonitoringError base exception."""
        error = MonitoringError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_monitor_not_found_error(self) -> None:
        """Test MonitorNotFoundError exception."""
        error = MonitorNotFoundError("Chat not monitored")
        assert str(error) == "Chat not monitored"
        assert isinstance(error, MonitoringError)


# ============================================================================
# Tests for MonitoringService Initialization
# ============================================================================


class TestMonitoringServiceInit:
    """Tests for MonitoringService initialization."""

    def test_init_with_explicit_db_path(
        self,
        mock_session_manager: SessionManager,
        temp_data_dir: Path,
        temp_db_path: Path,
    ) -> None:
        """Test initialization with explicit database path."""
        service = MonitoringService(
            session_manager=mock_session_manager,
            data_dir=temp_data_dir,
            db_path=temp_db_path,
        )

        assert service._session_manager is mock_session_manager
        assert service._data_dir == temp_data_dir
        assert service._loaders == {}
        assert service._db is not None

    def test_init_with_default_db_path(
        self,
        mock_session_manager: SessionManager,
        temp_data_dir: Path,
    ) -> None:
        """Test initialization with default database path."""
        service = MonitoringService(
            session_manager=mock_session_manager,
            data_dir=temp_data_dir,
        )

        assert service._session_manager is mock_session_manager
        assert service._data_dir == temp_data_dir
        assert service._loaders == {}


# ============================================================================
# Tests for _ensure_loader
# ============================================================================


class TestEnsureLoader:
    """Tests for _ensure_loader method."""

    def test_ensure_loader_success(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test ensuring loader for valid session."""
        session_id, _ = session_with_files

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            monitoring_service._ensure_loader(session_id)

            assert session_id in monitoring_service._loaders
            mock_loader.validate.assert_called_once()

    def test_ensure_loader_already_loaded(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test ensuring loader when already loaded."""
        session_id, _ = session_with_files

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            # First call
            monitoring_service._ensure_loader(session_id)
            # Second call
            monitoring_service._ensure_loader(session_id)

            # Should only create loader once
            assert mock_loader_cls.call_count == 1

    def test_ensure_loader_session_not_found(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test ensuring loader for non-existent session."""
        with pytest.raises(MonitoringError, match="not found"):
            monitoring_service._ensure_loader("nonexistent")

    def test_ensure_loader_missing_session_file(
        self,
        monitoring_service: MonitoringService,
        temp_data_dir: Path,
    ) -> None:
        """Test ensuring loader with missing session file."""
        session_dir = temp_data_dir / "incomplete"
        session_dir.mkdir()
        (session_dir / "config.json").write_text('{"api_id": 123, "api_hash": "abc"}')

        with pytest.raises(MonitoringError, match="not found"):
            monitoring_service._ensure_loader("incomplete")


# ============================================================================
# Tests for enable_monitoring
# ============================================================================


class TestEnableMonitoring:
    """Tests for enable_monitoring method."""

    @pytest.mark.asyncio
    async def test_enable_monitoring_new_chat(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
        fake_messages: list[Message],
    ) -> None:
        """Test enabling monitoring for a new chat."""
        session_id, _ = session_with_files
        chat_id = 123456

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch(
                "chatfilter.service.monitoring.get_messages",
                return_value=fake_messages,
            ) as mock_get_messages:
                result = await monitoring_service.enable_monitoring(
                    session_id, chat_id, initial_message_limit=1000
                )

            assert result.session_id == session_id
            assert result.chat_id == chat_id
            assert result.is_enabled is True
            assert result.message_count == len(fake_messages)
            assert result.unique_authors == 5  # 5 unique authors in fake_messages
            assert result.last_message_id == max(msg.id for msg in fake_messages)
            assert result.last_sync_at is not None
            mock_get_messages.assert_awaited_once_with(mock_client, chat_id, limit=1000)

    @pytest.mark.asyncio
    async def test_enable_monitoring_already_enabled(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test enabling monitoring for already monitored chat."""
        session_id, _ = session_with_files
        chat_id = 123456

        # Pre-create a monitor state
        existing_state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            message_count=100,
        )
        monitoring_service._db.save_monitor_state(existing_state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            result = await monitoring_service.enable_monitoring(session_id, chat_id)

            # Should return existing state without fetching messages
            assert result.session_id == session_id
            assert result.chat_id == chat_id
            assert result.message_count == 100

    @pytest.mark.asyncio
    async def test_enable_monitoring_re_enable_disabled(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test re-enabling a disabled monitor."""
        session_id, _ = session_with_files
        chat_id = 123456

        # Pre-create a disabled monitor state
        existing_state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=False,
            message_count=50,
        )
        monitoring_service._db.save_monitor_state(existing_state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            result = await monitoring_service.enable_monitoring(session_id, chat_id)

            # Should re-enable existing monitor
            assert result.session_id == session_id
            assert result.chat_id == chat_id
            assert result.is_enabled is True
            assert result.message_count == 50  # Preserves existing data

    @pytest.mark.asyncio
    async def test_enable_monitoring_empty_chat(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test enabling monitoring for chat with no messages."""
        session_id, _ = session_with_files
        chat_id = 999999

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch("chatfilter.service.monitoring.get_messages", return_value=[]):
                result = await monitoring_service.enable_monitoring(session_id, chat_id)

            assert result.message_count == 0
            assert result.unique_authors == 0
            assert result.last_message_id is None

    @pytest.mark.asyncio
    async def test_enable_monitoring_session_not_found(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test enabling monitoring with non-existent session."""
        with pytest.raises(MonitoringError, match="not found"):
            await monitoring_service.enable_monitoring("nonexistent", 123)


# ============================================================================
# Tests for disable_monitoring
# ============================================================================


class TestDisableMonitoring:
    """Tests for disable_monitoring method."""

    @pytest.mark.asyncio
    async def test_disable_monitoring_without_delete(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test disabling monitoring without deleting data."""
        session_id = "test-session"
        chat_id = 123456

        # Create a monitor state
        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        result = await monitoring_service.disable_monitoring(session_id, chat_id, delete_data=False)

        assert result is True
        loaded = monitoring_service._db.load_monitor_state(session_id, chat_id)
        assert loaded is not None
        assert loaded.is_enabled is False

    @pytest.mark.asyncio
    async def test_disable_monitoring_with_delete(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test disabling monitoring with data deletion."""
        session_id = "test-session"
        chat_id = 123456

        # Create a monitor state
        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        result = await monitoring_service.disable_monitoring(session_id, chat_id, delete_data=True)

        assert result is True
        loaded = monitoring_service._db.load_monitor_state(session_id, chat_id)
        assert loaded is None

    @pytest.mark.asyncio
    async def test_disable_monitoring_not_found(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test disabling non-existent monitor."""
        result = await monitoring_service.disable_monitoring("nonexistent", 999, delete_data=False)

        assert result is False

    @pytest.mark.asyncio
    async def test_disable_monitoring_delete_not_found(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test deleting non-existent monitor."""
        result = await monitoring_service.disable_monitoring("nonexistent", 999, delete_data=True)

        assert result is False


# ============================================================================
# Tests for sync_chat
# ============================================================================


class TestSyncChat:
    """Tests for sync_chat method."""

    @pytest.mark.asyncio
    async def test_sync_chat_with_new_messages(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
        fake_messages: list[Message],
    ) -> None:
        """Test syncing chat with new messages."""
        session_id, _ = session_with_files
        chat_id = 123456

        # Create existing monitor state
        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            message_count=100,
            unique_author_ids=[1, 2, 3],
            last_message_id=50,
        )
        monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            # Return subset of messages as "new"
            new_messages = fake_messages[:3]
            with patch(
                "chatfilter.service.monitoring.get_messages_since",
                return_value=new_messages,
            ) as mock_get_messages_since:
                snapshot = await monitoring_service.sync_chat(session_id, chat_id)

            assert snapshot.chat_id == chat_id
            assert snapshot.new_messages == len(new_messages)
            assert snapshot.message_count == 100 + len(new_messages)
            assert snapshot.sync_duration_seconds is not None
            mock_get_messages_since.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sync_chat_no_new_messages(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test syncing chat with no new messages."""
        session_id, _ = session_with_files
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            message_count=100,
            last_message_id=50,
        )
        monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch("chatfilter.service.monitoring.get_messages_since", return_value=[]):
                snapshot = await monitoring_service.sync_chat(session_id, chat_id)

            assert snapshot.new_messages == 0
            assert snapshot.message_count == 100

    @pytest.mark.asyncio
    async def test_sync_chat_first_sync(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
        fake_messages: list[Message],
    ) -> None:
        """Test syncing chat with no previous message ID (first sync)."""
        session_id, _ = session_with_files
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            last_message_id=None,  # No previous messages
        )
        monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch(
                "chatfilter.service.monitoring.get_messages",
                return_value=fake_messages,
            ) as mock_get_messages:
                snapshot = await monitoring_service.sync_chat(session_id, chat_id)

            assert snapshot.new_messages == len(fake_messages)
            mock_get_messages.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sync_chat_with_new_authors(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test syncing chat with new unique authors."""
        session_id, _ = session_with_files
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            message_count=50,
            unique_author_ids=[1, 2, 3],
            last_message_id=50,
        )
        monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            # Messages from existing and new authors
            now = datetime.now(UTC)
            new_messages = [
                Message(id=51, chat_id=chat_id, author_id=2, text="msg1", timestamp=now),
                Message(id=52, chat_id=chat_id, author_id=4, text="msg2", timestamp=now),
                Message(id=53, chat_id=chat_id, author_id=5, text="msg3", timestamp=now),
            ]

            with patch(
                "chatfilter.service.monitoring.get_messages_since",
                return_value=new_messages,
            ):
                snapshot = await monitoring_service.sync_chat(session_id, chat_id)

            assert snapshot.new_authors == 2  # Authors 4 and 5 are new
            assert snapshot.unique_authors == 5  # Total: 1,2,3,4,5

    @pytest.mark.asyncio
    async def test_sync_chat_not_monitored(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test syncing chat that is not being monitored."""
        session_id, _ = session_with_files

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            with pytest.raises(MonitorNotFoundError, match="not being monitored"):
                await monitoring_service.sync_chat(session_id, 999999)

    @pytest.mark.asyncio
    async def test_sync_chat_disabled(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test syncing disabled monitor."""
        session_id, _ = session_with_files
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=False,
        )
        monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            with pytest.raises(MonitoringError, match="disabled"):
                await monitoring_service.sync_chat(session_id, chat_id)

    @pytest.mark.asyncio
    async def test_sync_chat_updates_timestamps(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test that sync updates first_message_at when None."""
        session_id, _ = session_with_files
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            last_message_id=None,
            first_message_at=None,
        )
        monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            now = datetime.now(UTC)
            messages = [
                Message(id=1, chat_id=chat_id, author_id=1, text="msg", timestamp=now),
            ]

            with patch("chatfilter.service.monitoring.get_messages", return_value=messages):
                await monitoring_service.sync_chat(session_id, chat_id)

            updated_state = monitoring_service._db.load_monitor_state(session_id, chat_id)
            assert updated_state is not None
            assert updated_state.first_message_at is not None


# ============================================================================
# Tests for sync_all_enabled
# ============================================================================


class TestSyncAllEnabled:
    """Tests for sync_all_enabled method."""

    @pytest.mark.asyncio
    async def test_sync_all_enabled_multiple_chats(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test syncing all enabled monitors."""
        session_id, _ = session_with_files

        # Create multiple enabled monitors
        for chat_id in [100, 200, 300]:
            state = ChatMonitorState(
                session_id=session_id,
                chat_id=chat_id,
                is_enabled=True,
                last_message_id=50,
            )
            monitoring_service._db.save_monitor_state(state)

        # Create one disabled monitor (should be skipped)
        disabled_state = ChatMonitorState(
            session_id=session_id,
            chat_id=400,
            is_enabled=False,
        )
        monitoring_service._db.save_monitor_state(disabled_state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch("chatfilter.service.monitoring.get_messages_since", return_value=[]):
                snapshots = await monitoring_service.sync_all_enabled(session_id)

        assert len(snapshots) == 3  # Only enabled monitors
        assert all(isinstance(s, SyncSnapshot) for s in snapshots)

    @pytest.mark.asyncio
    async def test_sync_all_enabled_with_failures(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test sync_all_enabled continues on individual failures."""
        session_id, _ = session_with_files

        # Create two monitors
        for chat_id in [100, 200]:
            state = ChatMonitorState(
                session_id=session_id,
                chat_id=chat_id,
                is_enabled=True,
                last_message_id=50,
            )
            monitoring_service._db.save_monitor_state(state)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            call_count = 0

            async def mock_get_messages_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise Exception("Network error")
                return []

            with patch(
                "chatfilter.service.monitoring.get_messages_since",
                side_effect=mock_get_messages_side_effect,
            ):
                snapshots = await monitoring_service.sync_all_enabled(session_id)

        # Should have one successful sync despite one failure
        assert len(snapshots) == 1

    @pytest.mark.asyncio
    async def test_sync_all_enabled_no_monitors(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test sync_all_enabled with no enabled monitors."""
        snapshots = await monitoring_service.sync_all_enabled("nonexistent-session")

        assert snapshots == []


# ============================================================================
# Tests for get_monitor_state
# ============================================================================


class TestGetMonitorState:
    """Tests for get_monitor_state method."""

    def test_get_monitor_state_exists(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting existing monitor state."""
        session_id = "test-session"
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            message_count=100,
        )
        monitoring_service._db.save_monitor_state(state)

        result = monitoring_service.get_monitor_state(session_id, chat_id)

        assert result is not None
        assert result.session_id == session_id
        assert result.chat_id == chat_id
        assert result.message_count == 100

    def test_get_monitor_state_not_found(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting non-existent monitor state."""
        result = monitoring_service.get_monitor_state("nonexistent", 999)

        assert result is None


# ============================================================================
# Tests for list_monitors
# ============================================================================


class TestListMonitors:
    """Tests for list_monitors method."""

    def test_list_monitors_all(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test listing all monitors."""
        session_id = "test-session"

        # Create enabled and disabled monitors
        for i, enabled in enumerate([True, False, True]):
            state = ChatMonitorState(
                session_id=session_id,
                chat_id=100 + i,
                is_enabled=enabled,
            )
            monitoring_service._db.save_monitor_state(state)

        result = monitoring_service.list_monitors(session_id, enabled_only=False)

        assert len(result) == 3

    def test_list_monitors_enabled_only(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test listing only enabled monitors."""
        session_id = "test-session"

        # Create enabled and disabled monitors
        for i, enabled in enumerate([True, False, True]):
            state = ChatMonitorState(
                session_id=session_id,
                chat_id=100 + i,
                is_enabled=enabled,
            )
            monitoring_service._db.save_monitor_state(state)

        result = monitoring_service.list_monitors(session_id, enabled_only=True)

        assert len(result) == 2
        assert all(m.is_enabled for m in result)

    def test_list_monitors_empty(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test listing monitors for session with none."""
        result = monitoring_service.list_monitors("nonexistent")

        assert result == []


# ============================================================================
# Tests for get_monitoring_summary
# ============================================================================


class TestGetMonitoringSummary:
    """Tests for get_monitoring_summary method."""

    def test_get_monitoring_summary_with_data(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting monitoring summary with data."""
        session_id = "test-session"
        chat_id = 123456

        now = datetime.now(UTC)
        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            message_count=100,
            unique_author_ids=[1, 2, 3],
            last_sync_at=now,
            first_message_at=now - timedelta(hours=24),
            last_message_at=now,
        )
        monitoring_service._db.save_monitor_state(state)

        # Add some snapshots
        for i in range(5):
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=3,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        result = monitoring_service.get_monitoring_summary(
            session_id, chat_id, chat_title="Test Chat"
        )

        assert result is not None
        assert isinstance(result, MonitoringSummary)
        assert result.session_id == session_id
        assert result.chat_id == chat_id
        assert result.chat_title == "Test Chat"
        assert result.is_enabled is True
        assert result.message_count == 100
        assert result.unique_authors == 3
        assert result.sync_count == 5

    def test_get_monitoring_summary_not_found(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting summary for non-existent monitor."""
        result = monitoring_service.get_monitoring_summary("nonexistent", 999)

        assert result is None


# ============================================================================
# Tests for get_growth_metrics
# ============================================================================


class TestGetGrowthMetrics:
    """Tests for get_growth_metrics method."""

    def test_get_growth_metrics_with_data(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting growth metrics with snapshot data."""
        session_id = "test-session"
        chat_id = 123456

        # Create monitor state
        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        # Create snapshots over 24 hours
        now = datetime.now(UTC)
        for i in range(24):
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=23 - i),
                message_count=100 + i * 10,
                unique_authors=10 + i,
                new_messages=10,
                new_authors=1,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        result = monitoring_service.get_growth_metrics(session_id, chat_id, hours=24.0)

        assert result is not None
        assert isinstance(result, GrowthMetrics)
        assert result.chat_id == chat_id
        assert result.total_new_messages == 24 * 10
        assert result.total_new_authors == 24 * 1
        assert result.messages_per_hour > 0
        assert result.author_growth_rate > 0
        assert len(result.snapshots) == 24

    def test_get_growth_metrics_no_data(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting growth metrics with no snapshots."""
        result = monitoring_service.get_growth_metrics("nonexistent", 999)

        assert result is None

    def test_get_growth_metrics_custom_period(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting growth metrics for custom time period."""
        session_id = "test-session"
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        # Create snapshots
        now = datetime.now(UTC)
        for i in range(10):
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=9 - i),
                message_count=100,
                unique_authors=10,
                new_messages=5,
                new_authors=0,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        result = monitoring_service.get_growth_metrics(session_id, chat_id, hours=6.0)

        assert result is not None
        # Should only include snapshots from last 6 hours
        assert len(result.snapshots) <= 7


# ============================================================================
# Tests for get_snapshots
# ============================================================================


class TestGetSnapshots:
    """Tests for get_snapshots method."""

    def test_get_snapshots_all(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting all snapshots."""
        session_id = "test-session"
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(10):
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        result = monitoring_service.get_snapshots(session_id, chat_id)

        assert len(result) == 10
        # Should be newest first
        assert result[0].sync_at > result[-1].sync_at

    def test_get_snapshots_with_since(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting snapshots since a specific time."""
        session_id = "test-session"
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(10):
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        since = now - timedelta(hours=5)
        result = monitoring_service.get_snapshots(session_id, chat_id, since=since)

        assert len(result) <= 6  # Last 5 hours + current

    def test_get_snapshots_with_limit(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting snapshots with limit."""
        session_id = "test-session"
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        now = datetime.now(UTC)
        for i in range(10):
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        result = monitoring_service.get_snapshots(session_id, chat_id, limit=5)

        assert len(result) == 5

    def test_get_snapshots_empty(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test getting snapshots for chat with none."""
        result = monitoring_service.get_snapshots("nonexistent", 999)

        assert result == []


# ============================================================================
# Tests for Global Service Singleton
# ============================================================================


class TestGlobalMonitoringService:
    """Tests for global monitoring service singleton."""

    def test_get_monitoring_service_first_call(
        self,
        mock_session_manager: SessionManager,
        temp_data_dir: Path,
    ) -> None:
        """Test getting monitoring service on first call."""
        reset_monitoring_service()  # Ensure clean state

        service = get_monitoring_service(
            session_manager=mock_session_manager,
            data_dir=temp_data_dir,
        )

        assert service is not None
        assert isinstance(service, MonitoringService)

    def test_get_monitoring_service_subsequent_call(
        self,
        mock_session_manager: SessionManager,
        temp_data_dir: Path,
    ) -> None:
        """Test getting monitoring service on subsequent calls."""
        reset_monitoring_service()

        service1 = get_monitoring_service(
            session_manager=mock_session_manager,
            data_dir=temp_data_dir,
        )
        service2 = get_monitoring_service()

        assert service1 is service2  # Should be same instance

    def test_get_monitoring_service_without_init(self) -> None:
        """Test getting service without initialization raises error."""
        reset_monitoring_service()

        with pytest.raises(ValueError, match="required on first call"):
            get_monitoring_service()

    def test_reset_monitoring_service(
        self,
        mock_session_manager: SessionManager,
        temp_data_dir: Path,
    ) -> None:
        """Test resetting global monitoring service."""
        reset_monitoring_service()

        service1 = get_monitoring_service(
            session_manager=mock_session_manager,
            data_dir=temp_data_dir,
        )

        reset_monitoring_service()

        service2 = get_monitoring_service(
            session_manager=mock_session_manager,
            data_dir=temp_data_dir,
        )

        assert service1 is not service2  # Should be different instances


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


class TestEdgeCasesAndErrors:
    """Tests for edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_enable_monitoring_with_duplicate_authors(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test enabling monitoring with duplicate authors."""
        session_id, _ = session_with_files
        chat_id = 123456

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            # Messages with duplicate author IDs
            now = datetime.now(UTC)
            messages = [
                Message(id=1, chat_id=chat_id, author_id=100, text="msg1", timestamp=now),
                Message(id=2, chat_id=chat_id, author_id=100, text="msg2", timestamp=now),
                Message(id=3, chat_id=chat_id, author_id=200, text="msg3", timestamp=now),
            ]

            with patch("chatfilter.service.monitoring.get_messages", return_value=messages):
                result = await monitoring_service.enable_monitoring(session_id, chat_id)

            # Should count unique authors correctly
            assert result.message_count == 3
            assert result.unique_authors == 2  # Only 2 unique authors

    @pytest.mark.asyncio
    async def test_sync_chat_cleanup_old_snapshots(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
    ) -> None:
        """Test that sync_chat cleans up old snapshots."""
        session_id, _ = session_with_files
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
            last_message_id=1,
        )
        monitoring_service._db.save_monitor_state(state)

        # Create many old snapshots
        now = datetime.now(UTC)
        for i in range(1100):  # More than keep_count of 1000
            snapshot = SyncSnapshot(
                chat_id=chat_id,
                sync_at=now - timedelta(hours=i),
                message_count=100,
                unique_authors=10,
            )
            monitoring_service._db.save_snapshot(session_id, snapshot)

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch("chatfilter.service.monitoring.get_messages_since", return_value=[]):
                await monitoring_service.sync_chat(session_id, chat_id)

        # Check that old snapshots were deleted
        count = monitoring_service._db.count_snapshots(session_id, chat_id)
        assert count <= 1001  # 1000 kept + 1 new

    @pytest.mark.asyncio
    async def test_enable_monitoring_preserves_snapshot_creation(
        self,
        monitoring_service: MonitoringService,
        session_with_files: tuple[str, Path],
        fake_messages: list[Message],
    ) -> None:
        """Test that enable_monitoring creates a snapshot."""
        session_id, _ = session_with_files
        chat_id = 123456

        with patch("chatfilter.telegram.client.TelegramClientLoader") as mock_loader_cls:
            mock_loader = mock_loader_cls.return_value
            mock_loader.validate.return_value = None

            mock_client = AsyncMock()
            mock_session_ctx = AsyncMock()
            mock_session_ctx.__aenter__.return_value = mock_client
            mock_session_ctx.__aexit__.return_value = None
            monitoring_service._session_manager.session.return_value = mock_session_ctx

            with patch(
                "chatfilter.service.monitoring.get_messages",
                return_value=fake_messages,
            ):
                await monitoring_service.enable_monitoring(session_id, chat_id)

        # Check snapshot was created
        snapshots = monitoring_service._db.load_snapshots(session_id, chat_id)
        assert len(snapshots) == 1
        assert snapshots[0].message_count == len(fake_messages)

    def test_get_growth_metrics_zero_period_hours(
        self,
        monitoring_service: MonitoringService,
    ) -> None:
        """Test growth metrics with very small period hours."""
        session_id = "test-session"
        chat_id = 123456

        state = ChatMonitorState(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=True,
        )
        monitoring_service._db.save_monitor_state(state)

        # Create snapshot with same sync_at (effectively very small time period)
        now = datetime.now(UTC)
        snapshot = SyncSnapshot(
            chat_id=chat_id,
            sync_at=now,
            message_count=100,
            unique_authors=10,
            new_messages=50,
            new_authors=5,
        )
        monitoring_service._db.save_snapshot(session_id, snapshot)

        result = monitoring_service.get_growth_metrics(session_id, chat_id, hours=24.0)

        assert result is not None
        # Period hours will be very small but not exactly zero due to execution time
        assert result.period_hours < 0.01
        # Rates will be high due to small period
        assert result.messages_per_hour > 0.0
        assert result.author_growth_rate > 0.0
