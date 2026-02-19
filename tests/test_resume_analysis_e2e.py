"""E2E test for resuming paused group analysis.

This test verifies that:
1. Resume endpoint exists and handles POST requests correctly
2. Only pending and failed chats are selected for reanalysis (done chats skipped)
3. Status transitions PAUSED → IN_PROGRESS
4. Idempotency: concurrent requests return 409
5. Validation: non-paused/empty groups return appropriate errors
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

if TYPE_CHECKING:
    pass


@pytest.mark.asyncio
async def test_resume_paused_group_analyzes_only_pending_and_failed(tmp_path: Path) -> None:
    """Test that resume only analyzes pending + failed chats, skips done chats.

    Creates group with:
    - 10 done chats
    - 5 pending chats
    - 2 failed chats

    Verifies that only 7 chats (5 pending + 2 failed) are passed to start_analysis.
    """
    from chatfilter.models.group import GroupChatStatus, GroupStatus
    from chatfilter.service.group_service import GroupService
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.web.routers.groups import resume_group_analysis

    # Setup: Create test database and group
    db = GroupDatabase(tmp_path / "groups.db")
    service = GroupService(db)

    # Create group with 17 chats
    chat_refs = [f"@chat_{i}" for i in range(17)]
    group = service.create_group("Test Resume Group", chat_refs)
    group_id = group.id

    # Get all chats to obtain their IDs
    all_chats = db.load_chats(group_id)
    chat_id_map = {chat["chat_ref"]: chat["id"] for chat in all_chats}

    # Mark first 10 as done
    for i in range(10):
        db.update_chat_status(
            chat_id=chat_id_map[chat_refs[i]],
            status=GroupChatStatus.DONE.value,
        )

    # Next 5 are pending (default status)
    # Mark last 2 as failed
    for i in range(15, 17):
        db.update_chat_status(
            chat_id=chat_id_map[chat_refs[i]],
            status=GroupChatStatus.FAILED.value,
        )

    # Set group status to PAUSED
    service.update_status(group_id, GroupStatus.PAUSED)

    # Verify initial state
    stats = service.get_group_stats(group_id)
    assert stats.analyzed == 10  # status DONE
    assert stats.status_pending == 5  # status PENDING
    assert stats.failed == 2  # status FAILED

    # Mock request with necessary state
    mock_request = MagicMock()
    mock_request.app.state.app_state.analysis_tasks = {}

    # Mock session manager
    mock_session_manager = MagicMock()
    mock_session_manager.list_sessions.return_value = ["test_session"]

    async def mock_is_healthy(session_id: str) -> bool:
        return True

    mock_session_manager.is_healthy = mock_is_healthy
    mock_request.app.state.app_state.session_manager = mock_session_manager

    # Mock GroupAnalysisEngine to track what gets analyzed
    analyzed_chats = []

    async def mock_start_analysis(group_id_arg: str, **kwargs) -> None:
        """Record which chats would be analyzed."""
        chats = db.load_chats(group_id_arg)
        for chat in chats:
            if chat["status"] in (GroupChatStatus.PENDING.value, GroupChatStatus.FAILED.value):
                analyzed_chats.append(chat["chat_ref"])
        await asyncio.sleep(0.001)  # Simulate async work

    mock_engine = MagicMock()
    mock_engine.start_analysis = AsyncMock(side_effect=mock_start_analysis)

    # Mock _get_group_service and _get_group_engine
    from unittest.mock import patch

    with patch("chatfilter.web.routers.groups._get_group_service", return_value=service), \
         patch("chatfilter.web.routers.groups._get_group_engine", return_value=mock_engine):

        # Call resume endpoint
        response = await resume_group_analysis(mock_request, group_id)

        # Verify response
        assert response.status_code == 204
        assert "HX-Trigger" in response.headers
        assert "refreshGroups" in response.headers["HX-Trigger"]

        # Verify status changed to IN_PROGRESS
        updated_group = service.get_group(group_id)
        assert updated_group.status == GroupStatus.IN_PROGRESS

        # Verify start_analysis was called
        mock_engine.start_analysis.assert_called_once_with(group_id)

        # Wait for background task to complete
        task = mock_request.app.state.app_state.analysis_tasks.get(group_id)
        if task:
            await task

    # Verify only 7 chats (pending + failed) were selected for analysis
    assert len(analyzed_chats) == 7
    # Verify done chats are NOT in analyzed list
    for i in range(10):
        assert chat_refs[i] not in analyzed_chats


@pytest.mark.asyncio
async def test_resume_non_paused_group_returns_400(tmp_path: Path) -> None:
    """Test that resume returns 400 if group is not paused."""
    from chatfilter.models.group import GroupStatus
    from chatfilter.service.group_service import GroupService
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.web.routers.groups import resume_group_analysis

    # Setup
    db = GroupDatabase(tmp_path / "groups.db")
    service = GroupService(db)

    group = service.create_group("Test Group", ["@chat1"])
    group_id = group.id

    # Group is PENDING by default (not PAUSED)
    assert service.get_group(group_id).status == GroupStatus.PENDING

    # Mock request
    mock_request = MagicMock()
    mock_request.app.state.app_state.session_manager = MagicMock()

    from unittest.mock import patch

    with patch("chatfilter.web.routers.groups._get_group_service", return_value=service):
        response = await resume_group_analysis(mock_request, group_id)

        # Verify 400 error
        assert response.status_code == 400
        assert "HX-Trigger" in response.headers


@pytest.mark.asyncio
async def test_resume_empty_group_returns_400(tmp_path: Path) -> None:
    """Test that resume returns 400 if no chats to analyze (all done)."""
    from chatfilter.models.group import GroupChatStatus, GroupStatus
    from chatfilter.service.group_service import GroupService
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.web.routers.groups import resume_group_analysis

    # Setup
    db = GroupDatabase(tmp_path / "groups.db")
    service = GroupService(db)

    chat_refs = ["@chat1", "@chat2"]
    group = service.create_group("Test Group", chat_refs)
    group_id = group.id

    # Get chat IDs
    all_chats = db.load_chats(group_id)
    chat_id_map = {chat["chat_ref"]: chat["id"] for chat in all_chats}

    # Mark all chats as done
    for ref in chat_refs:
        db.update_chat_status(
            chat_id=chat_id_map[ref],
            status=GroupChatStatus.DONE.value,
        )

    # Set status to PAUSED
    service.update_status(group_id, GroupStatus.PAUSED)

    # Mock request
    mock_request = MagicMock()
    mock_request.app.state.app_state.session_manager = MagicMock()

    from unittest.mock import patch

    with patch("chatfilter.web.routers.groups._get_group_service", return_value=service):
        response = await resume_group_analysis(mock_request, group_id)

        # Verify 400 error (no chats to analyze)
        assert response.status_code == 400
        assert "HX-Trigger" in response.headers


@pytest.mark.asyncio
async def test_resume_concurrent_requests_return_409(tmp_path: Path) -> None:
    """Test that concurrent resume requests return 409 (idempotency via atomic update)."""
    from chatfilter.models.group import GroupStatus
    from chatfilter.service.group_service import GroupService
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.web.routers.groups import resume_group_analysis

    # Setup
    db = GroupDatabase(tmp_path / "groups.db")
    service = GroupService(db)

    group = service.create_group("Test Group", ["@chat1"])
    group_id = group.id
    service.update_status(group_id, GroupStatus.PAUSED)

    # Mock request with session manager
    mock_request = MagicMock()
    mock_request.app.state.app_state.analysis_tasks = {}

    mock_session_manager = MagicMock()
    mock_session_manager.list_sessions.return_value = ["test_session"]

    async def mock_is_healthy(session_id: str) -> bool:
        return True

    mock_session_manager.is_healthy = mock_is_healthy
    mock_request.app.state.app_state.session_manager = mock_session_manager

    # Mock engine
    mock_engine = MagicMock()

    async def slow_analysis(group_id_arg: str, **kwargs) -> None:
        await asyncio.sleep(0.5)

    mock_engine.start_analysis = AsyncMock(side_effect=slow_analysis)

    from unittest.mock import patch

    with patch("chatfilter.web.routers.groups._get_group_service", return_value=service), \
         patch("chatfilter.web.routers.groups._get_group_engine", return_value=mock_engine):

        # First request succeeds
        response1 = await resume_group_analysis(mock_request, group_id)
        assert response1.status_code == 204

        # Status now IN_PROGRESS
        assert service.get_group(group_id).status == GroupStatus.IN_PROGRESS

        # Second concurrent request should fail with 409 (atomic update fails)
        response2 = await resume_group_analysis(mock_request, group_id)
        assert response2.status_code == 409
        assert "HX-Trigger" in response2.headers


@pytest.mark.asyncio
async def test_resume_nonexistent_group_returns_404(tmp_path: Path) -> None:
    """Test that resume returns 404 for non-existent group."""
    from chatfilter.service.group_service import GroupService
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.web.routers.groups import resume_group_analysis

    # Setup
    db = GroupDatabase(tmp_path / "groups.db")
    service = GroupService(db)

    # Mock request
    mock_request = MagicMock()
    mock_request.app.state.app_state.session_manager = MagicMock()

    from unittest.mock import patch

    with patch("chatfilter.web.routers.groups._get_group_service", return_value=service):
        response = await resume_group_analysis(mock_request, "nonexistent-id")

        # Verify 404 error
        assert response.status_code == 404
        assert "HX-Trigger" in response.headers
