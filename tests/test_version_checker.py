"""Tests for version checker service.

Tests cover:
- VersionInfo: version information dataclass
- UpdateCheckResult: update check result
- VersionChecker: update checking functionality
- Version comparison logic
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from chatfilter.service.version_checker import (
    UpdateCheckResult,
    VersionChecker,
    VersionInfo,
)


class TestVersionInfo:
    """Tests for VersionInfo dataclass."""

    def test_creation(self) -> None:
        """VersionInfo should initialize with correct values."""
        now = datetime.now(UTC)
        info = VersionInfo(
            version="1.2.3",
            tag_name="v1.2.3",
            published_at=now,
            html_url="https://github.com/test/repo/releases/tag/v1.2.3",
            release_notes="Bug fixes",
            is_prerelease=False,
        )

        assert info.version == "1.2.3"
        assert info.tag_name == "v1.2.3"
        assert info.published_at == now
        assert info.html_url == "https://github.com/test/repo/releases/tag/v1.2.3"
        assert info.release_notes == "Bug fixes"
        assert info.is_prerelease is False

    def test_prerelease_default(self) -> None:
        """is_prerelease should default to False."""
        info = VersionInfo(
            version="1.0.0",
            tag_name="v1.0.0",
            published_at=datetime.now(UTC),
            html_url="",
            release_notes="",
        )

        assert info.is_prerelease is False


class TestUpdateCheckResult:
    """Tests for UpdateCheckResult dataclass."""

    def test_creation(self) -> None:
        """UpdateCheckResult should initialize with correct values."""
        result = UpdateCheckResult(
            current_version="1.0.0",
            latest_version=None,
            update_available=False,
        )

        assert result.current_version == "1.0.0"
        assert result.latest_version is None
        assert result.update_available is False
        assert result.error is None

    def test_with_error(self) -> None:
        """UpdateCheckResult should store error message."""
        result = UpdateCheckResult(
            current_version="1.0.0",
            latest_version=None,
            update_available=False,
            error="Connection failed",
        )

        assert result.error == "Connection failed"


class TestVersionChecker:
    """Tests for VersionChecker class."""

    @pytest.fixture
    def checker(self) -> VersionChecker:
        """Create a version checker instance."""
        return VersionChecker(
            github_repo="owner/repo",
            current_version="1.0.0",
            timeout=5.0,
        )

    def test_initialization(self, checker: VersionChecker) -> None:
        """Should initialize with correct values."""
        assert checker.github_repo == "owner/repo"
        assert checker.current_version == "1.0.0"
        assert checker.timeout == 5.0
        assert "api.github.com" in checker._api_url

    def test_is_newer_version_true(self, checker: VersionChecker) -> None:
        """Should detect newer versions correctly."""
        assert checker._is_newer_version("2.0.0", "1.0.0") is True
        assert checker._is_newer_version("1.1.0", "1.0.0") is True
        assert checker._is_newer_version("1.0.1", "1.0.0") is True

    def test_is_newer_version_false(self, checker: VersionChecker) -> None:
        """Should detect same or older versions."""
        assert checker._is_newer_version("1.0.0", "1.0.0") is False
        assert checker._is_newer_version("0.9.0", "1.0.0") is False
        assert checker._is_newer_version("1.0.0", "2.0.0") is False

    def test_is_newer_version_different_lengths(self, checker: VersionChecker) -> None:
        """Should handle version strings of different lengths."""
        assert checker._is_newer_version("1.0.0.1", "1.0.0") is True
        assert checker._is_newer_version("1.0", "1.0.0") is False

    def test_is_newer_version_invalid(self, checker: VersionChecker) -> None:
        """Should handle invalid version strings gracefully."""
        assert checker._is_newer_version("invalid", "1.0.0") is False
        assert checker._is_newer_version("1.0.0", "invalid") is False

    def test_parse_version_info(self, checker: VersionChecker) -> None:
        """Should parse GitHub release data correctly."""
        release_data = {
            "tag_name": "v2.0.0",
            "published_at": "2024-01-15T10:00:00Z",
            "html_url": "https://github.com/owner/repo/releases/tag/v2.0.0",
            "body": "Release notes here",
            "prerelease": False,
        }

        info = checker._parse_version_info(release_data)

        assert info.version == "2.0.0"  # v prefix removed
        assert info.tag_name == "v2.0.0"
        assert info.html_url == "https://github.com/owner/repo/releases/tag/v2.0.0"
        assert info.release_notes == "Release notes here"
        assert info.is_prerelease is False

    def test_parse_version_info_prerelease(self, checker: VersionChecker) -> None:
        """Should detect pre-release versions."""
        release_data = {
            "tag_name": "v2.0.0-beta",
            "published_at": "2024-01-15T10:00:00Z",
            "html_url": "",
            "body": "",
            "prerelease": True,
        }

        info = checker._parse_version_info(release_data)

        assert info.is_prerelease is True

    @pytest.mark.asyncio
    async def test_check_for_updates_newer_available(self, checker: VersionChecker) -> None:
        """Should detect when update is available."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "tag_name": "v2.0.0",
            "published_at": "2024-01-15T10:00:00Z",
            "html_url": "https://github.com/owner/repo/releases/tag/v2.0.0",
            "body": "New features",
            "prerelease": False,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await checker.check_for_updates()

            assert result.update_available is True
            assert result.latest_version is not None
            assert result.latest_version.version == "2.0.0"

    @pytest.mark.asyncio
    async def test_check_for_updates_no_update(self, checker: VersionChecker) -> None:
        """Should detect when no update is available."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "tag_name": "v1.0.0",
            "published_at": "2024-01-15T10:00:00Z",
            "html_url": "",
            "body": "",
            "prerelease": False,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await checker.check_for_updates()

            assert result.update_available is False

    @pytest.mark.asyncio
    async def test_check_for_updates_404(self, checker: VersionChecker) -> None:
        """Should handle 404 (no releases) gracefully."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await checker.check_for_updates()

            assert result.update_available is False
            assert result.latest_version is None
            assert result.error is None

    @pytest.mark.asyncio
    async def test_check_for_updates_http_error(self, checker: VersionChecker) -> None:
        """Should handle HTTP errors gracefully."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.HTTPError("Connection failed"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await checker.check_for_updates()

            assert result.update_available is False
            assert result.error is not None
            assert "HTTP error" in result.error

    @pytest.mark.asyncio
    async def test_check_for_updates_skips_prerelease(self, checker: VersionChecker) -> None:
        """Should skip pre-releases by default."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "tag_name": "v2.0.0-beta",
            "published_at": "2024-01-15T10:00:00Z",
            "html_url": "",
            "body": "",
            "prerelease": True,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client

            result = await checker.check_for_updates()

            assert result.update_available is False
