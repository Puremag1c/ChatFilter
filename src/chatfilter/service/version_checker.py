"""Version checking service for application updates.

This module provides functionality to check for new versions of the application
by querying the GitHub releases API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class VersionInfo:
    """Information about a version."""

    version: str
    """Version string (e.g., '0.2.0')"""

    tag_name: str
    """Git tag name (e.g., 'v0.2.0')"""

    published_at: datetime
    """Release publication date"""

    html_url: str
    """URL to the release page"""

    release_notes: str
    """Release notes/description"""

    is_prerelease: bool = False
    """Whether this is a pre-release version"""


@dataclass
class UpdateCheckResult:
    """Result of an update check."""

    current_version: str
    """Current application version"""

    latest_version: VersionInfo | None
    """Latest available version, if any"""

    update_available: bool
    """Whether an update is available"""

    error: str | None = None
    """Error message if check failed"""


class VersionChecker:
    """Service for checking application version updates.

    This service queries the GitHub releases API to check if a new version
    of the application is available.

    Args:
        github_repo: GitHub repository in format 'owner/repo'
        current_version: Current application version
        timeout: HTTP request timeout in seconds
    """

    def __init__(
        self,
        github_repo: str,
        current_version: str,
        timeout: float = 10.0,
    ) -> None:
        """Initialize version checker."""
        self.github_repo = github_repo
        self.current_version = current_version
        self.timeout = timeout
        self._api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"

    async def check_for_updates(
        self,
        include_prereleases: bool = False,
    ) -> UpdateCheckResult:
        """Check for available updates.

        Args:
            include_prereleases: Whether to include pre-release versions

        Returns:
            UpdateCheckResult with information about available updates
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self._api_url,
                    headers={
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )

                if response.status_code == 404:
                    logger.info("No releases found for repository %s", self.github_repo)
                    return UpdateCheckResult(
                        current_version=self.current_version,
                        latest_version=None,
                        update_available=False,
                    )

                response.raise_for_status()
                release_data = response.json()

                # Skip pre-releases if not requested
                if release_data.get("prerelease", False) and not include_prereleases:
                    logger.debug("Latest release is a pre-release, skipping")
                    return UpdateCheckResult(
                        current_version=self.current_version,
                        latest_version=None,
                        update_available=False,
                    )

                # Parse release information
                latest_version = self._parse_version_info(release_data)

                # Compare versions
                update_available = self._is_newer_version(
                    latest_version.version,
                    self.current_version,
                )

                logger.info(
                    "Version check complete: current=%s, latest=%s, update_available=%s",
                    self.current_version,
                    latest_version.version,
                    update_available,
                )

                return UpdateCheckResult(
                    current_version=self.current_version,
                    latest_version=latest_version,
                    update_available=update_available,
                )

        except httpx.HTTPError as e:
            logger.error("HTTP error while checking for updates: %s", e)
            return UpdateCheckResult(
                current_version=self.current_version,
                latest_version=None,
                update_available=False,
                error=f"HTTP error: {e}",
            )
        except Exception as e:
            logger.error("Unexpected error while checking for updates: %s", e)
            return UpdateCheckResult(
                current_version=self.current_version,
                latest_version=None,
                update_available=False,
                error=f"Error: {e}",
            )

    def _parse_version_info(self, release_data: dict[str, Any]) -> VersionInfo:
        """Parse GitHub release data into VersionInfo.

        Args:
            release_data: GitHub API release response

        Returns:
            VersionInfo object
        """
        tag_name = release_data["tag_name"]
        # Remove 'v' prefix if present
        version = tag_name.lstrip("v")

        published_at_str = release_data.get("published_at", "")
        published_at = (
            datetime.fromisoformat(published_at_str.replace("Z", "+00:00"))
            if published_at_str
            else datetime.now(UTC)
        )

        return VersionInfo(
            version=version,
            tag_name=tag_name,
            published_at=published_at,
            html_url=release_data.get("html_url", ""),
            release_notes=release_data.get("body", ""),
            is_prerelease=release_data.get("prerelease", False),
        )

    def _is_newer_version(self, remote_version: str, local_version: str) -> bool:
        """Compare versions to determine if remote is newer.

        Args:
            remote_version: Version from GitHub
            local_version: Current application version

        Returns:
            True if remote version is newer
        """
        try:
            # Simple version comparison (assumes semantic versioning)
            remote_parts = [int(x) for x in remote_version.split(".")]
            local_parts = [int(x) for x in local_version.split(".")]

            # Pad shorter version with zeros
            max_len = max(len(remote_parts), len(local_parts))
            remote_parts.extend([0] * (max_len - len(remote_parts)))
            local_parts.extend([0] * (max_len - len(local_parts)))

            return remote_parts > local_parts
        except (ValueError, AttributeError):
            logger.warning(
                "Could not compare versions: remote=%s, local=%s",
                remote_version,
                local_version,
            )
            return False
