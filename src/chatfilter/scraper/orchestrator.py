"""Search orchestrator: coordinates platform searches and deduplicates results."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from chatfilter.ai.billing import InsufficientBalance
from chatfilter.models.group import (
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.scraper.base import PlatformSearchResult

if TYPE_CHECKING:
    from chatfilter.ai.billing import BillingService
    from chatfilter.scraper.base import BasePlatform
    from chatfilter.scraper.query_generator import QueryGenerator
    from chatfilter.scraper.registry import PlatformRegistry
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

# In-memory scraping progress tracker: group_id → progress dict
# Each entry: {"platforms": {platform_id: {"status": str, "chats_found": int}}, "total_found": int}
_scraping_progress: dict[str, dict[str, Any]] = {}

# In-memory scraping result store: group_id → result summary
# Stored after scraping completes, consumed once by the polling endpoint to show toast.
_scraping_results: dict[str, dict[str, Any]] = {}


def get_scraping_progress(group_id: str) -> dict[str, Any] | None:
    """Return current scraping progress for a group, or None if not tracked."""
    return _scraping_progress.get(group_id)


def init_scraping_progress(group_id: str, platform_ids: list[str]) -> None:
    """Pre-initialize progress before the asyncio task starts.

    Called before asyncio.create_task() so the first poll always finds platform info.
    The orchestrator will overwrite this once platforms are resolved.
    """
    _scraping_progress[group_id] = {
        "platforms": {pid: {"status": "searching", "chats_found": 0} for pid in platform_ids},
        "total_found": 0,
    }


def clear_scraping_progress(group_id: str) -> None:
    """Remove progress entry once no longer needed."""
    _scraping_progress.pop(group_id, None)


def get_scraping_result(group_id: str) -> dict[str, Any] | None:
    """Pop the scraping result for a group (consumed once by the polling endpoint)."""
    return _scraping_results.pop(group_id, None)


def store_scraping_result(group_id: str, result: dict[str, Any]) -> None:
    """Store scraping result summary for post-scraping toast display."""
    _scraping_results[group_id] = result


@dataclass
class PlatformStats:
    """Stats for a single platform search."""

    platform_id: str
    queries_run: int = 0
    chats_found: int = 0
    error: str | None = None
    ai_cost: float = 0.0
    ai_model: str | None = None
    ai_tokens_in: int = 0
    ai_tokens_out: int = 0


@dataclass
class SearchResult:
    """Result of orchestrated search."""

    group_id: str
    platforms_searched: int = 0
    total_chats_found: int = 0
    duplicates_removed: int = 0
    platform_stats: list[PlatformStats] = field(default_factory=list)


class SearchOrchestrator:
    """Coordinates search across multiple platforms and deduplicates results."""

    def __init__(
        self,
        registry: PlatformRegistry,
        query_generator: QueryGenerator,
        db: GroupDatabase,
        billing: BillingService,
    ) -> None:
        self._registry = registry
        self._query_gen = query_generator
        self._db = db
        self._billing = billing

    async def search(
        self,
        user_query: str,
        platform_ids: list[str],
        user_id: str,
        group_name: str,
        group_id: str | None = None,
    ) -> SearchResult:
        """Run end-to-end search: generate queries, search platforms, deduplicate, create group.

        Args:
            user_query: Natural language search description.
            platform_ids: List of platform IDs to search.
            user_id: User identifier for billing.
            group_name: Name for the created group.
            group_id: Optional pre-created group ID. If None, a new ID is generated.

        Returns:
            SearchResult with group_id and statistics.
        """
        if group_id is None:
            group_id = f"group-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

        try:
            # Create/update group with SCRAPING status
            self._db.save_group(
                group_id=group_id,
                name=group_name.strip(),
                settings=GroupSettings().model_dump(),
                status=GroupStatus.SCRAPING.value,
                created_at=now,
                updated_at=now,
                user_id=user_id,
                source="scraping",
            )

            # Check user has balance to proceed with search
            if not self._billing.check_positive_balance(user_id):
                raise InsufficientBalance("User balance is insufficient for search")

            # 1. Generate search queries via AI
            (
                queries,
                ai_cost,
                ai_fallback,
                ai_model,
                ai_tokens_in,
                ai_tokens_out,
            ) = await self._query_gen.generate(user_query, user_id=user_id)
            logger.warning(
                "Generated %d queries for: %r (fallback: %s)", len(queries), user_query, ai_fallback
            )

            # Record query generation transaction (always, even if cost is 0)
            self._billing.force_charge(
                user_id,
                ai_cost,
                "query_processing",
                ai_model,
                ai_tokens_in,
                ai_tokens_out,
                "Query processing",
            )

            # 2. Resolve platforms
            platforms = self._resolve_platforms(platform_ids)
            if not platforms:
                logger.warning("No available platforms for IDs: %s", platform_ids)
                self._update_group_status(group_id, GroupStatus.FAILED)
                return SearchResult(group_id=group_id)

            # 3. Search all platforms concurrently (with progress tracking)
            _scraping_progress[group_id] = {
                "platforms": {p.id: {"status": "searching", "chats_found": 0} for p in platforms},
                "total_found": 0,
            }
            platform_results = await asyncio.gather(
                *(
                    self._search_platform_tracked(platform, queries, group_id, user_id)
                    for platform in platforms
                ),
                return_exceptions=True,
            )

            # 4. Collect and aggregate results
            all_refs: list[str] = []
            all_titles: dict[str, str] = {}
            stats_list: list[PlatformStats] = []

            for platform, result in zip(platforms, platform_results, strict=True):
                if isinstance(result, BaseException):
                    logger.error("Platform %s failed: %s", platform.id, result)
                    stats_list.append(PlatformStats(platform_id=platform.id, error=str(result)))
                else:
                    refs, pstats, titles = result
                    logger.warning(
                        "Platform %s returned %d unique refs (queries_run=%d, error=%s)",
                        platform.id,
                        len(refs),
                        pstats.queries_run,
                        pstats.error,
                    )
                    all_refs.extend(refs)
                    all_titles.update(titles)
                    stats_list.append(pstats)

            # 5. Deduplicate across platforms
            total_before = len(all_refs)
            unique_refs = _deduplicate_refs(all_refs)
            duplicates_removed = total_before - len(unique_refs)
            logger.warning(
                "Dedup: %d refs from platforms → %d unique (%d cross-platform duplicates removed)",
                total_before,
                len(unique_refs),
                duplicates_removed,
            )

            # 6. AI post-filter: remove obviously irrelevant refs
            if unique_refs:
                from chatfilter.ai.html_parser import filter_refs_by_relevance
                from chatfilter.ai.service import AIService

                ai_service = AIService(self._db)
                unique_refs, filter_cost = await filter_refs_by_relevance(
                    unique_refs,
                    user_query,
                    ai_service,
                    user_id=user_id,
                    titles=all_titles,
                )
                self._billing.force_charge(
                    user_id, filter_cost, "parse_response", None, 0, 0, "Post-filter"
                )

            # 7. Add chats to group and update status
            if unique_refs:
                for ref in unique_refs:
                    self._db.save_chat(
                        group_id=group_id,
                        chat_ref=ref,
                        chat_type=ChatTypeEnum.PENDING.value,
                        status=GroupChatStatus.PENDING.value,
                    )
                self._update_group_status(group_id, GroupStatus.PENDING)
                logger.warning(
                    "Scraping complete for group %s: saved %d chats to DB, status → PENDING",
                    group_id,
                    len(unique_refs),
                )
            else:
                # All platforms returned empty or failed
                all_failed = all(s.error is not None for s in stats_list)
                status = GroupStatus.FAILED if all_failed else GroupStatus.PENDING
                self._update_group_status(group_id, status)
                logger.warning(
                    "Scraping complete for group %s: 0 chats, status → %s (all_failed=%s)",
                    group_id,
                    status.value,
                    all_failed,
                )

            platforms_searched = sum(1 for s in stats_list if s.error is None)

            # Store result summary for toast display
            store_scraping_result(
                group_id,
                {
                    "total_chats": len(unique_refs),
                    "platforms_searched": platforms_searched,
                    "platforms_total": len(stats_list),
                    "ai_fallback": ai_fallback,
                    "all_failed": all(s.error is not None for s in stats_list)
                    if stats_list
                    else True,
                },
            )

            return SearchResult(
                group_id=group_id,
                platforms_searched=platforms_searched,
                total_chats_found=len(unique_refs),
                duplicates_removed=duplicates_removed,
                platform_stats=stats_list,
            )

        except InsufficientBalance:
            logger.warning("Insufficient balance for user %s, search aborted", user_id)
            store_scraping_result(
                group_id,
                {
                    "total_chats": 0,
                    "platforms_searched": 0,
                    "platforms_total": 0,
                    "ai_fallback": False,
                    "all_failed": True,
                    "error": "insufficient_balance",
                },
            )
            self._update_group_status(group_id, GroupStatus.FAILED)
            raise
        except Exception:
            logger.exception("Search orchestrator failed for group %s", group_id)
            store_scraping_result(
                group_id,
                {
                    "total_chats": 0,
                    "platforms_searched": 0,
                    "platforms_total": 0,
                    "ai_fallback": False,
                    "all_failed": True,
                    "error": "internal_error",
                },
            )
            self._update_group_status(group_id, GroupStatus.FAILED)
            raise

    def _resolve_platforms(self, platform_ids: list[str]) -> list[BasePlatform]:
        """Resolve platform IDs to available platform instances."""
        platforms = []
        for pid in platform_ids:
            try:
                platform = self._registry.get(pid)
                platforms.append(platform)
            except KeyError:
                logger.warning("Unknown platform ID: %s", pid)
        return platforms

    _PLATFORM_TIMEOUT = 120  # seconds per platform

    async def _search_platform_tracked(
        self,
        platform: BasePlatform,
        queries: list[str],
        group_id: str,
        user_id: str,
    ) -> tuple[list[str], PlatformStats, dict[str, str]]:
        """Wrapper around _search_platform that updates scraping progress."""
        try:
            refs, stats, titles = await asyncio.wait_for(
                self._search_platform(platform, queries, user_id),
                timeout=self._PLATFORM_TIMEOUT,
            )
        except TimeoutError:
            logger.warning("Platform %s timed out after %ds", platform.id, self._PLATFORM_TIMEOUT)
            refs = []
            titles = {}
            stats = PlatformStats(platform_id=platform.id, error="Timed out")
        progress = _scraping_progress.get(group_id)
        if progress is not None:
            status = "error" if stats.error else "done"
            progress["platforms"][platform.id] = {
                "status": status,
                "chats_found": stats.chats_found,
            }
            progress["total_found"] = sum(p["chats_found"] for p in progress["platforms"].values())
        return refs, stats, titles

    async def _search_platform(
        self,
        platform: BasePlatform,
        queries: list[str],
        user_id: str,
    ) -> tuple[list[str], PlatformStats, dict[str, str]]:
        """Search a single platform with all queries."""
        stats = PlatformStats(platform_id=platform.id)
        all_refs: list[str] = []
        all_titles: dict[str, str] = {}

        # Check availability
        if not await platform.is_available():
            stats.error = "Platform not available (missing API key or disabled)"
            return all_refs, stats, all_titles

        for query in queries:
            try:
                result = await platform.search(query)
                # Handle both PlatformSearchResult (new) and list[str] (legacy)
                if isinstance(result, PlatformSearchResult):
                    all_refs.extend(result.refs)
                    all_titles.update(result.titles)
                    stats.ai_cost += result.ai_cost
                    stats.ai_tokens_in += result.ai_tokens_in
                    stats.ai_tokens_out += result.ai_tokens_out
                    if result.ai_model:
                        stats.ai_model = result.ai_model
                    refs_count = len(result.refs)
                else:
                    # Legacy: platform returns list[str]
                    all_refs.extend(result)
                    refs_count = len(result)
                stats.queries_run += 1
                stats.chats_found += refs_count
                logger.warning(
                    "Platform %s query %r → %d refs (running total: %d raw)",
                    platform.id,
                    query[:60],
                    refs_count,
                    len(all_refs),
                )
            except Exception:
                logger.exception("Platform %s failed for query %r", platform.id, query)
                # Continue with remaining queries — don't fail entire platform
                continue

        # Deduplicate within platform (multiple queries often return the same chats)
        raw_count = len(all_refs)
        all_refs = _deduplicate_refs(all_refs)
        stats.chats_found = len(all_refs)
        if raw_count != len(all_refs):
            logger.warning(
                "Platform %s intra-dedup: %d raw → %d unique (%d duplicates across queries)",
                platform.id,
                raw_count,
                len(all_refs),
                raw_count - len(all_refs),
            )

        if stats.queries_run == 0 and not all_refs:
            stats.error = "All queries failed"

        # Record parse_response transaction (always, even if AI cost is 0)
        self._billing.force_charge(
            user_id,
            stats.ai_cost,
            "parse_response",
            stats.ai_model,
            stats.ai_tokens_in,
            stats.ai_tokens_out,
            f"Parsing: {platform.name}",
        )

        # Record platform_request transaction (always, even if cost is 0)
        platform_cost = 0.0
        if stats.queries_run > 0:
            setting = self._db.get_platform_setting(stats.platform_id)
            if setting:
                platform_cost = stats.queries_run * setting["cost_per_request_usd"]
        self._billing.force_charge(
            user_id,
            platform_cost,
            "platform_request",
            None,
            0,
            0,
            f"Request: {platform.name}",
        )

        return all_refs, stats, all_titles

    def _update_group_status(self, group_id: str, status: GroupStatus) -> None:
        """Update group status in database."""
        group_data = self._db.load_group(group_id)
        if not group_data:
            return
        self._db.save_group(
            group_id=group_id,
            name=group_data["name"],
            settings=group_data["settings"],
            status=status.value,
            created_at=group_data["created_at"],
            updated_at=datetime.now(UTC),
            user_id=group_data.get("user_id", ""),
        )


# --- Deduplication ---

_TME_PATTERN = re.compile(
    r"(?:https?://)?(?:t\.me|telegram\.me)/(?:joinchat/)?(\w+)", re.IGNORECASE
)
_AT_PATTERN = re.compile(r"^@(\w+)$")


def _normalize_ref(raw: str) -> str | None:
    """Normalize a chat reference to canonical @username form.

    Handles: t.me/xxx, https://t.me/xxx, @xxx, telegram.me/xxx
    Returns None if the ref cannot be normalized.
    """
    raw = raw.strip()
    if not raw:
        return None

    # Try t.me link
    m = _TME_PATTERN.match(raw)
    if m:
        username = m.group(1).lower()
        # joinchat links are invite hashes, keep as t.me link
        if "joinchat" in raw.lower():
            return f"t.me/joinchat/{m.group(1)}"
        return f"@{username}"

    # Try @username
    m = _AT_PATTERN.match(raw)
    if m:
        return f"@{m.group(1).lower()}"

    # Fallback: return as-is (numeric IDs etc.)
    return raw.strip().lower()


def _deduplicate_refs(refs: list[str]) -> list[str]:
    """Deduplicate chat references by normalizing to canonical form.

    Preserves order of first occurrence.
    """
    seen: set[str] = set()
    unique: list[str] = []

    for raw in refs:
        normalized = _normalize_ref(raw)
        if normalized is None:
            continue
        if normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)

    return unique
