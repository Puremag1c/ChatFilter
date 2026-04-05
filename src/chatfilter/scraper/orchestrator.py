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

if TYPE_CHECKING:
    from chatfilter.ai.billing import BillingService
    from chatfilter.scraper.base import BasePlatform
    from chatfilter.scraper.query_generator import QueryGenerator
    from chatfilter.scraper.registry import PlatformRegistry
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

# Estimated cost per search for balance reservation
_ESTIMATED_COST_PER_SEARCH = 0.01

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
        pre_reserved: bool = False,
    ) -> SearchResult:
        """Run end-to-end search: generate queries, search platforms, deduplicate, create group.

        Args:
            user_query: Natural language search description.
            platform_ids: List of platform IDs to search.
            user_id: User identifier for billing.
            group_name: Name for the created group.
            group_id: Optional pre-created group ID. If None, a new ID is generated.
            pre_reserved: If True, skip the internal reserve() call because the caller
                already reserved the balance atomically before queuing this task.

        Returns:
            SearchResult with group_id and statistics.
        """
        estimated_cost = _ESTIMATED_COST_PER_SEARCH * max(len(platform_ids), 1)
        ai_cost = 0.0

        if group_id is None:
            group_id = f"group-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)

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

        try:
            # 1. Reserve balance (skip if caller already reserved atomically)
            if not pre_reserved:
                self._billing.reserve(user_id, estimated_cost)

            # 2. Generate search queries via AI (captures cost)
            queries, ai_cost, ai_fallback = await self._query_gen.generate(
                user_query, user_id=user_id
            )
            logger.info(
                "Generated %d queries for: %r (fallback: %s)", len(queries), user_query, ai_fallback
            )

            # 3. Resolve platforms
            platforms = self._resolve_platforms(platform_ids)
            if not platforms:
                logger.warning("No available platforms for IDs: %s", platform_ids)
                self._update_group_status(group_id, GroupStatus.FAILED)
                self._billing.settle(
                    user_id, estimated_cost, 0.0, "search", 0, 0, "No platforms available"
                )
                return SearchResult(group_id=group_id)

            # 4. Search all platforms concurrently (with progress tracking)
            _scraping_progress[group_id] = {
                "platforms": {p.id: {"status": "searching", "chats_found": 0} for p in platforms},
                "total_found": 0,
            }
            platform_results = await asyncio.gather(
                *(
                    self._search_platform_tracked(platform, queries, group_id)
                    for platform in platforms
                ),
                return_exceptions=True,
            )

            # 5. Collect and aggregate results
            all_refs: list[str] = []
            stats_list: list[PlatformStats] = []

            for platform, result in zip(platforms, platform_results, strict=True):
                if isinstance(result, BaseException):
                    logger.error("Platform %s failed: %s", platform.id, result)
                    stats_list.append(PlatformStats(platform_id=platform.id, error=str(result)))
                else:
                    refs, pstats = result
                    all_refs.extend(refs)
                    stats_list.append(pstats)

            # 6. Deduplicate
            unique_refs = _deduplicate_refs(all_refs)
            duplicates_removed = len(all_refs) - len(unique_refs)

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
            else:
                # All platforms returned empty or failed
                all_failed = all(s.error is not None for s in stats_list)
                status = GroupStatus.FAILED if all_failed else GroupStatus.PENDING
                self._update_group_status(group_id, status)

            # Store result summary for toast display before clearing progress
            platforms_searched = sum(1 for s in stats_list if s.error is None)
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

            # Clear progress tracking
            clear_scraping_progress(group_id)

            # 8. Calculate cost and settle billing
            # Sum platform API request costs: queries_run × cost_per_request for each platform
            platform_cost = 0.0
            for s in stats_list:
                if s.error is None and s.queries_run > 0:
                    setting = self._db.get_platform_setting(s.platform_id)
                    if setting:
                        platform_cost += s.queries_run * setting["cost_per_request_usd"]

            # BillingService applies the DB cost multiplier automatically
            actual_cost = ai_cost + platform_cost
            self._billing.settle(
                user_id,
                estimated_cost,
                actual_cost,
                "search",
                0,
                0,
                f"Search: {platforms_searched} platforms, {len(unique_refs)} chats",
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
            clear_scraping_progress(group_id)
            self._update_group_status(group_id, GroupStatus.FAILED)
            if pre_reserved:
                # Caller reserved before queuing — refund the reservation
                self._billing.settle(
                    user_id,
                    estimated_cost,
                    0.0,
                    "search",
                    0,
                    0,
                    "Search aborted: insufficient balance",
                )
            # else: reserve() never succeeded — do NOT call settle() or a phantom refund is issued
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
            clear_scraping_progress(group_id)
            self._update_group_status(group_id, GroupStatus.FAILED)
            # Settle with zero cost on failure
            self._billing.settle(user_id, estimated_cost, 0.0, "search", 0, 0, "Search failed")
            raise

    def _resolve_platforms(self, platform_ids: list[str]) -> list[BasePlatform]:
        """Resolve platform IDs to available platform instances."""
        platforms = []
        for pid in platform_ids:
            try:
                platform = self._registry.get(pid)
                if not platform.is_implemented:
                    logger.info("Skipping stub platform %s (not yet implemented)", pid)
                    continue
                platforms.append(platform)
            except KeyError:
                logger.warning("Unknown platform ID: %s", pid)
        return platforms

    async def _search_platform_tracked(
        self,
        platform: BasePlatform,
        queries: list[str],
        group_id: str,
    ) -> tuple[list[str], PlatformStats]:
        """Wrapper around _search_platform that updates scraping progress."""
        refs, stats = await self._search_platform(platform, queries)
        progress = _scraping_progress.get(group_id)
        if progress is not None:
            status = "error" if stats.error else "done"
            progress["platforms"][platform.id] = {
                "status": status,
                "chats_found": stats.chats_found,
            }
            progress["total_found"] = sum(p["chats_found"] for p in progress["platforms"].values())
        return refs, stats

    async def _search_platform(
        self,
        platform: BasePlatform,
        queries: list[str],
    ) -> tuple[list[str], PlatformStats]:
        """Search a single platform with all queries."""
        stats = PlatformStats(platform_id=platform.id)
        all_refs: list[str] = []

        # Check availability
        if not await platform.is_available():
            stats.error = "Platform not available (missing API key or disabled)"
            return all_refs, stats

        for query in queries:
            try:
                refs = await platform.search(query)
                all_refs.extend(refs)
                stats.queries_run += 1
                stats.chats_found += len(refs)
            except Exception:
                logger.exception("Platform %s failed for query %r", platform.id, query)
                # Continue with remaining queries — don't fail entire platform
                continue

        if stats.queries_run == 0 and not all_refs:
            stats.error = "All queries failed"

        return all_refs, stats

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
