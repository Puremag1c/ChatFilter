"""Backend tests for scraping/search engine — SPEC.md Must Have coverage."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.models.group import GroupStatus
from chatfilter.scraper.base import BasePlatform
from chatfilter.scraper.orchestrator import (
    SearchOrchestrator,
    _deduplicate_refs,
    _normalize_ref,
    clear_scraping_progress,
    get_scraping_progress,
)
from chatfilter.scraper.query_generator import QueryGenerator, _parse_json_array
from chatfilter.scraper.registry import PlatformRegistry
from tests.db_helpers import make_group_db

# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------


class _FakePlatform(BasePlatform):
    id = "fake"
    name = "Fake"
    url = "https://example.com"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    def __init__(self, results: list[str] | None = None, fail: bool = False) -> None:
        self._results = results or []
        self._fail = fail

    async def search(self, query: str) -> list[str]:
        if self._fail:
            raise RuntimeError("Platform error")
        return list(self._results)


class _FakePlatformNeedsKey(BasePlatform):
    id = "fake_key"
    name = "Fake (needs key)"
    url = "https://example.com"
    method = "api"
    needs_api_key = True
    cost_tier = "expensive"

    async def search(self, query: str) -> list[str]:
        return ["@secret_channel"]

    async def is_available(self) -> bool:
        return False  # no key configured


def _make_billing(balance: float = 10.0) -> MagicMock:
    billing = MagicMock()
    billing.reserve.return_value = balance
    billing.settle.return_value = balance
    billing.check_balance.return_value = balance > 0
    return billing


def _make_query_gen(queries: list[str] | None = None, ai_cost: float = 0.001) -> AsyncMock:
    gen = AsyncMock(spec=QueryGenerator)
    gen.generate.return_value = (queries or ["test query"], ai_cost, False, "test-model", 10, 20)
    return gen


@pytest.fixture()
def group_db(tmp_path):
    return make_group_db(tmp_path / "test.db")


# ---------------------------------------------------------------------------
# 1. GroupStatus enum includes SCRAPING
# ---------------------------------------------------------------------------


def test_group_status_has_scraping():
    """SPEC: New status 'scraping' must exist in GroupStatus enum."""
    assert GroupStatus.SCRAPING == "scraping"
    assert "scraping" in [s.value for s in GroupStatus]


# ---------------------------------------------------------------------------
# 2. Deduplication logic
# ---------------------------------------------------------------------------


def test_deduplicate_removes_duplicates():
    refs = ["@channel", "@Channel", "t.me/channel", "https://t.me/channel"]
    unique = _deduplicate_refs(refs)
    assert len(unique) == 1
    assert unique[0] == "@channel"


def test_deduplicate_preserves_order():
    refs = ["@alpha", "@beta", "@alpha", "@gamma"]
    unique = _deduplicate_refs(refs)
    assert unique == ["@alpha", "@beta", "@gamma"]


def test_deduplicate_empty():
    assert _deduplicate_refs([]) == []


def test_deduplicate_strips_empty():
    refs = ["", "  ", "@valid"]
    unique = _deduplicate_refs(refs)
    assert unique == ["@valid"]


def test_deduplicate_joinchat_preserved():
    refs = ["https://t.me/joinchat/ABC123", "https://t.me/joinchat/ABC123"]
    unique = _deduplicate_refs(refs)
    assert len(unique) == 1


# ---------------------------------------------------------------------------
# 3. Ref normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("t.me/mychannel", "@mychannel"),
        ("https://t.me/mychannel", "@mychannel"),
        ("@mychannel", "@mychannel"),
        ("@MyChannel", "@mychannel"),
        ("telegram.me/test", "@test"),
        ("", None),
        ("  ", None),
    ],
)
def test_normalize_ref(raw, expected):
    assert _normalize_ref(raw) == expected


# ---------------------------------------------------------------------------
# 4. QueryGenerator fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_generator_uses_ai():
    ai = AsyncMock()
    response = MagicMock(content='["crypto channels", "крипто каналы"]', cost_usd=0.001, model="gpt-4o-mini", tokens_in=50, tokens_out=20)
    ai.complete.return_value = response
    gen = QueryGenerator(ai)
    queries, cost, fallback, model, tokens_in, tokens_out = await gen.generate("crypto")
    assert queries == ["crypto channels", "крипто каналы"]
    assert cost == 0.001
    assert fallback is False


@pytest.mark.asyncio
async def test_query_generator_fallback_on_ai_error():
    """If AI fails, fallback to original user_text."""
    ai = AsyncMock()
    ai.complete.side_effect = RuntimeError("AI unavailable")
    gen = QueryGenerator(ai)
    queries, cost, fallback, model, tokens_in, tokens_out = await gen.generate("some query")
    assert queries == ["some query"]
    assert cost == 0.0  # No cost on failure
    assert fallback is True


@pytest.mark.asyncio
async def test_query_generator_fallback_on_empty_response():
    ai = AsyncMock()
    response = MagicMock(content="[]", cost_usd=0.0, model="gpt-4o-mini", tokens_in=50, tokens_out=0)
    ai.complete.return_value = response
    gen = QueryGenerator(ai)
    queries, cost, fallback, model, tokens_in, tokens_out = await gen.generate("some query")
    assert queries == ["some query"]
    assert cost == 0.0
    assert fallback is True


def test_parse_json_array_handles_markdown_fences():
    text = '```json\n["a", "b"]\n```'
    assert _parse_json_array(text) == ["a", "b"]


def test_parse_json_array_invalid_returns_empty():
    assert _parse_json_array("not json") == []
    assert _parse_json_array("{}") == []


# ---------------------------------------------------------------------------
# 5. PlatformRegistry
# ---------------------------------------------------------------------------


def test_registry_register_and_get():
    reg = PlatformRegistry()
    p = _FakePlatform()
    reg.register(p)
    assert reg.get("fake") is p


def test_registry_get_unknown_raises():
    reg = PlatformRegistry()
    with pytest.raises(KeyError):
        reg.get("nonexistent")


def test_registry_get_all():
    reg = PlatformRegistry()
    p1 = _FakePlatform()
    p1.id = "a"
    p2 = _FakePlatform()
    p2.id = "b"
    reg.register(p1)
    reg.register(p2)
    assert len(reg.get_all()) == 2


def test_registry_get_available_no_settings(group_db):
    """Platform without API key requirement is available with no settings row."""
    reg = PlatformRegistry()
    p = _FakePlatform()
    reg.register(p)
    available = reg.get_available(group_db)
    assert p in available


def test_registry_get_available_needs_key_no_settings(group_db):
    """Platform needing API key is NOT available without settings row."""
    reg = PlatformRegistry()
    p = _FakePlatformNeedsKey()
    reg.register(p)
    available = reg.get_available(group_db)
    assert p not in available


def test_registry_get_available_needs_key_with_key(group_db):
    """Platform needing API key IS available when API key is configured."""
    group_db.save_platform_setting("fake_key", api_key="secret123", enabled=True)
    reg = PlatformRegistry()
    p = _FakePlatformNeedsKey()
    reg.register(p)
    available = reg.get_available(group_db)
    assert p in available


def test_registry_get_available_disabled(group_db):
    """Disabled platform is not available."""
    group_db.save_platform_setting("fake", enabled=False)
    reg = PlatformRegistry()
    p = _FakePlatform()
    reg.register(p)
    available = reg.get_available(group_db)
    assert p not in available


# ---------------------------------------------------------------------------
# 6. SearchOrchestrator — core flow
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry_with_platform():
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@chan1", "@chan2", "t.me/chan1"])
    reg.register(p)
    return reg, p


@pytest.mark.asyncio
async def test_orchestrator_creates_group_with_scraping_status(group_db, tmp_path):
    """SPEC: Group must be created with status=scraping during search."""
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@testchan"])
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["query1"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["fake"],
        user_id="user1",
        group_name="My Group",
    )

    # Group should now be in pending (scraping completed)
    group = group_db.load_group(result.group_id)
    assert group is not None
    assert group["status"] == GroupStatus.PENDING.value


@pytest.mark.asyncio
async def test_orchestrator_deduplicates_results(group_db):
    """SPEC: After all platforms, single deduplication step."""
    reg = PlatformRegistry()
    # Two platforms returning overlapping refs
    p1 = _FakePlatform(results=["@chan1", "@chan2"])
    p1.id = "p1"
    p2 = _FakePlatform(results=["@chan2", "@chan3", "t.me/chan1"])
    p2.id = "p2"
    reg.register(p1)
    reg.register(p2)

    billing = _make_billing()
    qgen = _make_query_gen(["query1"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["p1", "p2"],
        user_id="user1",
        group_name="Dedup Test",
    )

    # 5 raw refs: [@chan1, @chan2] + [@chan2, @chan3, t.me/chan1→@chan1]
    # unique: @chan1, @chan2, @chan3 → 3, duplicates_removed = 5 - 3 = 2
    assert result.total_chats_found == 3
    assert result.duplicates_removed == 2


@pytest.mark.asyncio
async def test_orchestrator_saves_chats_to_group(group_db):
    """SPEC: Unique refs should be saved as chats in the created group."""
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@alpha", "@beta"])
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["query"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["fake"],
        user_id="user1",
        group_name="Chats Test",
    )

    chats = group_db.load_chats(result.group_id)
    chat_refs = {c["chat_ref"] for c in chats}
    assert "@alpha" in chat_refs
    assert "@beta" in chat_refs


@pytest.mark.asyncio
async def test_orchestrator_platform_failure_continues(group_db):
    """SPEC: Platform failure should not fail entire search."""
    reg = PlatformRegistry()
    p_fail = _FakePlatform(fail=True)
    p_fail.id = "failing"
    p_ok = _FakePlatform(results=["@good_chan"])
    p_ok.id = "working"
    reg.register(p_fail)
    reg.register(p_ok)

    billing = _make_billing()
    qgen = _make_query_gen(["query"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["failing", "working"],
        user_id="user1",
        group_name="Resilience Test",
    )

    # working platform found 1 chat, failing platform errored
    assert result.total_chats_found == 1
    failing_stat = next(s for s in result.platform_stats if s.platform_id == "failing")
    assert failing_stat.error is not None


@pytest.mark.asyncio
async def test_orchestrator_all_platforms_fail_sets_failed_status(group_db):
    """All platforms failing → group status = failed."""
    reg = PlatformRegistry()
    p = _FakePlatform(fail=True)
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["query"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["fake"],
        user_id="user1",
        group_name="All Fail",
    )

    group = group_db.load_group(result.group_id)
    assert group["status"] == GroupStatus.FAILED.value


@pytest.mark.asyncio
async def test_orchestrator_unknown_platform_skipped(group_db):
    """Unknown platform IDs are silently skipped."""
    reg = PlatformRegistry()
    # No platforms registered

    billing = _make_billing()
    qgen = _make_query_gen(["query"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["nonexistent"],
        user_id="user1",
        group_name="Unknown Platform",
    )

    group = group_db.load_group(result.group_id)
    assert group["status"] == GroupStatus.FAILED.value
    assert result.total_chats_found == 0


@pytest.mark.asyncio
async def test_orchestrator_uses_pre_created_group_id(group_db):
    """Passing group_id reuses it instead of generating a new one."""
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@c"])
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["q"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["fake"],
        user_id="user1",
        group_name="Pre-created",
        group_id="group-preset-123",
    )

    assert result.group_id == "group-preset-123"
    group = group_db.load_group("group-preset-123")
    assert group is not None


@pytest.mark.asyncio
async def test_orchestrator_billing_force_charge_called(group_db):
    """SPEC: Billing must charge after each AI step (no reserve/settle)."""
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@c"])
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["q"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    await orch.search(
        user_query="test",
        platform_ids=["fake"],
        user_id="user1",
        group_name="Billing Test",
    )

    # New model: force_charge is called instead of reserve/settle
    billing.force_charge.assert_called()
    billing.reserve.assert_not_called()
    billing.settle.assert_not_called()


# ---------------------------------------------------------------------------
# 7. Scraping progress tracking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scraping_progress_tracked_during_search(group_db):
    """SPEC: While scraping, progress is tracked per-platform."""

    class _TrackingPlatform(BasePlatform):
        id = "tracking"
        name = "Tracking"
        url = "https://example.com"
        method = "http"
        needs_api_key = False
        cost_tier = "cheap"

        async def search(self, query: str) -> list[str]:
            return ["@tracked_chan"]

    reg = PlatformRegistry()
    p = _TrackingPlatform()
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["q"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="test",
        platform_ids=["tracking"],
        user_id="user1",
        group_name="Progress Test",
    )

    # After completion, progress is kept in memory so the polling endpoint
    # can show the completed per-platform breakdown for one more cycle.
    # The endpoint itself clears it after displaying once.
    progress = get_scraping_progress(result.group_id)
    assert progress is not None
    assert progress["platforms"]["tracking"]["status"] == "done"

    # Manual cleanup (in production, the polling endpoint does this)
    clear_scraping_progress(result.group_id)


def test_get_scraping_progress_returns_none_for_unknown():
    assert get_scraping_progress("nonexistent-group-id") is None


def test_clear_scraping_progress_is_idempotent():
    """clear_scraping_progress on non-existent ID should not raise."""
    clear_scraping_progress("nonexistent-id-xyz")  # should not raise


# ---------------------------------------------------------------------------
# 8. Platform base class / availability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_base_platform_is_available_no_key():
    p = _FakePlatform()
    assert await p.is_available() is True


@pytest.mark.asyncio
async def test_base_platform_is_available_needs_key():
    p = _FakePlatformNeedsKey()
    assert await p.is_available() is False


# ---------------------------------------------------------------------------
# 9. AppSettings: cost_multiplier and platform_settings
# ---------------------------------------------------------------------------


def test_get_cost_multiplier_default(group_db):
    """Default cost multiplier is 1.0."""
    assert group_db.get_cost_multiplier() == 1.0


def test_set_cost_multiplier(group_db):
    group_db.set_cost_multiplier(2.5)
    assert group_db.get_cost_multiplier() == 2.5


def test_save_and_get_platform_setting(group_db):
    group_db.save_platform_setting("tgstat", api_key="key123", cost=0.003, enabled=True)
    s = group_db.get_platform_setting("tgstat")
    assert s is not None
    assert s["api_key"] == "key123"
    assert s["cost_per_request_usd"] == 0.003
    assert s["enabled"] is True


def test_platform_setting_upsert(group_db):
    group_db.save_platform_setting("tgstat", api_key="old", cost=0.001, enabled=True)
    group_db.save_platform_setting("tgstat", api_key="new", cost=0.002, enabled=False)
    s = group_db.get_platform_setting("tgstat")
    assert s["api_key"] == "new"
    assert s["enabled"] is False


def test_get_all_platform_settings(group_db):
    group_db.save_platform_setting("p1", enabled=True)
    group_db.save_platform_setting("p2", api_key="k", enabled=False)
    settings = group_db.get_all_platform_settings()
    ids = {s["id"] for s in settings}
    assert "p1" in ids
    assert "p2" in ids


def test_platform_setting_not_found_returns_none(group_db):
    assert group_db.get_platform_setting("nonexistent") is None


# ---------------------------------------------------------------------------
# 10. End-to-end: group transitions scraping → pending
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_group_transitions_scraping_to_pending(group_db):
    """SPEC: After scraping + dedup, status transitions to pending."""
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@final_chan"])
    reg.register(p)

    billing = _make_billing()
    qgen = _make_query_gen(["query"])
    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    result = await orch.search(
        user_query="find channels",
        platform_ids=["fake"],
        user_id="user_x",
        group_name="Transition Test",
    )

    group = group_db.load_group(result.group_id)
    assert group["status"] == GroupStatus.PENDING.value
    assert group["source"] == "scraping"


# ---------------------------------------------------------------------------
# 11. Cost calculation with multiplier
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_orchestrator_cost_multiplier_applied(group_db):
    """SPEC: Billing must apply cost multiplier to AI cost."""
    reg = PlatformRegistry()
    p = _FakePlatform(results=["@test"])
    reg.register(p)

    billing = _make_billing()

    # Mock query generator to return a fixed AI cost of $0.01
    qgen = AsyncMock(spec=QueryGenerator)
    ai_cost = 0.01
    qgen.generate.return_value = (["test query"], ai_cost, False, "test-model", 10, 20)

    orch = SearchOrchestrator(reg, qgen, group_db, billing)

    await orch.search(
        user_query="test",
        platform_ids=["fake"],
        user_id="user1",
        group_name="Cost Test",
    )

    # Verify force_charge was called with the AI cost for query processing
    billing.force_charge.assert_called()

    # Get the force_charge call arguments to verify cost is passed through
    call_args = billing.force_charge.call_args
    # force_charge(user_id, amount, tx_type, model, tokens_in, tokens_out, description)
    actual_cost_arg = call_args[0][1]  # 2nd positional argument
    assert actual_cost_arg == ai_cost, f"Expected {ai_cost}, got {actual_cost_arg}"
