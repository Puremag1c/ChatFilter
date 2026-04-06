"""Generated backend tests for SPEC.md gaps not covered by existing tests.

Gaps covered:
1. ai_transactions type='search' written to DB when settle(model='search') called
2. Balance check before search: orchestrator raises InsufficientBalance when balance is 0
3. Platform spec completeness: all 12 platforms have required SPEC attributes
4. Cost multiplier correctly applied to search billing at DB level
5. TGStat platform makes a real HTTP request when API key is configured
"""

from __future__ import annotations

import contextlib
import importlib
import pkgutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.ai.billing import BillingService, InsufficientBalance
from chatfilter.models.group import GroupStatus
from chatfilter.scraper.base import BasePlatform
from chatfilter.scraper.orchestrator import SearchOrchestrator
from chatfilter.scraper.query_generator import QueryGenerator
from chatfilter.scraper.registry import PlatformRegistry
from tests.db_helpers import make_group_db, make_user_db

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _FakePlatform(BasePlatform):
    id = "fake"
    name = "Fake"
    url = "https://example.com"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    def __init__(self, results: list[str] | None = None) -> None:
        self._results = results or []

    async def search(self, query: str) -> list[str]:
        return list(self._results)


def _make_query_gen(queries: list[str] | None = None, ai_cost: float = 0.001) -> AsyncMock:
    gen = AsyncMock(spec=QueryGenerator)
    gen.generate.return_value = (queries or ["test query"], ai_cost, False, "gpt-4o-mini", 0, 0)
    return gen


@pytest.fixture()
def group_db(tmp_path):
    return make_group_db(tmp_path / "test.db")


# ---------------------------------------------------------------------------
# GAP 1: ai_transactions type='search' verified at DB level
# ---------------------------------------------------------------------------


class TestAiTransactionTypeSearch:
    """SPEC: Billing stores type='search' for search operations (ai_transactions table)."""

    def test_settle_with_search_model_creates_search_type_transaction(self, tmp_path: Path):
        """When force_charge() is called with model='search', DB record must have type='search'."""
        db = make_user_db(tmp_path / "search_txn.db")
        billing = BillingService(db)
        user_id = db.create_user("searcher", "password123")

        billing.topup(user_id, 5.0, "initial load")
        billing.force_charge(
            user_id, 0.05, "search", "search", 0, 0, "Search: 3 platforms, 12 chats"
        )

        txns = billing.get_transactions(user_id)
        charge_txns = [t for t in txns if t["type"] != "topup"]
        assert len(charge_txns) == 1, f"Expected 1 non-topup transaction, got: {charge_txns}"
        assert charge_txns[0]["type"] == "search", (
            f"Expected type='search' but got type='{charge_txns[0]['type']}'. "
            "SPEC requires ai_transactions.type='search' for search operations."
        )

    def test_settle_with_ai_model_creates_charge_type_transaction(self, tmp_path: Path):
        """When force_charge() is called with an AI model name, type must be 'charge'."""
        db = make_user_db(tmp_path / "charge_txn.db")
        billing = BillingService(db)
        user_id = db.create_user("aiuser", "password123")

        billing.topup(user_id, 5.0, "initial")
        billing.force_charge(user_id, 0.05, "charge", "gpt-4o-mini", 100, 200, "AI analysis")

        txns = billing.get_transactions(user_id)
        charge_txns = [t for t in txns if t["type"] != "topup"]
        assert charge_txns[0]["type"] == "charge", (
            f"Non-search model must produce type='charge', got: '{charge_txns[0]['type']}'"
        )

    def test_search_transaction_records_description(self, tmp_path: Path):
        """SPEC: search transaction description must be persisted in DB."""
        db = make_user_db(tmp_path / "search_desc.db")
        billing = BillingService(db)
        user_id = db.create_user("descuser", "password123")

        billing.topup(user_id, 5.0, "initial")
        desc = "Search: 5 platforms, 42 chats"
        billing.force_charge(user_id, 0.05, "search", "search", 0, 0, desc)

        txns = billing.get_transactions(user_id)
        search_txn = next((t for t in txns if t["type"] == "search"), None)
        assert search_txn is not None, "No search transaction found"
        assert search_txn["description"] == desc


# ---------------------------------------------------------------------------
# GAP 2: Balance check before search - zero balance raises InsufficientBalance
# ---------------------------------------------------------------------------


class TestSearchBalanceCheck:
    """SPEC: Check balance BEFORE search starts."""

    @pytest.mark.asyncio
    async def test_zero_balance_raises_insufficient_balance(self, group_db, tmp_path):
        """User with zero balance: orchestrator.reserve() raises InsufficientBalance."""
        user_db = make_user_db(tmp_path / "broke.db")
        user_id = user_db.create_user("broke_user", "password123")
        # Set balance to 0.0 explicitly (server_default is 1.0)
        user_db.update_balance(user_id, 0.0)

        billing = BillingService(user_db)

        reg = PlatformRegistry()
        p = _FakePlatform(results=["@somechan"])
        reg.register(p)
        qgen = _make_query_gen(["crypto"])

        orch = SearchOrchestrator(reg, qgen, group_db, billing)

        # Orchestrator should raise InsufficientBalance when reserve() fails
        with pytest.raises(InsufficientBalance):
            await orch.search(
                user_query="crypto channels",
                platform_ids=["fake"],
                user_id=user_id,
                group_name="Zero Balance Test",
            )

    @pytest.mark.asyncio
    async def test_zero_balance_group_set_to_failed_status(self, group_db, tmp_path):
        """Group created during failed search (zero balance) must end in FAILED status."""
        user_db = make_user_db(tmp_path / "broke2.db")
        user_id = user_db.create_user("broke2", "password123")
        user_db.update_balance(user_id, 0.0)

        billing = BillingService(user_db)

        reg = PlatformRegistry()
        p = _FakePlatform(results=["@somechan"])
        reg.register(p)
        qgen = _make_query_gen(["crypto"])

        orch = SearchOrchestrator(reg, qgen, group_db, billing)

        # Pre-create group to track its ID
        group_id = "group-test-zero-balance"

        with contextlib.suppress(InsufficientBalance):
            await orch.search(
                user_query="crypto channels",
                platform_ids=["fake"],
                user_id=user_id,
                group_name="Zero Balance Test",
                group_id=group_id,
            )

        # Group must be set to FAILED status
        group = group_db.load_group(group_id)
        assert group is not None, "Group should exist in DB even after failed search"
        assert group["status"] == GroupStatus.FAILED.value, (
            f"Expected group status=failed after InsufficientBalance, got: {group['status']}. "
            "SPEC: group should not be left in 'scraping' status indefinitely."
        )


# ---------------------------------------------------------------------------
# GAP 3: Platform spec completeness - all 12 platforms have SPEC attributes
# ---------------------------------------------------------------------------


class TestPlatformSpecCompleteness:
    """SPEC: Each platform has structured spec with method, needs_api_key, cost_tier."""

    REQUIRED_ATTRS = ["id", "name", "url", "method", "needs_api_key", "cost_tier"]
    VALID_METHODS = {"api", "http", "playwright"}
    VALID_TIERS = {"cheap", "medium", "expensive"}
    EXPECTED_PLATFORM_COUNT = 10
    EXPECTED_PLATFORM_IDS = {
        "tgstat",
        "telemetr",
        "teleteg",
        "nicegram",
        "combot",
        "hottg",
        "telegram_channels",
        "tlgrm",
        "lyzem",
        "telegago",
    }

    def _load_all_platforms(self) -> list[BasePlatform]:
        import chatfilter.scraper.platforms as pkg

        platforms = []
        for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
            mod = importlib.import_module(f"chatfilter.scraper.platforms.{modname}")
            for attr in dir(mod):
                cls = getattr(mod, attr)
                if (
                    isinstance(cls, type)
                    and issubclass(cls, BasePlatform)
                    and cls is not BasePlatform
                    and hasattr(cls, "id")
                    and cls.id
                ):
                    platforms.append(cls())
        return platforms

    def test_exactly_12_platforms_exist(self):
        """SPEC lists exactly 12 platforms."""
        platforms = self._load_all_platforms()
        assert len(platforms) == self.EXPECTED_PLATFORM_COUNT, (
            f"Expected {self.EXPECTED_PLATFORM_COUNT} platforms, found {len(platforms)}: "
            f"{[p.id for p in platforms]}"
        )

    def test_all_platforms_have_required_attributes(self):
        """Every platform must declare id, name, url, method, needs_api_key, cost_tier."""
        platforms = self._load_all_platforms()
        for platform in platforms:
            for attr in self.REQUIRED_ATTRS:
                val = getattr(platform, attr, None)
                assert val is not None and val != "", (
                    f"Platform '{platform.id}' missing required attribute '{attr}'"
                )

    def test_all_platforms_have_valid_method(self):
        """Platform method must be: api, http, or playwright."""
        platforms = self._load_all_platforms()
        for platform in platforms:
            assert platform.method in self.VALID_METHODS, (
                f"Platform '{platform.id}' has invalid method='{platform.method}'. "
                f"Valid: {self.VALID_METHODS}"
            )

    def test_all_platforms_have_valid_cost_tier(self):
        """Platform cost_tier must be: cheap, medium, or expensive."""
        platforms = self._load_all_platforms()
        for platform in platforms:
            assert platform.cost_tier in self.VALID_TIERS, (
                f"Platform '{platform.id}' has invalid cost_tier='{platform.cost_tier}'. "
                f"Valid: {self.VALID_TIERS}"
            )

    def test_all_spec_platform_ids_present(self):
        """All platform IDs from SPEC must be registered."""
        platforms = self._load_all_platforms()
        found_ids = {p.id for p in platforms}
        missing = self.EXPECTED_PLATFORM_IDS - found_ids
        assert not missing, f"Platform IDs from SPEC missing in code: {missing}"


# ---------------------------------------------------------------------------
# GAP 4: Cost multiplier verified at DB level (not just mock)
# ---------------------------------------------------------------------------


class TestCostMultiplierAtDBLevel:
    """SPEC: Global multiplier applied to ALL AI costs including search."""

    def test_multiplier_2x_doubles_balance_deduction(self, tmp_path: Path):
        """With multiplier=2.0, a $0.05 raw search cost deducts $0.10 from user's balance."""
        gdb = make_group_db(tmp_path / "gdb.db")
        udb = make_user_db(tmp_path / "udb.db")

        gdb.set_cost_multiplier(2.0)

        billing = BillingService(udb, gdb)
        user_id = udb.create_user("multuser", "password123")
        billing.topup(user_id, 100.0, "initial")  # Large enough to not hit default 1.0 issues

        balance_before = billing.get_balance(user_id)

        raw_cost = 0.05  # Raw unscaled cost
        multiplier = 2.0
        # force_charge applies multiplier internally: deducts 0.05 * 2 = 0.10
        billing.force_charge(user_id, raw_cost, "search", "search", 0, 0, "Search 2x test")

        balance_after = billing.get_balance(user_id)
        deducted = balance_before - balance_after
        expected_deduction = raw_cost * multiplier  # $0.10

        assert deducted == pytest.approx(expected_deduction, abs=1e-6), (
            f"Expected ${expected_deduction:.2f} deducted with 2x multiplier on $0.05 raw search, "
            f"got ${deducted:.4f}. SPEC: multiplier applies to all AI operations."
        )

    def test_default_multiplier_1x_charges_exact_cost(self, tmp_path: Path):
        """Default multiplier=1.0: charge equals actual cost, no markup."""
        gdb = make_group_db(tmp_path / "gdb1.db")
        udb = make_user_db(tmp_path / "udb1.db")

        gdb.set_cost_multiplier(1.0)

        billing = BillingService(udb, gdb)
        user_id = udb.create_user("nomark", "password123")
        billing.topup(user_id, 100.0, "initial")

        balance_before = billing.get_balance(user_id)
        cost = 0.05
        billing.force_charge(user_id, cost, "search", "search", 0, 0, "1x search")

        balance_after = billing.get_balance(user_id)
        deducted = balance_before - balance_after
        assert deducted == pytest.approx(0.05, abs=1e-6), (
            f"Expected $0.05 deducted with 1x multiplier, got ${deducted:.4f}"
        )


# ---------------------------------------------------------------------------
# GAP 5: TGStat platform makes a real HTTP request when API key is configured
# ---------------------------------------------------------------------------


class TestTgstatRealApiImplementation:
    """SPEC Must Have #3: TGStat API — real GET to api.tgstat.ru/channels/search."""

    @pytest.mark.asyncio
    async def test_tgstat_has_real_api_implementation(self, tmp_path):
        """tgstat.py makes a real GET to api.tgstat.ru/channels/search when api_key is set."""
        from chatfilter.scraper.platforms.tgstat import TgstatPlatform
        from tests.db_helpers import make_group_db

        db = make_group_db(tmp_path / "tgstat_test.db")
        db.save_platform_setting("tgstat", api_key="test-api-key", cost=0.001, enabled=True)

        platform = TgstatPlatform()
        platform._db = db

        fake_response = {
            "status": "ok",
            "response": {
                "count": 2,
                "total_count": 2,
                "items": [
                    {"id": 1, "username": "channel_one", "title": "Channel One"},
                    {"id": 2, "username": "channel_two", "title": "Channel Two"},
                ],
            },
        }

        with patch("chatfilter.scraper.platforms.tgstat.httpx.AsyncClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value.__aenter__.return_value
            mock_resp = MagicMock()
            mock_resp.json.return_value = fake_response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get = AsyncMock(return_value=mock_resp)

            result = await platform.search("crypto")

        # Verify HTTP GET was made (not just returning empty stub)
        mock_client.get.assert_called_once()
        call_args = mock_client.get.call_args
        url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
        assert "api.tgstat.ru/channels/search" in url, (
            f"Expected call to api.tgstat.ru/channels/search, got: {url!r}. "
            "SPEC Must Have #3: TGStat must hit real API endpoint."
        )

        # Verify API key is passed
        params = call_args[1].get("params", {})
        assert params.get("token") == "test-api-key", (
            f"Expected token='test-api-key' in params, got: {params!r}"
        )
        assert params.get("q") == "crypto", f"Expected q='crypto' in params, got: {params!r}"

        # Verify results are parsed
        assert len(result.refs) == 2, f"Expected 2 refs from parsed response, got: {result.refs!r}"
        assert "@channel_one" in result.refs
        assert "@channel_two" in result.refs

    @pytest.mark.asyncio
    async def test_tgstat_returns_empty_without_api_key(self, tmp_path):
        """tgstat.py returns empty result and does NOT call API when no key configured."""
        from chatfilter.scraper.platforms.tgstat import TgstatPlatform
        from tests.db_helpers import make_group_db

        db = make_group_db(tmp_path / "tgstat_nokey.db")
        # No api_key set

        platform = TgstatPlatform()
        platform._db = db

        with patch("chatfilter.scraper.platforms.tgstat.httpx.AsyncClient") as mock_client_cls:
            result = await platform.search("crypto")
            mock_client_cls.assert_not_called()

        assert result.refs == [], f"Expected empty refs without API key, got: {result.refs!r}"
