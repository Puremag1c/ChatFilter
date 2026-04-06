"""AI billing service.

BillingService wraps UserDatabase balance/transaction methods and provides
high-level charge/topup operations for AI usage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from chatfilter.storage.user_database import UserDatabase

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase


class InsufficientBalance(Exception):
    """Raised when a user has insufficient AI balance."""


class BillingService:
    """Service for AI billing operations.

    Accepts a UserDatabase instance via dependency injection.
    All balance and transaction state lives in the DB — this class
    contains only business logic.

    If group_db is provided, BillingService automatically applies the global
    cost multiplier (from app_settings) to all charge/reserve/settle calls.
    """

    def __init__(self, db: UserDatabase, group_db: GroupDatabase | None = None) -> None:
        self._db = db
        self._group_db = group_db

    def _get_multiplier(self) -> float:
        """Return global cost multiplier from settings (default 1.0)."""
        if self._group_db is None:
            return 1.0
        return self._group_db.get_cost_multiplier()

    def get_balance(self, user_id: str) -> float:
        """Return current balance in USD."""
        return self._db.get_balance(user_id)

    def check_balance(self, user_id: str) -> bool:
        """Return True if user has positive balance."""
        return self._db.get_balance(user_id) > 0

    def reserve(self, user_id: str, estimated_cost: float) -> float:
        """Atomically reserve estimated_cost from balance before starting AI call.

        The global cost multiplier is applied automatically to estimated_cost.
        Must be paired with settle() after the call completes.

        Returns new balance.
        Raises InsufficientBalance if balance < estimated_cost * multiplier.
        """
        try:
            return self._db.reserve_balance(user_id, estimated_cost * self._get_multiplier())
        except ValueError as exc:
            if str(exc).startswith("insufficient:"):
                balance = float(str(exc).split(":")[1])
                raise InsufficientBalance(
                    f"User {user_id} has insufficient balance: {balance:.6f} USD"
                ) from exc
            raise

    def settle(
        self,
        user_id: str,
        reserved_cost: float,
        actual_cost: float,
        model: str,
        tokens_in: int,
        tokens_out: int,
        description: str,
    ) -> float:
        """Settle a prior reserve with the actual cost after AI call completes.

        The global cost multiplier is applied automatically to both reserved_cost
        and actual_cost, matching the multiplier applied during reserve().
        Refunds if actual < reserved; charges extra (capped) if actual > reserved.
        Records transaction for actual_cost * multiplier.

        Returns new balance.
        """
        multiplier = self._get_multiplier()
        return self._db.settle_reserve(
            user_id=user_id,
            reserved_cost=reserved_cost * multiplier,
            actual_cost=actual_cost * multiplier,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            description=description,
        )

    def charge(
        self,
        user_id: str,
        cost_usd: float,
        model: str,
        tokens_in: int,
        tokens_out: int,
        description: str,
    ) -> float:
        """Deduct cost_usd from user balance atomically.

        The global cost multiplier is applied automatically to cost_usd.
        Uses a single DB transaction (check + deduct + record) so concurrent
        requests cannot both pass the balance > 0 check before either deducts.

        Raises InsufficientBalance if balance <= 0.
        Returns new balance.
        """
        try:
            return self._db.atomic_charge(
                user_id=user_id,
                cost_usd=cost_usd * self._get_multiplier(),
                model=model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                description=description,
            )
        except ValueError as exc:
            if str(exc).startswith("insufficient:"):
                balance = float(str(exc).split(":")[1])
                raise InsufficientBalance(
                    f"User {user_id} has insufficient balance: {balance:.6f} USD"
                ) from exc
            raise

    def force_charge(
        self,
        user_id: str,
        cost_usd: float,
        tx_type: str,
        model: str | None,
        tokens_in: int,
        tokens_out: int,
        description: str,
    ) -> float:
        """Deduct cost_usd from user balance WITHOUT checking balance >= 0.

        The global cost multiplier is applied automatically to cost_usd.
        Always succeeds — balance can go negative.

        Args:
            tx_type: 'query_processing' | 'parse_response' | 'platform_request'

        Returns new balance.
        """
        return self._db.force_charge(
            user_id=user_id,
            cost_usd=cost_usd * self._get_multiplier(),
            tx_type=tx_type,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            description=description,
        )

    def check_positive_balance(self, user_id: str) -> bool:
        """Return True if user has positive balance (> 0)."""
        return self._db.get_balance(user_id) > 0

    def try_start_search(self, user_id: str, estimated_cost: float) -> bool:
        """Atomically check balance > 0 and deduct estimated_cost to start a search.

        The global cost multiplier is applied automatically to estimated_cost.
        Returns True if balance was positive and the deduction succeeded,
        False if balance was zero or negative.

        This replaces the separate check_positive_balance() + reserve() pattern.
        A single UPDATE ... WHERE ai_balance_usd > 0 prevents the TOCTOU race
        where two concurrent requests both pass a read-only balance check before
        either deduction lands.

        Pair with settle() to reconcile estimated vs actual cost after search completes.
        """
        return self._db.atomic_check_and_deduct(
            user_id, min_balance=0.0, initial_deduct=estimated_cost * self._get_multiplier()
        )

    def topup(self, user_id: str, amount_usd: float, admin_description: str) -> float:
        """Add amount_usd to user balance.

        Returns new balance.
        """
        return self._db.atomic_topup(user_id, amount_usd, admin_description)

    def get_transactions(self, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent transactions ordered by created_at DESC."""
        return self._db.get_transactions(user_id, limit=limit)
