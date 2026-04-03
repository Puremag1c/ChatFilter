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

        The global cost multiplier is applied automatically to actual_cost.
        reserved_cost must be the already-multiplied value returned by reserve().
        Refunds if actual < reserved; charges extra (capped) if actual > reserved.
        Records transaction for actual_cost * multiplier.

        Returns new balance.
        """
        return self._db.settle_reserve(
            user_id=user_id,
            reserved_cost=reserved_cost,
            actual_cost=actual_cost * self._get_multiplier(),
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

    def topup(self, user_id: str, amount_usd: float, admin_description: str) -> float:
        """Add amount_usd to user balance.

        Returns new balance.
        """
        balance = self._db.get_balance(user_id)
        new_balance = balance + amount_usd
        self._db.update_balance(user_id, new_balance)
        self._db.add_transaction(
            user_id=user_id,
            transaction_type="topup",
            amount_usd=amount_usd,
            balance_after=new_balance,
            description=admin_description,
        )
        return new_balance

    def get_transactions(self, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent transactions ordered by created_at DESC."""
        return self._db.get_transactions(user_id, limit=limit)
