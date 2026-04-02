"""AI billing service.

BillingService wraps UserDatabase balance/transaction methods and provides
high-level charge/topup operations for AI usage.
"""

from __future__ import annotations

from chatfilter.storage.user_database import UserDatabase


class InsufficientBalance(Exception):
    """Raised when a user has insufficient AI balance."""


class BillingService:
    """Service for AI billing operations.

    Accepts a UserDatabase instance via dependency injection.
    All balance and transaction state lives in the DB — this class
    contains only business logic.
    """

    def __init__(self, db: UserDatabase) -> None:
        self._db = db

    def get_balance(self, user_id: str) -> float:
        """Return current balance in USD."""
        return self._db.get_balance(user_id)

    def check_balance(self, user_id: str) -> bool:
        """Return True if user has positive balance."""
        return self._db.get_balance(user_id) > 0

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

        Raises InsufficientBalance if balance <= 0.
        Returns new balance.
        """
        balance = self._db.get_balance(user_id)
        if balance <= 0:
            raise InsufficientBalance(f"User {user_id} has insufficient balance: {balance:.6f} USD")
        new_balance = balance - cost_usd
        self._db.update_balance(user_id, new_balance)
        self._db.add_transaction(
            user_id=user_id,
            transaction_type="charge",
            amount_usd=-cost_usd,
            balance_after=new_balance,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            description=description,
        )
        return new_balance

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

    def get_transactions(self, user_id: str, limit: int = 50) -> list[dict]:
        """Return recent transactions ordered by created_at DESC."""
        return self._db.get_transactions(user_id, limit=limit)
