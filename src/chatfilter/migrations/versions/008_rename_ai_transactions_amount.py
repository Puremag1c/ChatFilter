"""Rename ai_transactions.amount → amount_usd.

Migration 007 was initially deployed with column name ``amount`` and later
edited in-place to ``amount_usd``. Existing databases still have the old name.
This migration renames the column for those databases; fresh databases already
have ``amount_usd`` from migration 007 and are not affected.

Revision ID: 008
Create Date: 2026-04-02
"""

from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision: str = "008"
down_revision: str | None = "007"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    bind = op.get_bind()
    result = bind.execute(text("PRAGMA table_info(ai_transactions)"))
    columns = [row[1] for row in result]
    if "amount" in columns and "amount_usd" not in columns:
        with op.batch_alter_table("ai_transactions") as batch_op:
            batch_op.alter_column("amount", new_column_name="amount_usd")


def downgrade() -> None:
    bind = op.get_bind()
    result = bind.execute(text("PRAGMA table_info(ai_transactions)"))
    columns = [row[1] for row in result]
    if "amount_usd" in columns and "amount" not in columns:
        with op.batch_alter_table("ai_transactions") as batch_op:
            batch_op.alter_column("amount_usd", new_column_name="amount")
