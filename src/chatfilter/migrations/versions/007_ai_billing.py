"""Add AI billing: ai_balance_usd on users, ai_transactions table.

Revision ID: 007
Create Date: 2026-04-02
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: str | None = "006"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Add ai_balance_usd column to users (default 0.0)
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("ai_balance_usd", sa.Float(), nullable=False, server_default="1.0")
        )

    # Create ai_transactions table
    op.create_table(
        "ai_transactions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id", sa.Text(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("amount_usd", sa.Float(), nullable=False),
        sa.Column("balance_after", sa.Float(), nullable=False),
        sa.Column("model", sa.Text()),
        sa.Column("tokens_in", sa.Integer()),
        sa.Column("tokens_out", sa.Integer()),
        sa.Column("description", sa.Text()),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("idx_ai_transactions_user_id", "ai_transactions", ["user_id"])
    op.create_index("idx_ai_transactions_created_at", "ai_transactions", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_ai_transactions_created_at", "ai_transactions")
    op.drop_index("idx_ai_transactions_user_id", "ai_transactions")
    op.drop_table("ai_transactions")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("ai_balance_usd")
