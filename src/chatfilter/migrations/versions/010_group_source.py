"""Add source column to chat_groups to track creation origin.

Revision ID: 010
Create Date: 2026-04-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "010"
down_revision: str | None = "009"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("chat_groups") as batch_op:
        batch_op.add_column(sa.Column("source", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("chat_groups") as batch_op:
        batch_op.drop_column("source")
