"""Add username column to chat_catalog.

Revision ID: 005
Create Date: 2026-03-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: str | None = "002"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def _column_exists(table: str, column: str) -> bool:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    return any(col["name"] == column for col in insp.get_columns(table))


def upgrade() -> None:
    if not _column_exists("chat_catalog", "username"):
        op.add_column("chat_catalog", sa.Column("username", sa.Text, nullable=True))


def downgrade() -> None:
    op.drop_column("chat_catalog", "username")
