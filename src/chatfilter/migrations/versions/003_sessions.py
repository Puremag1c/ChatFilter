"""Add persistent sessions table.

Revision ID: 003
Create Date: 2026-03-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: str | None = "005"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def _table_exists(name: str) -> bool:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    return name in insp.get_table_names()


def upgrade() -> None:
    if not _table_exists("sessions"):
        op.create_table(
            "sessions",
            sa.Column("session_id", sa.Text, primary_key=True),
            sa.Column("data", sa.Text, nullable=False),
            sa.Column("created_at", sa.Float, nullable=False),
            sa.Column("last_accessed", sa.Float, nullable=False),
        )
        op.create_index("idx_sessions_last_accessed", "sessions", ["last_accessed"])


def downgrade() -> None:
    op.drop_index("idx_sessions_last_accessed", table_name="sessions")
    op.drop_table("sessions")
