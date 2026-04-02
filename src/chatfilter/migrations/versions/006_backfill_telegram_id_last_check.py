"""Backfill telegram_id and last_check in chat_catalog.

Revision ID: 006
Create Date: 2026-04-02
"""

from __future__ import annotations

from alembic import op

revision: str = "006"
down_revision: str | None = "003"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE chat_catalog SET telegram_id = CAST(SUBSTR(id, 5) AS INTEGER) "
        "WHERE (telegram_id = 0 OR telegram_id IS NULL) AND id LIKE '-100%'"
    )
    op.execute(
        "UPDATE chat_catalog SET last_check = created_at "
        "WHERE last_check IS NULL AND created_at IS NOT NULL"
    )


def downgrade() -> None:
    pass  # Data was missing before; no way to restore
