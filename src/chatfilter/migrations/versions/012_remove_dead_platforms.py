"""Remove dead platform_settings rows for google_search and baza_tg.

Revision ID: 012
Create Date: 2026-04-06
"""

from __future__ import annotations

from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Remove google_search and baza_tg from platform_settings."""
    op.execute("DELETE FROM platform_settings WHERE id IN ('google_search', 'baza_tg')")


def downgrade() -> None:
    """Restore google_search and baza_tg rows (disabled)."""
    op.execute(
        """
        INSERT INTO platform_settings (id, api_key, cost_per_request_usd, enabled)
        VALUES ('google_search', NULL, 0, 0),
               ('baza_tg', NULL, 0, 0)
        ON CONFLICT(id) DO NOTHING
        """
    )
