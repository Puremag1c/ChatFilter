"""Add scraping status + platform_settings table + cost_multiplier setting.

Revision ID: 009
Create Date: 2026-04-03
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "009"
down_revision: str | None = "008"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Create platform_settings table
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("api_key", sa.Text()),
        sa.Column("cost_per_request_usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("extra_config", sa.Text()),  # stored as JSON string
    )

    # Insert default cost_multiplier into app_settings (if not already set)
    op.execute(
        """
        INSERT INTO app_settings (key, value, updated_at)
        VALUES ('cost_multiplier', '1.0', datetime('now'))
        ON CONFLICT(key) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_table("platform_settings")
    op.execute("DELETE FROM app_settings WHERE key = 'cost_multiplier'")
