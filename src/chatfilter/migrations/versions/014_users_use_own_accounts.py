"""Add users.use_own_accounts boolean (default 0).

Phase 2 of the redesign: sessions and proxies move under admin ownership
by default. The per-user opt-in flag that says "I want to keep my own
accounts/proxies and run my analyses on them" lives on the users row.

The column is added in Phase 2 (UI toggle visible in Profile, stored in
DB) but has no runtime effect until Phase 4 wires pool-routing into the
scheduler.

Revision ID: 014
Create Date: 2026-04-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "014"
down_revision: str | None = "013"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "use_own_accounts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("use_own_accounts")
