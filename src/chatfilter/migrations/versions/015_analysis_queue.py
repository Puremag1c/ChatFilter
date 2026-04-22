"""Create analysis_queue table + its indexes.

Phase 3 of the redesign. One row per chat-task — the atomic unit the
scheduler in Phase 4 will pick up, assign to a free slot, run, and mark
terminal. ``pool_key`` separates admin-shared work from power-users who
opt into their own accounts; ``charged_amount`` is filled by Phase 5's
pre-charge and refunded on ERROR.

Indexes are deliberate:
  * (status, pool_key, created_at) — the FairShare claim selects by
    these three columns in that order.
  * (user_id, status)               — the "how many running tasks does
    this user currently hold?" sub-query.
  * (group_chat_id)                 — for bulk "cancel group" ops.

Revision ID: 015
Create Date: 2026-04-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "015"
down_revision: str | None = "014"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "analysis_queue",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("group_id", sa.String(), sa.ForeignKey("chat_groups.id"), nullable=False),
        sa.Column(
            "group_chat_id",
            sa.Integer(),
            sa.ForeignKey("group_chats.id"),
            nullable=False,
        ),
        sa.Column("chat_ref", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("pool_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("account_id", sa.String(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("charged_amount", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_analysis_queue_status_pool_created",
        "analysis_queue",
        ["status", "pool_key", "created_at"],
    )
    op.create_index(
        "idx_analysis_queue_user_status",
        "analysis_queue",
        ["user_id", "status"],
    )
    op.create_index(
        "idx_analysis_queue_group_chat",
        "analysis_queue",
        ["group_chat_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_analysis_queue_group_chat", table_name="analysis_queue")
    op.drop_index("idx_analysis_queue_user_status", table_name="analysis_queue")
    op.drop_index("idx_analysis_queue_status_pool_created", table_name="analysis_queue")
    op.drop_table("analysis_queue")
