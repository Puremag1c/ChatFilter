"""Initial schema.

Revision ID: 001
Create Date: 2026-03-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: str | None = None
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def _table_exists(name: str) -> bool:
    """Check if a table already exists (for adopting existing databases)."""
    conn = op.get_bind()
    insp = sa.inspect(conn)
    return name in insp.get_table_names()


def upgrade() -> None:
    if not _table_exists("chat_groups"):
        op.create_table(
            "chat_groups",
            sa.Column("id", sa.Text, primary_key=True),
            sa.Column("name", sa.Text, nullable=False),
            sa.Column("settings", sa.Text, nullable=False),
            sa.Column("status", sa.Text, nullable=False),
            sa.Column("created_at", sa.Text, nullable=False),
            sa.Column("updated_at", sa.Text, nullable=False),
            sa.Column("analysis_started_at", sa.Text),
            sa.Column("user_id", sa.Text, nullable=False, server_default=""),
        )
        op.create_index("idx_chat_groups_user_id", "chat_groups", ["user_id"])

    if not _table_exists("group_chats"):
        op.create_table(
            "group_chats",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column(
                "group_id",
                sa.Text,
                sa.ForeignKey("chat_groups.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("chat_ref", sa.Text, nullable=False),
            sa.Column("chat_type", sa.Text, nullable=False),
            sa.Column("status", sa.Text, nullable=False),
            sa.Column("assigned_account", sa.Text),
            sa.Column("error", sa.Text),
            sa.Column("subscribers", sa.Integer),
            sa.Column("tried_accounts", sa.Text),
            sa.Column("title", sa.Text),
            sa.Column("moderation", sa.Boolean),
            sa.Column("messages_per_hour", sa.Float),
            sa.Column("unique_authors_per_hour", sa.Float),
            sa.Column("captcha", sa.Boolean),
            sa.Column("partial_data", sa.Boolean),
            sa.Column("metrics_version", sa.Integer),
        )
        op.create_index("idx_group_chats_group_id", "group_chats", ["group_id"])

    if not _table_exists("group_tasks"):
        op.create_table(
            "group_tasks",
            sa.Column("id", sa.Text, primary_key=True),
            sa.Column(
                "group_id",
                sa.Text,
                sa.ForeignKey("chat_groups.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("requested_metrics", sa.Text),
            sa.Column("time_window", sa.Text),
            sa.Column("created_at", sa.Text, nullable=False),
            sa.Column("status", sa.Text, nullable=False),
        )

    if not _table_exists("users"):
        op.create_table(
            "users",
            sa.Column("id", sa.Text, primary_key=True),
            sa.Column("username", sa.Text, unique=True, nullable=False),
            sa.Column("password_hash", sa.Text, nullable=False),
            sa.Column("is_admin", sa.Integer, nullable=False, server_default="0"),
            sa.Column("created_at", sa.Text, nullable=False),
        )
        op.create_index("idx_users_username", "users", ["username"])


def downgrade() -> None:
    op.drop_table("group_tasks")
    op.drop_table("group_chats")
    op.drop_table("chat_groups")
    op.drop_table("users")
