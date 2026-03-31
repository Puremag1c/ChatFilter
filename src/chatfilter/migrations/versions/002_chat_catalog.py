"""Add chat_catalog, catalog_group_chats, account_subscriptions, app_settings tables.

Revision ID: 002
Create Date: 2026-03-31
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def _table_exists(name: str) -> bool:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    return name in insp.get_table_names()


def _index_exists(table: str, index: str) -> bool:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    return any(idx["name"] == index for idx in insp.get_indexes(table))


def upgrade() -> None:
    if not _table_exists("chat_catalog"):
        op.create_table(
            "chat_catalog",
            sa.Column("id", sa.Text, primary_key=True),
            sa.Column("telegram_id", sa.Integer),
            sa.Column("title", sa.Text),
            sa.Column("chat_type", sa.Text),
            sa.Column("subscribers", sa.Integer),
            sa.Column("moderation", sa.Boolean),
            sa.Column("messages_per_hour", sa.Float),
            sa.Column("unique_authors_per_hour", sa.Float),
            sa.Column("captcha", sa.Boolean),
            sa.Column("partial_data", sa.Boolean),
            sa.Column("last_check", sa.Text),
            sa.Column("analysis_mode", sa.Text),
            sa.Column("created_at", sa.Text),
        )
        op.create_index("idx_chat_catalog_last_check", "chat_catalog", ["last_check"])
        op.create_index("idx_chat_catalog_chat_type", "chat_catalog", ["chat_type"])

    if not _table_exists("catalog_group_chats"):
        op.create_table(
            "catalog_group_chats",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column(
                "catalog_chat_id",
                sa.Text,
                sa.ForeignKey("chat_catalog.id"),
                nullable=False,
            ),
            sa.Column(
                "group_chat_id",
                sa.Integer,
                sa.ForeignKey("group_chats.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.UniqueConstraint("catalog_chat_id", "group_chat_id", name="uq_catalog_group_chats"),
        )

    if not _table_exists("account_subscriptions"):
        op.create_table(
            "account_subscriptions",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("account_id", sa.Text, nullable=False),
            sa.Column(
                "catalog_chat_id",
                sa.Text,
                sa.ForeignKey("chat_catalog.id"),
            ),
            sa.Column("telegram_chat_id", sa.Integer),
            sa.Column("joined_at", sa.Text, nullable=False),
            sa.UniqueConstraint("account_id", "catalog_chat_id", name="uq_account_subscriptions"),
        )
        op.create_index("idx_account_subs_account", "account_subscriptions", ["account_id"])
        op.create_index("idx_account_subs_joined", "account_subscriptions", ["joined_at"])

    if not _table_exists("app_settings"):
        op.create_table(
            "app_settings",
            sa.Column("key", sa.Text, primary_key=True),
            sa.Column("value", sa.Text, nullable=False),
            sa.Column("updated_at", sa.Text, nullable=False),
        )

    # Seed default app_settings
    conn = op.get_bind()
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    defaults = [
        ("max_chats_per_account", "300"),
        ("analysis_freshness_days", "7"),
    ]
    for key, value in defaults:
        existing = conn.execute(
            sa.text("SELECT 1 FROM app_settings WHERE key = :key"), {"key": key}
        ).fetchone()
        if not existing:
            conn.execute(
                sa.text(
                    "INSERT INTO app_settings (key, value, updated_at) VALUES (:key, :value, :updated_at)"
                ),
                {"key": key, "value": value, "updated_at": now},
            )

    # Data migration: populate chat_catalog from existing group_chats
    # Deduplicate by chat_ref, keeping freshest data (highest id = most recent analysis)
    existing_catalog = conn.execute(
        sa.text("SELECT id FROM chat_catalog LIMIT 1")
    ).fetchone()

    if existing_catalog is None:
        # Check if group_chats has any data
        rows = conn.execute(
            sa.text(
                """
                SELECT chat_ref, title, chat_type, subscribers, moderation,
                       messages_per_hour, unique_authors_per_hour, captcha,
                       partial_data, id
                FROM group_chats
                WHERE chat_ref IS NOT NULL
                  AND chat_ref != ''
                ORDER BY id DESC
                """
            )
        ).fetchall()

        now = datetime.now(timezone.utc).isoformat()
        seen: set[str] = set()
        catalog_rows = []
        for row in rows:
            chat_ref = row[0]
            if chat_ref in seen:
                continue
            seen.add(chat_ref)
            catalog_rows.append(
                {
                    "id": chat_ref,
                    "title": row[1],
                    "chat_type": row[2] if row[2] in (
                        "group", "forum", "channel_comments",
                        "channel_no_comments", "dead"
                    ) else "pending",
                    "subscribers": row[3],
                    "moderation": row[4],
                    "messages_per_hour": row[5],
                    "unique_authors_per_hour": row[6],
                    "captcha": row[7],
                    "partial_data": row[8],
                    "created_at": now,
                }
            )

        for cr in catalog_rows:
            conn.execute(
                sa.text(
                    """
                    INSERT INTO chat_catalog
                        (id, title, chat_type, subscribers, moderation,
                         messages_per_hour, unique_authors_per_hour, captcha,
                         partial_data, created_at)
                    VALUES
                        (:id, :title, :chat_type, :subscribers, :moderation,
                         :messages_per_hour, :unique_authors_per_hour, :captcha,
                         :partial_data, :created_at)
                    """
                ),
                cr,
            )

        # Create catalog_group_chats links
        link_rows = conn.execute(
            sa.text(
                """
                SELECT id, chat_ref FROM group_chats
                WHERE chat_ref IS NOT NULL AND chat_ref != ''
                """
            )
        ).fetchall()

        for link_row in link_rows:
            group_chat_id = link_row[0]
            chat_ref = link_row[1]
            if chat_ref not in seen:
                continue
            conn.execute(
                sa.text(
                    """
                    INSERT OR IGNORE INTO catalog_group_chats (catalog_chat_id, group_chat_id)
                    VALUES (:catalog_chat_id, :group_chat_id)
                    """
                ),
                {"catalog_chat_id": chat_ref, "group_chat_id": group_chat_id},
            )


def downgrade() -> None:
    op.drop_table("account_subscriptions")
    op.drop_table("catalog_group_chats")
    op.drop_table("chat_catalog")
    op.drop_table("app_settings")
