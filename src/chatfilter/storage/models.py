"""SQLAlchemy table definitions.

These mirror the existing schema created by group_database/schema.py
and user_database.py. They are used by Alembic for migration generation
and can be used for SQLAlchemy Core queries in the future.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
)

metadata = MetaData()

chat_groups = Table(
    "chat_groups",
    metadata,
    Column("id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("settings", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_at", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
    Column("analysis_started_at", Text),
    Column("user_id", Text, nullable=False, server_default=""),
    Index("idx_chat_groups_user_id", "user_id"),
)

group_chats = Table(
    "group_chats",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("group_id", Text, ForeignKey("chat_groups.id", ondelete="CASCADE"), nullable=False),
    Column("chat_ref", Text, nullable=False),
    Column("chat_type", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("assigned_account", Text),
    Column("error", Text),
    Column("subscribers", Integer),
    Column("tried_accounts", Text),
    Column("title", Text),
    Column("moderation", Boolean),
    Column("messages_per_hour", Float),
    Column("unique_authors_per_hour", Float),
    Column("captcha", Boolean),
    Column("partial_data", Boolean),
    Column("metrics_version", Integer),
    Index("idx_group_chats_group_id", "group_id"),
)

group_tasks = Table(
    "group_tasks",
    metadata,
    Column("id", Text, primary_key=True),
    Column("group_id", Text, ForeignKey("chat_groups.id", ondelete="CASCADE"), nullable=False),
    Column("requested_metrics", Text),
    Column("time_window", Text),
    Column("created_at", Text, nullable=False),
    Column("status", Text, nullable=False),
)

users = Table(
    "users",
    metadata,
    Column("id", Text, primary_key=True),
    Column("username", Text, unique=True, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("is_admin", Integer, nullable=False, server_default="0"),
    Column("created_at", Text, nullable=False),
    Column("ai_balance_usd", Float, nullable=False, server_default="1.0"),
    Index("idx_users_username", "username"),
)

chat_catalog = Table(
    "chat_catalog",
    metadata,
    Column("id", Text, primary_key=True),
    Column("telegram_id", Integer),
    Column("title", Text),
    Column("chat_type", Text),
    Column("subscribers", Integer),
    Column("moderation", Boolean),
    Column("messages_per_hour", Float),
    Column("unique_authors_per_hour", Float),
    Column("captcha", Boolean),
    Column("partial_data", Boolean),
    Column("last_check", Text),
    Column("analysis_mode", Text),
    Column("created_at", Text),
    Index("idx_chat_catalog_last_check", "last_check"),
    Index("idx_chat_catalog_chat_type", "chat_type"),
)

catalog_group_chats = Table(
    "catalog_group_chats",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("catalog_chat_id", Text, ForeignKey("chat_catalog.id"), nullable=False),
    Column(
        "group_chat_id", Integer, ForeignKey("group_chats.id", ondelete="CASCADE"), nullable=False
    ),
)

account_subscriptions = Table(
    "account_subscriptions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("account_id", Text, nullable=False),
    Column("catalog_chat_id", Text, ForeignKey("chat_catalog.id")),
    Column("telegram_chat_id", Integer),
    Column("joined_at", Text, nullable=False),
    Index("idx_account_subs_account", "account_id"),
    Index("idx_account_subs_joined", "joined_at"),
)

app_settings = Table(
    "app_settings",
    metadata,
    Column("key", Text, primary_key=True),
    Column("value", Text, nullable=False),
    Column("updated_at", Text, nullable=False),
)

ai_transactions = Table(
    "ai_transactions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Text, ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("type", Text, nullable=False),  # 'charge' | 'topup'
    Column("amount_usd", Float, nullable=False),
    Column("balance_after", Float, nullable=False),
    Column("model", Text),
    Column("tokens_in", Integer),
    Column("tokens_out", Integer),
    Column("description", Text),
    Column("created_at", Text, nullable=False),
    Index("idx_ai_transactions_user_id", "user_id"),
    Index("idx_ai_transactions_created_at", "created_at"),
)
