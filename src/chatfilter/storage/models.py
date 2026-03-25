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
    Index("idx_users_username", "username"),
)
