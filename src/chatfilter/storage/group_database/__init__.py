"""Database module for chat group storage and analysis tracking."""

from chatfilter.storage.database import SQLiteDatabase

from .chats import ChatsMixin
from .groups import GroupsMixin
from .metrics import MetricsMixin
from .schema import SchemaMixin
from .stats import StatsMixin
from .tasks import TasksMixin


class GroupDatabase(
    SchemaMixin,
    GroupsMixin,
    ChatsMixin,
    TasksMixin,
    MetricsMixin,
    StatsMixin,
    SQLiteDatabase,
):
    """SQLite database for persisting chat group data and analysis results.

    Tables:
        - chat_groups: Group metadata and settings
        - group_chats: Individual chats within groups (includes metrics columns)
        - group_tasks: Analysis tasks for groups

    This class combines multiple mixins to organize code by domain:
        - SchemaMixin: Schema initialization and migrations
        - GroupsMixin: Group CRUD operations
        - ChatsMixin: Chat CRUD operations
        - TasksMixin: Task management
        - MetricsMixin: Metrics CRUD operations
        - StatsMixin: Statistics and aggregations
    """

    pass


# Re-export the sentinel value from chats module for backwards compatibility
from .chats import _UNSET

__all__ = ["GroupDatabase", "_UNSET"]
