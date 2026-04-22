"""Database module for chat group storage and analysis tracking."""

from chatfilter.storage.sqlite import SQLiteDatabase

from .analysis_queue import AnalysisQueueMixin
from .app_settings import AppSettingsMixin
from .catalog import CatalogMixin
from .chats import _UNSET, ChatsMixin
from .groups import GroupsMixin
from .metrics import MetricsMixin
from .schema import SchemaMixin
from .stats import StatsMixin
from .subscriptions import SubscriptionsMixin
from .tasks import TasksMixin


class GroupDatabase(
    SchemaMixin,
    GroupsMixin,
    ChatsMixin,
    TasksMixin,
    MetricsMixin,
    StatsMixin,
    CatalogMixin,
    SubscriptionsMixin,
    AnalysisQueueMixin,
    AppSettingsMixin,
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
        - CatalogMixin: Chat catalog CRUD operations
        - AppSettingsMixin: App settings CRUD operations
    """

    pass


__all__ = ["AppSettingsMixin", "CatalogMixin", "GroupDatabase", "SubscriptionsMixin", "_UNSET"]
