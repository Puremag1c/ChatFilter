"""Test helper functions for working with v5 schema.

These functions provide compatibility layer for tests that used the old
group_results table API. In v5, metrics are stored directly in group_chats columns.
"""

from __future__ import annotations

from datetime import UTC, datetime

from chatfilter.models.group import GroupChatStatus
from chatfilter.storage.group_database import GroupDatabase


def save_test_result(db: GroupDatabase, group_id: str, chat_ref: str, metrics: dict) -> None:
    """Save result for a chat (compatibility helper for v5 schema).

    In v5, metrics are in group_chats columns, not separate group_results table.

    Args:
        db: Database instance
        group_id: Group ID
        chat_ref: Chat reference
        metrics: Metrics dict (includes status, error_reason if dead, etc.)
    """
    # Find chat by (group_id, chat_ref)
    chats = db.load_chats(group_id=group_id)
    chat = next((c for c in chats if c["chat_ref"] == chat_ref), None)

    if not chat:
        raise ValueError(f"Chat not found: {chat_ref}")

    chat_id = chat["id"]
    status_value = metrics.get("status", "done")

    # Extract error_reason if present (for dead chats)
    error_reason = metrics.get("error_reason")

    # Save metrics
    db.save_chat_metrics(chat_id, metrics)

    # Update chat_type and subscribers (not in save_chat_metrics)
    with db._connection() as conn:
        conn.execute(
            """
            UPDATE group_chats
            SET chat_type = ?,
                subscribers = ?,
                error = ?
            WHERE id = ?
            """,
            (
                metrics.get("chat_type"),
                metrics.get("subscribers"),
                error_reason,
                chat_id,
            ),
        )

    # Update status if needed
    if status_value == "done":
        db.update_chat_status(chat_id, GroupChatStatus.DONE.value, None)
    elif status_value == "dead":
        db.update_chat_status(chat_id, GroupChatStatus.ERROR.value, error_reason)


def load_test_result(db: GroupDatabase, group_id: str, chat_ref: str) -> dict | None:
    """Load result for a chat (compatibility helper for v5 schema).

    Returns:
        Dict with 'metrics_data' key containing all metrics, or None if chat not found
    """
    # Find chat
    chats = db.load_chats(group_id=group_id)
    chat = next((c for c in chats if c["chat_ref"] == chat_ref), None)

    if not chat:
        return None

    # Check if chat has metrics (title not NULL means has metrics)
    metrics = db.get_chat_metrics(chat["id"])

    # If no metrics, return None
    if not metrics.get("title") and metrics.get("chat_type") != "dead":
        return None

    # Build result dict compatible with old API
    status = "dead" if chat["status"] == GroupChatStatus.ERROR.value else "done"

    return {
        "chat_ref": chat_ref,
        "analyzed_at": datetime.now(UTC),  # Timestamp not stored in v5
        "metrics_data": {
            "chat_ref": chat_ref,
            "chat_type": metrics.get("chat_type") or chat["chat_type"],
            "title": metrics.get("title"),
            "subscribers": metrics.get("subscribers") or chat.get("subscribers"),
            "moderation": metrics.get("moderation"),
            "messages_per_hour": metrics.get("messages_per_hour"),
            "unique_authors_per_hour": metrics.get("unique_authors_per_hour"),
            "captcha": metrics.get("captcha"),
            "status": status,
            "error_reason": chat.get("error") if status == "dead" else None,
        },
    }


def load_test_results(db: GroupDatabase, group_id: str) -> list[dict]:
    """Load all results for a group (compatibility helper for v5 schema).

    Returns:
        List of result dicts with 'metrics_data' key
    """
    chats = db.load_chats(group_id=group_id)
    results = []

    for chat in chats:
        # Only include chats that have metrics (processed chats)
        metrics = db.get_chat_metrics(chat["id"])

        # Skip chats without metrics (pending/joining)
        if not metrics.get("title") and metrics.get("chat_type") != "dead":
            continue

        status = "dead" if chat["status"] == GroupChatStatus.ERROR.value else "done"

        results.append({
            "chat_ref": chat["chat_ref"],
            "analyzed_at": datetime.now(UTC),
            "metrics_data": {
                "chat_ref": chat["chat_ref"],
                "chat_type": metrics.get("chat_type") or chat["chat_type"],
                "title": metrics.get("title"),
                "subscribers": metrics.get("subscribers") or chat.get("subscribers"),
                "moderation": metrics.get("moderation"),
                "messages_per_hour": metrics.get("messages_per_hour"),
                "unique_authors_per_hour": metrics.get("unique_authors_per_hour"),
                "captcha": metrics.get("captcha"),
                "status": status,
                "error_reason": chat.get("error") if status == "dead" else None,
            },
        })

    return results


def upsert_test_result(db: GroupDatabase, group_id: str, chat_ref: str, metrics: dict) -> None:
    """Upsert result (preserve existing non-None values).

    Args:
        db: Database instance
        group_id: Group ID
        chat_ref: Chat reference
        metrics: Metrics dict (None values preserve existing)
    """
    # Find chat
    chats = db.load_chats(group_id=group_id)
    chat = next((c for c in chats if c["chat_ref"] == chat_ref), None)

    if not chat:
        raise ValueError(f"Chat not found: {chat_ref}")

    chat_id = chat["id"]

    # Load existing metrics
    existing_metrics = db.get_chat_metrics(chat_id)

    # Merge: new value if not None, else keep existing
    merged_metrics = {
        "title": metrics.get("title") if metrics.get("title") is not None else existing_metrics.get("title"),
        "moderation": metrics.get("moderation") if metrics.get("moderation") is not None else existing_metrics.get("moderation"),
        "messages_per_hour": metrics.get("messages_per_hour") if metrics.get("messages_per_hour") is not None else existing_metrics.get("messages_per_hour"),
        "unique_authors_per_hour": metrics.get("unique_authors_per_hour") if metrics.get("unique_authors_per_hour") is not None else existing_metrics.get("unique_authors_per_hour"),
        "captcha": metrics.get("captcha") if metrics.get("captcha") is not None else existing_metrics.get("captcha"),
        "partial_data": metrics.get("partial_data") if metrics.get("partial_data") is not None else existing_metrics.get("partial_data"),
        "metrics_version": metrics.get("metrics_version") if metrics.get("metrics_version") is not None else existing_metrics.get("metrics_version"),
    }

    # Save merged metrics
    db.save_chat_metrics(chat_id, merged_metrics)

    # Update chat_type and subscribers if provided
    chat_type = metrics.get("chat_type") if metrics.get("chat_type") is not None else existing_metrics.get("chat_type")
    subscribers = metrics.get("subscribers") if metrics.get("subscribers") is not None else (existing_metrics.get("subscribers") or chat.get("subscribers"))

    with db._connection() as conn:
        conn.execute(
            """
            UPDATE group_chats
            SET chat_type = ?,
                subscribers = ?
            WHERE id = ?
            """,
            (chat_type, subscribers, chat_id),
        )


def clear_test_results(db: GroupDatabase, group_id: str) -> None:
    """Clear all results for a group (set metrics to NULL).

    Args:
        db: Database instance
        group_id: Group ID
    """
    with db._connection() as conn:
        conn.execute(
            """
            UPDATE group_chats
            SET title = NULL,
                moderation = NULL,
                messages_per_hour = NULL,
                unique_authors_per_hour = NULL,
                captcha = NULL,
                partial_data = NULL,
                metrics_version = NULL,
                subscribers = NULL
            WHERE group_id = ?
            """,
            (group_id,),
        )
