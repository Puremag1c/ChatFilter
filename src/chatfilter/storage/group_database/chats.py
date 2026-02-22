"""Chat operations for GroupDatabase."""

import json
from typing import Any

# Sentinel value to distinguish "not provided" from None
_UNSET = object()


class ChatsMixin:
    """Mixin providing chat CRUD operations within groups."""

    def save_chat(
        self,
        group_id: str,
        chat_ref: str,
        chat_type: str,
        status: str = "pending",
        assigned_account: str | None = None,
        error: str | None = None,
        chat_id: int | None = None,
        subscribers: int | None = None,
        tried_accounts: list[str] | None = None,
    ) -> int:
        """Save a chat within a group.

        Args:
            group_id: Group identifier
            chat_ref: Chat reference (username, link, or ID)
            chat_type: Chat type (pending/group/forum/channel_comments/channel_no_comments/dead)
            status: Chat status (pending/joining/analyzing/done/failed)
            assigned_account: Account assigned to analyze this chat
            error: Error message if status is failed
            chat_id: Optional explicit chat ID (for updates)
            subscribers: Optional subscriber count for channels
            tried_accounts: Optional list of account_ids that failed (ban/forbidden)

        Returns:
            Chat ID (auto-generated or provided)
        """
        tried_accounts_json = json.dumps(tried_accounts) if tried_accounts else None

        with self._connection() as conn:
            if chat_id is None:
                # Insert new chat
                cursor = conn.execute(
                    """
                    INSERT INTO group_chats
                    (group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts_json),
                )
                return cursor.lastrowid
            else:
                # Update existing chat
                conn.execute(
                    """
                    INSERT INTO group_chats
                    (id, group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        group_id = excluded.group_id,
                        chat_ref = excluded.chat_ref,
                        chat_type = excluded.chat_type,
                        status = excluded.status,
                        assigned_account = excluded.assigned_account,
                        error = excluded.error,
                        subscribers = excluded.subscribers,
                        tried_accounts = excluded.tried_accounts
                    """,
                    (chat_id, group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts_json),
                )
                return chat_id

    def update_chat_status(
        self,
        chat_id: int,
        status: str,
        assigned_account: str | None = _UNSET,
        error: str | None = _UNSET,
        tried_accounts: list[str] | None = _UNSET,
    ) -> None:
        """Update the status of a group chat.

        Args:
            chat_id: Chat ID
            status: New status (pending/joining/analyzing/done/failed)
            assigned_account: Optional account assignment (pass None to clear)
            error: Optional error message (pass None to clear)
            tried_accounts: Optional list of account_ids that failed (ban/forbidden)
        """
        with self._connection() as conn:
            # Build UPDATE statement dynamically based on provided fields
            updates = ["status = ?"]
            params: list[Any] = [status]

            if assigned_account is not _UNSET:
                updates.append("assigned_account = ?")
                params.append(assigned_account)

            if error is not _UNSET:
                updates.append("error = ?")
                params.append(error)

            if tried_accounts is not _UNSET:
                updates.append("tried_accounts = ?")
                params.append(json.dumps(tried_accounts) if tried_accounts else None)

            params.append(chat_id)

            conn.execute(
                f"UPDATE group_chats SET {', '.join(updates)} WHERE id = ?",
                params,
            )

    def load_chats(
        self,
        group_id: str,
        status: str | None = None,
        chat_type: str | None = None,
        assigned_account: str | None = None,
    ) -> list[dict[str, Any]]:
        """Load chats for a group with optional filtering.

        Args:
            group_id: Group identifier
            status: Optional status filter (pending/joining/analyzing/done/failed)
            chat_type: Optional chat_type filter
            assigned_account: Optional assigned account filter

        Returns:
            List of chat data dicts matching the filters
        """
        with self._connection() as conn:
            # Build query with dynamic filters
            query = "SELECT * FROM group_chats WHERE group_id = ?"
            params: list[Any] = [group_id]

            if status is not None:
                query += " AND status = ?"
                params.append(status)

            if chat_type is not None:
                query += " AND chat_type = ?"
                params.append(chat_type)

            if assigned_account is not None:
                query += " AND assigned_account = ?"
                params.append(assigned_account)

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        return [
            {
                "id": row["id"],
                "group_id": row["group_id"],
                "chat_ref": row["chat_ref"],
                "chat_type": row["chat_type"],
                "status": row["status"],
                "assigned_account": row["assigned_account"],
                "error": row["error"],
                "subscribers": row["subscribers"],
                "tried_accounts": json.loads(row["tried_accounts"]) if row["tried_accounts"] else [],
            }
            for row in rows
        ]

    def count_processed_chats(self, group_id: str) -> tuple[int, int]:
        """Count processed and total chats in a group.

        Args:
            group_id: Group identifier

        Returns:
            Tuple of (processed, total) where:
            - processed: count of chats with status in ('done', 'failed') OR chat_type = 'dead'
            - total: count of all chats in group
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    SUM(CASE
                        WHEN status IN ('done', 'failed') OR chat_type = 'dead'
                        THEN 1
                        ELSE 0
                    END) as processed,
                    COUNT(*) as total
                FROM group_chats
                WHERE group_id = ?
                """,
                (group_id,),
            )
            row = cursor.fetchone()

            # Handle empty result (no chats in group)
            processed = row["processed"] or 0
            total = row["total"] or 0

            return (processed, total)
