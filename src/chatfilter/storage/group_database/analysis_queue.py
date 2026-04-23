"""Analysis-queue operations.

One row per chat-task, picked up by the Phase-4 scheduler. The helpers
here encode the business rules that later phases assume:

    - ``enqueue_chat_task`` inserts a queued task.
    - ``claim_next_task`` atomically moves one queued task to running
      for a specific account, respecting FairShare (a cap on how many
      tasks one user may have running simultaneously) and pool isolation
      (admin vs. user:{id}).
    - ``mark_task_done`` / ``mark_task_error`` finalise a running task.
    - ``reset_running_tasks_to_queued`` — crash recovery on startup.

Atomicity: claim_next is wrapped in BEGIN IMMEDIATE so SQLite serialises
the read-select-update sequence; with uvicorn running single-process
this is sufficient.  On PostgreSQL the same SQL works under SELECT FOR
UPDATE SKIP LOCKED without code changes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ._base import DatabaseMixinBase


class AnalysisQueueMixin(DatabaseMixinBase):
    """Mixin for the analysis_queue table."""

    # ---- enqueue / claim -------------------------------------------

    def enqueue_chat_task(
        self,
        group_id: str,
        group_chat_id: int,
        chat_ref: str,
        user_id: str,
        pool_key: str,
    ) -> int:
        """Insert a fresh queued task. Returns the new task id."""
        now = datetime.now(UTC)
        with self._connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO analysis_queue
                  (group_id, group_chat_id, chat_ref, user_id, pool_key,
                   status, attempts, charged_amount, created_at)
                VALUES (?, ?, ?, ?, ?, 'queued', 0, 0, ?)
                """,
                (group_id, group_chat_id, chat_ref, user_id, pool_key, now),
            )
            return int(cursor.lastrowid or 0)

    def claim_next_task(
        self,
        pool_key: str,
        account_id: str,
        user_limit: int,
    ) -> dict[str, Any] | None:
        """Atomically pick one queued task from ``pool_key`` for ``account_id``.

        Respects the FairShare cap: a user who already holds
        ``user_limit`` running tasks is skipped, yielding the slot to
        someone else.  Returns the claimed row as a dict, or None if
        nothing is eligible.
        """
        now = datetime.now(UTC)
        with self._connection() as conn:
            # Ensure the whole select-update pair is serialised.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    """
                    SELECT q.id, q.group_id, q.group_chat_id, q.chat_ref,
                           q.user_id, q.pool_key
                    FROM analysis_queue AS q
                    WHERE q.status = 'queued'
                      AND q.pool_key = ?
                      AND (
                        SELECT COUNT(*) FROM analysis_queue AS r
                        WHERE r.user_id = q.user_id
                          AND r.status = 'running'
                      ) < ?
                    ORDER BY q.created_at ASC, q.id ASC
                    LIMIT 1
                    """,
                    (pool_key, user_limit),
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return None
                task_id = row["id"]
                conn.execute(
                    """
                    UPDATE analysis_queue
                       SET status = 'running',
                           account_id = ?,
                           started_at = ?
                     WHERE id = ?
                    """,
                    (account_id, now, task_id),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            return {
                "id": task_id,
                "group_id": row["group_id"],
                "group_chat_id": row["group_chat_id"],
                "chat_ref": row["chat_ref"],
                "user_id": row["user_id"],
                "pool_key": row["pool_key"],
                "account_id": account_id,
            }

    # ---- finalisation ----------------------------------------------

    def mark_task_done(self, task_id: int) -> None:
        now = datetime.now(UTC)
        with self._connection() as conn:
            conn.execute(
                "UPDATE analysis_queue SET status = 'done', finished_at = ? WHERE id = ?",
                (now, task_id),
            )

    def mark_task_error(self, task_id: int, error: str) -> None:
        now = datetime.now(UTC)
        with self._connection() as conn:
            conn.execute(
                "UPDATE analysis_queue "
                "SET status = 'error', error = ?, finished_at = ? "
                "WHERE id = ?",
                (error, now, task_id),
            )

    def requeue_task(self, task_id: int) -> int:
        """Put a crashed task back onto the queue for another account to try.

        Used by the scheduler when ``process_chat`` raises an unexpected
        exception and the per-task attempt counter is still below the
        retry cap. Clears ``account_id`` / ``started_at`` so the next
        ``claim_next_task`` picks it up freshly; bumps ``attempts``
        so the caller can stop after N retries.

        Returns the new attempts value.
        """
        now = datetime.now(UTC)
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE analysis_queue
                   SET status = 'queued',
                       account_id = NULL,
                       started_at = NULL,
                       attempts = attempts + 1,
                       finished_at = ?
                 WHERE id = ?
                """,
                (now, task_id),
            )
            row = conn.execute(
                "SELECT attempts FROM analysis_queue WHERE id = ?", (task_id,)
            ).fetchone()
            return int(row["attempts"]) if row else 0

    def get_task_attempts(self, task_id: int) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT attempts FROM analysis_queue WHERE id = ?", (task_id,)
            ).fetchone()
            return int(row["attempts"]) if row else 0

    # ---- lifecycle / recovery --------------------------------------

    def reset_running_tasks_to_queued(self) -> int:
        """On startup, return tasks stranded as 'running' to the queue.

        Increments ``attempts`` and clears ``account_id`` so another
        account may pick them.  Returns the number of rows reset.
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE analysis_queue
                   SET status = 'queued',
                       account_id = NULL,
                       started_at = NULL,
                       attempts = attempts + 1
                 WHERE status = 'running'
                """
            )
            return int(cursor.rowcount or 0)

    def cancel_group_tasks(self, group_id: str) -> int:
        """Mark all queued tasks of a group as cancelled.

        Running tasks are left alone — they finish naturally, after
        which callers may decide how to record the result.
        """
        now = datetime.now(UTC)
        with self._connection() as conn:
            cursor = conn.execute(
                "UPDATE analysis_queue "
                "SET status = 'cancelled', finished_at = ? "
                "WHERE group_id = ? AND status = 'queued'",
                (now, group_id),
            )
            return int(cursor.rowcount or 0)

    # ---- cost_per_chat (Phase 5 billing) ---------------------------

    _COST_PER_CHAT_KEY = "cost_per_chat"

    def get_cost_per_chat(self) -> float:
        """Admin-configured price charged to the user for every DONE chat.

        Lives in the key/value app_settings table; returns 0.0 when unset
        so a fresh deployment charges nothing until the admin opts in.
        """
        raw = self.get_setting(self._COST_PER_CHAT_KEY)  # type: ignore[attr-defined]
        if raw is None or raw == "":
            return 0.0
        try:
            return float(raw)
        except ValueError:
            return 0.0

    def set_cost_per_chat(self, value: float) -> None:
        if value < 0:
            raise ValueError("cost_per_chat cannot be negative")
        self.set_setting(self._COST_PER_CHAT_KEY, str(value))  # type: ignore[attr-defined]

    # ---- Phase 6: runtime switch flag -------------------------------

    _USE_QUEUE_KEY = "use_scheduler_queue"

    def get_use_scheduler_queue(self) -> bool:
        """Whether /start should enqueue rows instead of running in-memory."""
        raw = self.get_setting(self._USE_QUEUE_KEY)  # type: ignore[attr-defined]
        return raw in ("1", "true", "True", "yes")

    def set_use_scheduler_queue(self, value: bool) -> None:
        self.set_setting(self._USE_QUEUE_KEY, "1" if value else "0")  # type: ignore[attr-defined]

    # ---- Phase 6: queue stats aggregate -----------------------------

    def get_queue_stats(self, group_id: str | None = None) -> dict[str, int]:
        """Count ``analysis_queue`` rows by status.

        When ``group_id`` is provided, restricts to that group. Keys in
        the returned dict are raw status strings (``queued``,
        ``running``, ``done``, ``error``, ``cancelled``,
        ``blocked_no_funds``) — only non-zero counts are included.
        """
        with self._connection() as conn:
            if group_id is None:
                rows = conn.execute(
                    "SELECT status, COUNT(*) AS n FROM analysis_queue GROUP BY status"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT status, COUNT(*) AS n FROM analysis_queue "
                    "WHERE group_id = ? GROUP BY status",
                    (group_id,),
                ).fetchall()
        return {row["status"]: int(row["n"]) for row in rows}
