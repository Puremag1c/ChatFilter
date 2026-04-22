"""Global analysis scheduler.

Phase 4 of the redesign. Replaces the in-process ``asyncio.gather(...)``
model with a persistent queue + cooperative scheduler.

Lifecycle
---------
A single ``AnalysisScheduler`` instance lives for the entire app. It
runs one long-lived background task that wakes up every
``poll_interval`` seconds and:

    1. Reads the idle accounts in each pool ("admin", "user:{id}").
    2. For each idle account, tries to claim the next queued task
       from its pool — respecting the FairShare ``user_limit``.
    3. On claim, it spawns a per-task coroutine that calls
       ``worker.process_chat`` and finalises the row on completion.

The scheduler does NOT run telethon logic itself; that lives in the
worker and is invoked via ``process_chat``. This keeps the scheduler
easily testable with a fake session manager + fake worker.

Crash recovery
--------------
Call ``recover()`` once before ``start()``. It flips any rows still
in ``running`` from a previous process back to ``queued`` and bumps
``attempts``. The scheduler can then pick them up again.

Cancellation / Stop
-------------------
``AnalysisQueueMixin.cancel_group_tasks(group_id)`` marks all queued
rows of a group as ``cancelled``. Running rows finish normally (one
chat — usually seconds); the scheduler does not interrupt the worker
mid-flight in the MVP.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from chatfilter.analyzer.worker import ChatResult, process_chat
from chatfilter.models.group import (
    UNUSABLE_CHAT_TYPES,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
)

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)


class AnalysisScheduler:
    """Global chat-task scheduler — one instance per process."""

    def __init__(
        self,
        db: GroupDatabase,
        session_manager: Any,
        *,
        billing: Any | None = None,
        poll_interval: float = 1.0,
        user_limit: int = 2,
    ) -> None:
        self._db = db
        self._sm = session_manager
        self._billing = billing
        self._poll_interval = poll_interval
        self._user_limit = user_limit
        self._stop = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None
        # Track in-flight per-task coroutines so shutdown can wait for them.
        self._in_flight: set[asyncio.Task[None]] = set()
        # Fallback busy-set when SessionManager doesn't expose one of its own.
        # Entries are account_id strings for rows currently being worked.
        self._busy: set[str] = set()

    # ---- lifecycle --------------------------------------------------

    def recover(self) -> int:
        """Requeue every ``running`` row left over from a previous process."""
        reset = self._db.reset_running_tasks_to_queued()
        if reset:
            logger.warning(
                "Scheduler startup: returned %d running tasks to the queue", reset
            )
        return reset

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        self._stop.clear()
        self._loop_task = asyncio.create_task(self._loop(), name="analysis-scheduler")
        logger.info("AnalysisScheduler started")

    async def stop(self, *, timeout: float = 10.0) -> None:
        if self._loop_task is None:
            return
        self._stop.set()
        try:
            await asyncio.wait_for(self._loop_task, timeout=timeout)
        except TimeoutError:
            logger.warning("Scheduler loop did not exit within %ss — cancelling", timeout)
            self._loop_task.cancel()
        self._loop_task = None
        # Let remaining per-task coroutines finish so we don't lose results.
        if self._in_flight:
            logger.info("Waiting for %d in-flight tasks to finish", len(self._in_flight))
            await asyncio.gather(*self._in_flight, return_exceptions=True)
        logger.info("AnalysisScheduler stopped")

    # ---- loop --------------------------------------------------------

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.tick_once()
            except Exception:
                logger.exception("Scheduler tick raised unexpectedly")
            # Sleep but wake early if stop is requested.
            import contextlib

            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._poll_interval)

    async def tick_once(self) -> None:
        """Do one pass — claim as many tasks as there are idle accounts."""
        # Enumerate the pools we care about right now.
        pools = self._enumerate_pools()
        for pool_key, idle_accounts in pools.items():
            for account_id in idle_accounts:
                claimed = self._db.claim_next_task(
                    pool_key=pool_key,
                    account_id=account_id,
                    user_limit=self._user_limit,
                )
                if claimed is None:
                    # No eligible task for this pool right now.
                    break
                self._spawn_task(claimed, account_id)

    def _enumerate_pools(self) -> dict[str, list[str]]:
        """Gather {pool_key: [idle_account_id, ...]} from the session manager.

        Prefers the explicit ``idle_accounts`` / ``known_pools`` methods
        (used by tests with fake managers). Falls back to the production
        ``SessionManager`` API — ``list_sessions()`` + ``get_info(id)`` —
        mapped onto pool_keys via each session's owner metadata.
        """
        pools: dict[str, list[str]] = {}
        get_pools = getattr(self._sm, "known_pools", None)
        idle_fn = getattr(self._sm, "idle_accounts", None)

        # Explicit API (e.g. test fakes).
        if callable(get_pools) and callable(idle_fn):
            for pk in get_pools():
                pools[pk] = idle_fn(pk)
            return pools
        if callable(idle_fn):
            # Queue tells us which pools currently have work — only ask
            # idle_accounts for those.
            for pk in self._infer_pool_keys_from_queue():
                pools[pk] = idle_fn(pk)
            return pools

        # Fallback path — production SessionManager shape.
        return self._enumerate_pools_from_list_sessions()

    def _enumerate_pools_from_list_sessions(self) -> dict[str, list[str]]:
        """Derive pools from the SessionManager's list_sessions + get_info.

        Every connected session that is not currently busy in our
        local set becomes an idle account. The pool key is the session's
        owner; sessions whose owner field is missing or empty default
        to the shared admin pool.
        """
        list_fn = getattr(self._sm, "list_sessions", None)
        get_info = getattr(self._sm, "get_info", None)
        if not callable(list_fn) or not callable(get_info):
            return {}
        pools: dict[str, list[str]] = {}
        # Only enumerate pools that actually have queued work — otherwise
        # we'd spin over every account every tick.
        needed = set(self._infer_pool_keys_from_queue())
        if not needed:
            return {}
        session_state_enum: Any
        try:
            from chatfilter.telegram.session.models import SessionState

            session_state_enum = SessionState
        except Exception:
            session_state_enum = None
        # Owner lookup — falls back to "admin" for pre-Phase-4 sessions
        # and returns "user:{id}" for user-uploaded ones.
        def _lookup_owner_from_fs(session_id: str) -> str:
            try:
                from chatfilter.web.routers.sessions.io import (
                    get_session_owner,
                )
            except Exception:
                return "admin"
            try:
                return get_session_owner(session_id)
            except Exception:
                return "admin"
        for sid in list_fn():
            if sid in self._busy:
                continue
            info = get_info(sid)
            if info is None:
                continue
            if (
                session_state_enum is not None
                and getattr(info, "state", None) != session_state_enum.CONNECTED
            ):
                continue
            # info.owner wins if the manager exposes it; otherwise we
            # read the owner from the session's .account_info.json.
            owner = getattr(info, "owner", None) or _lookup_owner_from_fs(sid)
            if owner not in needed:
                continue
            pools.setdefault(owner, []).append(sid)
        return pools

    def _infer_pool_keys_from_queue(self) -> list[str]:
        """Fallback: pool keys that currently have at least one queued task."""
        with self._db._connection() as conn:
            rows = conn.execute(
                "SELECT DISTINCT pool_key FROM analysis_queue WHERE status = 'queued'"
            ).fetchall()
        return [row["pool_key"] for row in rows]

    # ---- per-task execution -----------------------------------------

    def _spawn_task(self, claimed: dict[str, Any], account_id: str) -> None:
        coro = self._run_task(claimed, account_id)
        task = asyncio.create_task(coro, name=f"chat-task-{claimed['id']}")
        self._in_flight.add(task)
        task.add_done_callback(self._in_flight.discard)

    async def _run_task(self, claimed: dict[str, Any], account_id: str) -> None:
        task_id = claimed["id"]
        user_id = claimed["user_id"]
        chat_ref = claimed["chat_ref"]
        chat_payload = {
            "id": claimed["group_chat_id"],
            "group_id": claimed["group_id"],
            "chat_ref": chat_ref,
        }
        # Mark the account busy so we don't double-book it this tick.
        mark_busy = getattr(self._sm, "mark_busy", None)
        if callable(mark_busy):
            mark_busy(account_id)
        else:
            self._busy.add(account_id)

        # Pre-charge for the chat. If billing/cost_per_chat is unset this
        # is a no-op and charged_amount stays at 0.0 — the existing
        # InsufficientBalance handling leaves the row queued and yields
        # the account to the next user.
        charged_amount = self._pre_charge(task_id, user_id, chat_ref)
        if charged_amount is None:
            # Pre-charge failed (insufficient funds) — task moved to
            # blocked_no_funds, skip execution.
            mark_idle = getattr(self._sm, "mark_idle", None)
            if callable(mark_idle):
                mark_idle(account_id)
            else:
                self._busy.discard(account_id)
            return

        try:
            client = await self._get_client(account_id)
            settings = self._load_group_settings(claimed["group_id"])
            result = await process_chat(
                chat_payload,
                client,
                account_id,
                settings,
                db=self._db,
            )
            self._persist_result(claimed, result, account_id)
            if result.status == GroupChatStatus.ERROR.value:
                self._refund(task_id, user_id, charged_amount, chat_ref, reason="ERROR")
                self._db.mark_task_error(task_id, result.error or "worker reported ERROR")
            else:
                # DONE regardless of chat_type (dead/banned/etc. are billable).
                self._db.mark_task_done(task_id)
        except Exception as e:
            logger.exception("Chat-task %s crashed", task_id)
            self._refund(task_id, user_id, charged_amount, chat_ref, reason="crash")
            self._db.mark_task_error(task_id, str(e))
        finally:
            mark_idle = getattr(self._sm, "mark_idle", None)
            if callable(mark_idle):
                mark_idle(account_id)
            else:
                self._busy.discard(account_id)

    # ---- billing helpers --------------------------------------------

    def _pre_charge(
        self, task_id: int, user_id: str, chat_ref: str
    ) -> float | None:
        """Charge cost_per_chat before the worker runs.

        Idempotent: if ``charged_amount`` on the row is already > 0
        (i.e. we charged on a previous boot and crashed before
        finalising), we skip the second charge and reuse the recorded
        amount. This is how crash recovery avoids double-billing the
        same chat.

        Returns the amount actually charged (>= 0) — caller stores it
        on the queue row so ``_refund`` can return the exact amount
        later. Returns None if the user is out of funds, in which case
        the task is moved to ``blocked_no_funds`` status.
        """
        # Check for an existing charge (crash recovery path).
        with self._db._connection() as conn:
            row = conn.execute(
                "SELECT charged_amount FROM analysis_queue WHERE id=?",
                (task_id,),
            ).fetchone()
        already_charged = float(row["charged_amount"]) if row else 0.0
        if already_charged > 0:
            return already_charged

        if self._billing is None:
            return 0.0
        try:
            cost = self._db.get_cost_per_chat()
        except Exception:
            cost = 0.0
        if cost <= 0 or not user_id:
            return 0.0
        try:
            self._billing.charge(
                user_id,
                cost,
                model="analysis",
                tokens_in=0,
                tokens_out=0,
                description=f"Chat analysis: {chat_ref}",
            )
        except Exception:
            logger.warning(
                "Task %s blocked — user %s out of funds for chat %s",
                task_id,
                user_id,
                chat_ref,
            )
            with self._db._connection() as conn:
                conn.execute(
                    "UPDATE analysis_queue SET status='blocked_no_funds', "
                    "started_at=NULL WHERE id=?",
                    (task_id,),
                )
            return None
        # Persist the charge on the queue row so refund is exact.
        with self._db._connection() as conn:
            conn.execute(
                "UPDATE analysis_queue SET charged_amount=? WHERE id=?",
                (cost, task_id),
            )
        return cost

    def _refund(
        self,
        task_id: int,
        user_id: str,
        amount: float,
        chat_ref: str,
        *,
        reason: str,
    ) -> None:
        if self._billing is None or amount <= 0 or not user_id:
            return
        try:
            self._billing.refund(
                user_id,
                amount,
                f"Refund ({reason}): {chat_ref}",
            )
            # Zero out charged_amount so a later bug can't double-refund.
            with self._db._connection() as conn:
                conn.execute(
                    "UPDATE analysis_queue SET charged_amount=0 WHERE id=?",
                    (task_id,),
                )
        except Exception:
            logger.exception("Refund failed for task %s (user=%s)", task_id, user_id)

    async def _get_client(self, account_id: str) -> Any:
        # Tests inject a fake ``get_client``; production uses ``connect``.
        for attr in ("get_client", "connect"):
            fn = getattr(self._sm, attr, None)
            if fn is None:
                continue
            result = fn(account_id)
            if asyncio.iscoroutine(result):
                return await result
            return result
        return None

    def _load_group_settings(self, group_id: str) -> GroupSettings:
        group = self._db.load_group(group_id)
        if not group:
            return GroupSettings()
        raw = group.get("settings")
        if isinstance(raw, dict):
            return GroupSettings(**raw)
        try:
            import json

            if isinstance(raw, str) and raw:
                return GroupSettings(**json.loads(raw))
        except Exception:
            pass
        return GroupSettings()

    def _persist_result(
        self,
        claimed: dict[str, Any],
        result: ChatResult,
        account_id: str,
    ) -> None:
        """Mirror (status, chat_type) into group_chats and store metrics."""
        from chatfilter.analyzer.group_engine import METRICS_VERSION

        chat_id = claimed["group_chat_id"]
        self._db.save_chat(
            group_id=claimed["group_id"],
            chat_ref=claimed["chat_ref"],
            chat_type=result.chat_type,
            status=result.status,
            assigned_account=account_id,
            error=result.error,
            chat_id=chat_id,
            subscribers=result.subscribers,
        )
        metrics = result.to_dict()
        metrics["metrics_version"] = METRICS_VERSION
        try:
            self._db.save_chat_metrics(chat_id, metrics)
        except Exception:
            logger.warning("Could not persist metrics for chat_id=%s", chat_id)

        # If the chat_type is unusable (DEAD/BANNED/RESTRICTED/PRIVATE),
        # there's nothing to cache or follow up on — it's terminal.
        if ChatTypeEnum(result.chat_type) in UNUSABLE_CHAT_TYPES:
            return
