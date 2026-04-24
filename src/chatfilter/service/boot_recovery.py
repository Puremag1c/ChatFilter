"""Boot Recovery — restore "what was connected" after a server restart.

When the process dies, several pieces of runtime-only state go with it:
``SessionManager._factories`` is empty, ``ProxyHealthMonitor`` hasn't
pinged anything yet, and the ``FloodTracker`` is back to zero. If we
do nothing, the admin pool stays dark until an operator clicks Connect
on every row by hand. This module rehydrates the system at boot so
that whatever was **intentionally** online before the restart comes
back online on its own.

Intent is expressed through the persistent ``autoconnect`` flag in
``sessions/<scope>/<name>/config.json``:
  * user clicked Connect  → ``autoconnect=True``   → we try to reconnect
  * user clicked Disconnect → ``autoconnect=False`` → we leave it alone
  * missing (pre-0.42 config) → ``True`` (existing sessions were alive)

Two phases, both run in a single background task kicked off from
``web/app.py`` lifespan:

  Phase A — ping every proxy in every pool so Phase B can tell live
  proxies from dead ones. Reuses ``ProxyHealthMonitor.check_all_proxies``
  so we don't duplicate the concurrency / persistence logic.

  Phase B — for every session (all pools):
    - read autoconnect → skip if False
    - reject sessions that need a human (banned / needs_code /
      needs_2fa / needs_config) or that are missing session.session
    - if the configured proxy came back dead → skip (watchdog will
      pick it up if the proxy revives later)
    - otherwise: register the loader + call ``SessionManager.connect``

A frozen ``BootRecoverySnapshot`` published via a thread-safe
``BootRecoveryHolder`` lets the progress banner and the status endpoint
show live counters without racing against the worker.

Scope is all pools (admin + user_*). Analyses that were in progress
before the restart are handled separately by
``AnalysisScheduler.recover()`` — we don't touch them here.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

# Sessions in these states need a human; we never auto-connect them.
HUMAN_NEEDED_STATES = frozenset({"banned", "needs_code", "needs_2fa", "needs_config"})

# Rough per-session "connect" cost used for the UI ETA.
AVG_CONNECT_SECONDS = 5

# Hard ceiling: even if every connect hangs, recovery must complete in
# reasonable time so the banner disappears.
DEFAULT_FAILSAFE_SECONDS = 300.0

# Concurrent connects to Telegram — small enough not to trip Flood, big
# enough to make 50 sessions finish in a minute.
DEFAULT_CONNECT_CONCURRENCY = 10


BootRecoveryPhase = Literal["pinging_proxies", "connecting_accounts", "done", "failed"]


@dataclass(frozen=True)
class BootRecoverySnapshot:
    """Immutable view of recovery state — consumed by UI banner / endpoint."""

    in_progress: bool
    phase: BootRecoveryPhase
    started_at: datetime
    finished_at: datetime | None
    proxies_total: int
    proxies_pinged: int
    proxies_alive: int
    sessions_total: int
    sessions_connected: int
    sessions_skipped_autoconnect_false: int
    sessions_skipped_dead_proxy: int
    sessions_skipped_human_needed: int
    sessions_failed: int
    eta_seconds: int | None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # datetimes → ISO strings for JSON serialisation.
        d["started_at"] = self.started_at.isoformat()
        d["finished_at"] = self.finished_at.isoformat() if self.finished_at else None
        return d


@dataclass
class _MutableState:
    """Internal mutable bookkeeping behind the holder's lock."""

    in_progress: bool = True
    phase: BootRecoveryPhase = "pinging_proxies"
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    proxies_total: int = 0
    proxies_pinged: int = 0
    proxies_alive: int = 0
    sessions_total: int = 0
    sessions_connected: int = 0
    sessions_skipped_autoconnect_false: int = 0
    sessions_skipped_dead_proxy: int = 0
    sessions_skipped_human_needed: int = 0
    sessions_failed: int = 0


class BootRecoveryHolder:
    """Thread-safe container. One writer (the recovery task) updates
    counters via ``update`` / ``mark_done``; many readers (middleware,
    HTTP endpoint) call ``snapshot`` which returns a frozen dataclass.

    ``threading.Lock`` rather than ``asyncio.Lock`` so that synchronous
    template-context code can also read without event-loop ceremony."""

    def __init__(self) -> None:
        self._state = _MutableState()
        self._lock = threading.Lock()

    def snapshot(self) -> BootRecoverySnapshot:
        with self._lock:
            s = self._state
            remaining = max(0, s.sessions_total - s.sessions_connected)
            eta = remaining * AVG_CONNECT_SECONDS if s.in_progress else None
            return BootRecoverySnapshot(
                in_progress=s.in_progress,
                phase=s.phase,
                started_at=s.started_at,
                finished_at=s.finished_at,
                proxies_total=s.proxies_total,
                proxies_pinged=s.proxies_pinged,
                proxies_alive=s.proxies_alive,
                sessions_total=s.sessions_total,
                sessions_connected=s.sessions_connected,
                sessions_skipped_autoconnect_false=s.sessions_skipped_autoconnect_false,
                sessions_skipped_dead_proxy=s.sessions_skipped_dead_proxy,
                sessions_skipped_human_needed=s.sessions_skipped_human_needed,
                sessions_failed=s.sessions_failed,
                eta_seconds=eta,
            )

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            self._state = replace(self._state, **kwargs)

    def increment(self, field_name: str, amount: int = 1) -> None:
        with self._lock:
            current = getattr(self._state, field_name)
            self._state = replace(self._state, **{field_name: current + amount})

    def mark_done(self, phase: BootRecoveryPhase = "done") -> None:
        with self._lock:
            self._state = replace(
                self._state,
                in_progress=False,
                phase=phase,
                finished_at=datetime.now(UTC),
            )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_boot_recovery(
    session_manager: Any,
    holder: BootRecoveryHolder,
    *,
    failsafe_seconds: float = DEFAULT_FAILSAFE_SECONDS,
    connect_concurrency: int = DEFAULT_CONNECT_CONCURRENCY,
) -> None:
    """Ping all proxies, then reconnect every session with autoconnect=True
    and a live proxy. Populates ``holder`` live; always ends with
    ``phase ∈ {'done', 'failed'}`` so the UI never hangs on the banner.

    Any unexpected exception outside the per-session try/except is
    logged and marks ``phase='failed'`` rather than propagating —
    the server stays usable even if recovery is broken."""
    try:
        await asyncio.wait_for(
            _run_phases(session_manager, holder, connect_concurrency),
            timeout=failsafe_seconds,
        )
        holder.mark_done("done")
    except TimeoutError:
        logger.warning(
            "Boot recovery hit failsafe timeout (%.0fs) — marking done so UI "
            "unfreezes; any unfinished sessions will be retried by watchdog / user.",
            failsafe_seconds,
        )
        holder.mark_done("done")
    except Exception:
        logger.exception("Boot recovery crashed — marking failed")
        holder.mark_done("failed")


async def _run_phases(
    session_manager: Any,
    holder: BootRecoveryHolder,
    connect_concurrency: int,
) -> None:
    # -------- Phase A: proxy pings --------
    holder.update(phase="pinging_proxies")
    try:
        # check_all_proxies persists WORKING/NO_PING/UNTESTED to every
        # proxies_*.json, so we can read the pools afterwards to learn
        # each proxy's alive/dead verdict.
        pinged = await check_all_proxies()
    except Exception:
        logger.exception("Boot recovery: proxy ping phase failed — continuing anyway")
        pinged = {}

    holder.update(
        proxies_total=len(pinged),
        proxies_pinged=len(pinged),
        proxies_alive=sum(1 for p in pinged.values() if _is_proxy_working(p)),
    )

    # Build a fast lookup for Phase B: proxy_id → is this proxy alive?
    proxy_alive = _load_proxy_alive_map()

    # -------- Phase B: session reconnects --------
    holder.update(phase="connecting_accounts")

    sessions = _list_all_sessions()
    holder.update(sessions_total=len(sessions))

    if not sessions:
        return

    sem = asyncio.Semaphore(connect_concurrency)

    async def _one(session_path: Path, session_id: str) -> None:
        async with sem:
            await _attempt_one_session(
                session_path, session_id, session_manager, proxy_alive, holder
            )

    await asyncio.gather(*(_one(p, sid) for p, sid in sessions), return_exceptions=True)


# ---------------------------------------------------------------------------
# Per-session logic
# ---------------------------------------------------------------------------


async def _attempt_one_session(
    session_path: Path,
    session_id: str,
    session_manager: Any,
    proxy_alive: dict[str, bool],
    holder: BootRecoveryHolder,
) -> None:
    cfg_path = session_path / "config.json"
    sess_file = session_path / "session.session"

    # Want this session back up?
    if not read_autoconnect(cfg_path):
        holder.increment("sessions_skipped_autoconnect_false")
        return

    # Human needed (banned / auth-in-flight / no proxy configured)?
    state = _detect_state_on_disk(session_path)
    if state in HUMAN_NEEDED_STATES:
        holder.increment("sessions_skipped_human_needed")
        return

    if not sess_file.exists():
        # No auth material on disk → user has to re-auth interactively.
        holder.increment("sessions_skipped_human_needed")
        return

    # Does the assigned proxy answer?
    proxy_id = _read_proxy_id(cfg_path)
    if proxy_id is not None and not proxy_alive.get(proxy_id, False):
        holder.increment("sessions_skipped_dead_proxy")
        return

    # At this point: session is valid, user wants it up, proxy (if any)
    # is alive. Register the factory and hand off to SessionManager.
    try:
        # Look up the name on the module at call time so tests can
        # monkeypatch ``chatfilter.service.boot_recovery.TelegramClientLoader``
        # and see their stub honored.
        import chatfilter.service.boot_recovery as _self

        loader = _self.TelegramClientLoader(sess_file)
        loader.validate()
    except Exception:
        logger.warning(
            "Boot recovery: loader validation failed for %s",
            session_id,
            exc_info=True,
        )
        holder.increment("sessions_failed")
        return

    session_manager.register(session_id, loader)

    try:
        await session_manager.connect(session_id)
    except Exception as e:
        # SessionManager publishes its own SSE "error"; we just count
        # this as a failure and move on. Watchdog will pick it up.
        logger.info(
            "Boot recovery: connect for %s raised %s — leaving to watchdog",
            session_id,
            e,
        )
        holder.increment("sessions_failed")
        return

    holder.increment("sessions_connected")


# ---------------------------------------------------------------------------
# Disk-side helpers
# ---------------------------------------------------------------------------


def _list_all_sessions() -> list[tuple[Path, str]]:
    """Walk every scope under ``sessions_dir`` and yield session dirs.

    Returns a list of (session_dir_path, session_id) tuples. We use the
    directory name as session_id — same convention as
    ``list_stored_sessions`` uses for ``SessionListItem.session_id``.
    """
    from chatfilter.config import get_settings

    out: list[tuple[Path, str]] = []
    root = get_settings().sessions_dir
    if not root.exists():
        return out
    for scope_dir in root.iterdir():
        if not scope_dir.is_dir():
            continue
        for session_dir in scope_dir.iterdir():
            if not session_dir.is_dir():
                continue
            # Skip anything without the minimum required files.
            if not (session_dir / ".account_info.json").exists():
                continue
            out.append((session_dir, session_dir.name))
    return out


def _read_proxy_id(config_path: Path) -> str | None:
    import json

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    value = data.get("proxy_id")
    return str(value) if value else None


def _detect_state_on_disk(session_dir: Path) -> str:
    """Cheap disk-only proxy for the listing layer's state detection.

    After a restart the SessionManager has no in-memory state for any
    session, so the "state" the listing would report is fully derived
    from files. We only need to distinguish 'human needed' from 'safe
    to auto-connect', so a small check of known marker files is enough.
    We deliberately do NOT import ``list_stored_sessions`` here to avoid
    dragging its heavier dependencies into the startup path.
    """
    if (session_dir / ".banned").exists():
        return "banned"
    if (session_dir / ".needs_code").exists():
        return "needs_code"
    if (session_dir / ".needs_2fa").exists():
        return "needs_2fa"
    if not (session_dir / "config.json").exists():
        return "needs_config"
    return "disconnected"


def _is_proxy_working(proxy: Any) -> bool:
    """``ProxyEntry.status == WORKING``, defensively imported so the
    module stays importable even if the enum layout changes."""
    from chatfilter.config_proxy import ProxyStatus

    return getattr(proxy, "status", None) == ProxyStatus.WORKING


def _load_proxy_alive_map() -> dict[str, bool]:
    """After Phase A every pool file is up to date. Rebuild a flat
    ``{proxy_id: is_alive}`` map across all pools so Phase B can look
    up each session's assigned proxy in O(1)."""
    from chatfilter.config import get_settings
    from chatfilter.storage.proxy_pool import load_proxy_pool

    out: dict[str, bool] = {}
    config_dir = get_settings().config_dir
    if not config_dir.exists():
        return out
    for proxy_file in config_dir.glob("proxies_*.json"):
        user_id = proxy_file.stem.removeprefix("proxies_")
        try:
            for p in load_proxy_pool(user_id):
                out[p.id] = _is_proxy_working(p)
        except Exception:
            logger.warning(
                "Boot recovery: could not load proxy pool %s",
                user_id,
                exc_info=True,
            )
    return out


# Module-level name tests can monkeypatch to avoid dragging Telethon
# into unit tests. Real production path imports the concrete class
# lazily — top-level import would slow the first request.
def _default_loader(session_file: Path) -> Any:
    from chatfilter.telegram.client.loader import TelegramClientLoader

    return TelegramClientLoader(session_file)


TelegramClientLoader = _default_loader


# Name used in Phase A — indirected so tests can stub the expensive
# real thing without importing it.
async def check_all_proxies() -> dict[str, Any]:
    from chatfilter.service.proxy_health import check_all_proxies as _real

    return await _real()


# ---------------------------------------------------------------------------
# Re-export the autoconnect reader so the tests have a single entry point.
# ---------------------------------------------------------------------------

from chatfilter.service.session_autoconnect import read_autoconnect  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_holder: BootRecoveryHolder | None = None


def get_boot_recovery_holder() -> BootRecoveryHolder | None:
    return _holder


def set_boot_recovery_holder(h: BootRecoveryHolder | None) -> None:
    global _holder
    _holder = h
