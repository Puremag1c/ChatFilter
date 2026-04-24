"""Read/write helpers for the persistent ``autoconnect`` flag on a session.

``autoconnect`` is the session's **desired state**:
  - ``True``  — last user action was "Connect" (or the session was
                brought up before the 0.42 release which introduced
                this flag, i.e. we assume alive unless proven otherwise)
  - ``False`` — last user action was "Disconnect"

Boot recovery (``service/boot_recovery.py``) reads this at startup and
tries to reconnect only the sessions whose flag is ``True``.

The flag lives in ``sessions/<scope>/<name>/config.json`` alongside
``proxy_id``. No Pydantic model — the file is a plain dict and other
callers (``web/routers/sessions/routes.py``) write it as JSON; adding
a dataclass here would force schema coordination everywhere. Two small
pure-function helpers are simpler and coexist safely.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def read_autoconnect(config_path: Path) -> bool:
    """Return the ``autoconnect`` value, defaulting to True.

    Defaults to ``True`` when:
      - the file does not exist
      - the file is not valid JSON
      - the field is absent (pre-0.42 config)

    Rationale: missing / broken config should not cause a previously
    alive session to stay dead forever. The user can always disconnect
    explicitly to set it to False.
    """
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return True
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("autoconnect: could not read %s: %s — defaulting to True", config_path, e)
        return True
    if not isinstance(data, dict):
        return True
    value = data.get("autoconnect", True)
    return bool(value)


def set_autoconnect(config_path: Path, value: bool) -> None:
    """Write ``autoconnect=value`` into the config, preserving other keys.

    Creates the file + parent dirs if missing. Atomic via temp-file
    rename. Corrupted source → overwritten with a fresh dict containing
    only the new flag (we prefer persisting user intent to preserving
    unreadable bytes).
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict[str, Any]
    try:
        existing = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            existing = {}
    except FileNotFoundError:
        existing = {}
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(
            "autoconnect: could not parse existing config %s (%s) — overwriting",
            config_path,
            e,
        )
        existing = {}

    existing["autoconnect"] = value

    tmp = config_path.with_suffix(config_path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    tmp.replace(config_path)
