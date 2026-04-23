"""Shared fixtures and helpers for sessions tests."""

from __future__ import annotations

import re
from typing import Any

import pytest


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag.

    Args:
        html: HTML content containing meta tag with csrf-token

    Returns:
        CSRF token string or None if not found
    """
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Real authenticated power-user TestClient
# ---------------------------------------------------------------------------
# Phase 2 put require_own_accounts on /api/sessions/* and require_admin on
# /admin/api/sessions/*. Tests here exercise business logic of those
# endpoints — they must reach the handler. Rather than bypass the gate
# with dependency_overrides (which masks architectural errors), we
# create a real power-user in the test DB, stamp its cookie on the
# TestClient, and return a tuple so tests know which pool_scope the
# request will land under (matches chatfilter.web.dependencies.get_pool_scope).


def _create_power_user_and_session() -> tuple[str, str]:
    """Insert a power-user row (use_own_accounts=True) and a logged-in session.

    Returns ``(user_id, session_id)``. Uses ``get_user_db`` which reads
    ``chatfilter.config.get_settings()`` — already patched by the
    autouse ``_isolate_data_dir`` fixture in the root conftest.
    """
    from chatfilter.config import get_settings
    from chatfilter.storage.user_database import get_user_db
    from chatfilter.web.session import get_session_store

    settings = get_settings()
    db = get_user_db(settings.effective_database_url)

    username = "sessions_poweruser"
    existing = db.get_user_by_username(username)
    user_id = existing["id"] if existing else db.create_user(username, "pw12345678", is_admin=False)
    db.set_use_own_accounts(user_id, True)

    store = get_session_store()
    sess = store.create_session()
    sess.set("user_id", user_id)
    sess.set("username", username)
    sess.set("is_admin", False)
    return user_id, sess.session_id


@pytest.fixture
def session_client() -> Any:
    """TestClient authenticated as a power-user for /api/sessions/* tests.

    Passes ``settings=get_settings()`` explicitly so ``app.state.settings``
    lands on the isolated test DB (``_isolate_data_dir`` autouse fixture
    only patches the dotted attribute — ``chatfilter.web.app`` imports
    ``get_settings`` by value at import time, so the monkeypatch never
    reaches the ``create_app`` call path unless we resolve it here).
    """
    from fastapi.testclient import TestClient

    from chatfilter.config import get_settings
    from chatfilter.web.app import create_app
    from chatfilter.web.session import SESSION_COOKIE_NAME

    _user_id, session_id = _create_power_user_and_session()
    app = create_app(debug=True, settings=get_settings())
    return TestClient(app, cookies={SESSION_COOKIE_NAME: session_id})


@pytest.fixture
def scope_name() -> str:
    """Pool scope the session_client requests will land under.

    Same rule as ``chatfilter.web.dependencies.get_pool_scope`` for a
    non-admin URL with an authenticated user: ``"user_{id}"``. The user
    is created by ``session_client``; we recompute its id here from
    the same username so tests can build expected file paths.
    """
    from chatfilter.config import get_settings
    from chatfilter.storage.user_database import get_user_db

    settings = get_settings()
    db = get_user_db(settings.effective_database_url)
    user = db.get_user_by_username("sessions_poweruser")
    if user is None:
        # session_client is a function-scoped fixture — if a test uses
        # ``scope_name`` alone without ``session_client`` it won't exist.
        # Create it now so the path is valid anyway.
        _create_power_user_and_session()
        user = db.get_user_by_username("sessions_poweruser")
    return f"user_{user['id']}"
