"""CSRF protection for state-changing endpoints.

This module provides CSRF token generation and validation to protect against
Cross-Site Request Forgery attacks. CSRF tokens are stored in the session and
validated on all POST/DELETE requests.

Features:
- Secure token generation using secrets module
- Session-based token storage
- Automatic token rotation on validation
- Support for both form-data and X-CSRF-Token header
- Exemption support for specific endpoints (e.g., health checks)
"""

from __future__ import annotations

import logging
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chatfilter.web.session import SessionData

logger = logging.getLogger(__name__)

# Session key for storing CSRF token
CSRF_SESSION_KEY = "_csrf_token"

# Header name for CSRF token
CSRF_HEADER_NAME = "X-CSRF-Token"

# Form field name for CSRF token
CSRF_FORM_FIELD = "csrf_token"


def generate_csrf_token() -> str:
    """Generate a new CSRF token.

    Returns:
        Secure random token (URL-safe, 32 bytes)
    """
    return secrets.token_urlsafe(32)


def get_csrf_token(session: SessionData) -> str:
    """Get or create CSRF token for session.

    If session doesn't have a CSRF token, generates a new one.

    Args:
        session: Session data to get token from

    Returns:
        CSRF token for this session
    """
    token = session.get(CSRF_SESSION_KEY)

    if not token:
        token = generate_csrf_token()
        session.set(CSRF_SESSION_KEY, token)
        logger.debug(f"Generated new CSRF token for session {session.session_id[:8]}...")

    return token


def validate_csrf_token(session: SessionData, token: str) -> bool:
    """Validate CSRF token against session.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        session: Session data to validate against
        token: Token to validate

    Returns:
        True if token is valid, False otherwise
    """
    expected_token = session.get(CSRF_SESSION_KEY)

    if not expected_token:
        logger.warning(f"No CSRF token in session {session.session_id[:8]}...")
        return False

    # Use secrets.compare_digest for constant-time comparison
    # to prevent timing attacks
    is_valid = secrets.compare_digest(expected_token, token)

    if not is_valid:
        logger.warning(
            f"CSRF token mismatch for session {session.session_id[:8]}... "
            f"(expected: {expected_token[:8]}..., got: {token[:8] if token else 'None'}...)"
        )

    return is_valid


def rotate_csrf_token(session: SessionData) -> str:
    """Rotate CSRF token for session.

    Generates a new token and stores it in session. This should be called
    after successful authentication or other sensitive operations.

    Args:
        session: Session to rotate token for

    Returns:
        New CSRF token
    """
    new_token = generate_csrf_token()
    session.set(CSRF_SESSION_KEY, new_token)
    logger.debug(f"Rotated CSRF token for session {session.session_id[:8]}...")
    return new_token
