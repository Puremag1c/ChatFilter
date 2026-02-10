"""Verification tests for removed session states.

This test suite ensures that removed states (session_expired, corrupted_session)
do NOT reappear in the codebase after their removal per SPEC requirements #2 and #3.

SPEC Requirements:
#2: Remove session_expired from classify_error_state, templates, CSS, translations
#3: Remove corrupted_session from templates and CSS

Risk: These states regressed before (session_expired reappeared in v0.8.3 after
removal in v0.8.1). These tests prevent future regressions.
"""

import pytest
from pathlib import Path
import re


# Forbidden state strings that must NOT appear in codebase
REMOVED_STATES = ["session_expired", "corrupted_session"]


@pytest.fixture
def project_root():
    """Get project root directory."""
    return Path(__file__).parent.parent


def test_removed_states_not_in_templates(project_root):
    """Verify removed states do not appear in HTML templates.

    Checks all .html files in templates/ directory for forbidden state strings.
    This prevents UI from rendering removed states.
    """
    templates_dir = project_root / "src" / "chatfilter" / "templates"
    assert templates_dir.exists(), f"Templates directory not found: {templates_dir}"

    html_files = list(templates_dir.rglob("*.html"))
    assert len(html_files) > 0, "No HTML template files found"

    violations = []

    for html_file in html_files:
        content = html_file.read_text()
        for state in REMOVED_STATES:
            # Check for state string in various contexts
            patterns = [
                f'"{state}"',           # Exact string in quotes
                f"'{state}'",           # Single quotes
                f"status == {state}",   # Condition
                f"status-{state}",      # CSS class pattern
                f"state-{state}",       # Alternative class pattern
                state,                  # Plain occurrence
            ]

            for pattern in patterns:
                if pattern in content:
                    # Get line number for better debugging
                    lines = content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if pattern in line:
                            violations.append(
                                f"{html_file.relative_to(project_root)}:{i} "
                                f"contains '{state}' in context: {line.strip()[:80]}"
                            )

    assert not violations, (
        f"Found {len(violations)} occurrences of removed states in templates:\n" +
        "\n".join(violations)
    )


def test_removed_states_not_in_css(project_root):
    """Verify removed states do not appear in CSS files.

    Checks CSS files for class selectors related to forbidden states.
    This prevents styling for removed states.
    """
    css_dir = project_root / "src" / "chatfilter" / "static" / "css"
    assert css_dir.exists(), f"CSS directory not found: {css_dir}"

    css_files = list(css_dir.rglob("*.css"))
    assert len(css_files) > 0, "No CSS files found"

    violations = []

    for css_file in css_files:
        content = css_file.read_text()
        for state in REMOVED_STATES:
            # Check for CSS class selectors
            patterns = [
                f".status-{state}",      # Class selector
                f".state-{state}",       # Alternative pattern
                f"[data-status='{state}']",  # Attribute selector
                f'[data-status="{state}"]',
                f"[data-state='{state}']",
                f'[data-state="{state}"]',
            ]

            for pattern in patterns:
                if pattern in content:
                    lines = content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if pattern in line:
                            violations.append(
                                f"{css_file.relative_to(project_root)}:{i} "
                                f"contains CSS for '{state}': {line.strip()[:80]}"
                            )

    assert not violations, (
        f"Found {len(violations)} CSS rules for removed states:\n" +
        "\n".join(violations)
    )


def test_removed_states_not_in_translations(project_root):
    """Verify removed states do not appear in translation files.

    Checks .po and .json translation files for forbidden state strings.
    This prevents translated UI text for removed states.
    """
    i18n_dir = project_root / "src" / "chatfilter" / "i18n"
    assert i18n_dir.exists(), f"i18n directory not found: {i18n_dir}"

    # Check both .po and .json files
    translation_files = list(i18n_dir.rglob("*.po")) + list(i18n_dir.rglob("*.json"))
    assert len(translation_files) > 0, "No translation files found"

    violations = []

    for trans_file in translation_files:
        content = trans_file.read_text()
        for state in REMOVED_STATES:
            # Check for msgid/msgstr in .po or keys in .json
            patterns = [
                f'msgid "{state}"',     # .po message ID
                f'msgstr "{state}"',    # .po message string
                f'"{state}"',           # JSON key or value
                state,                  # Plain occurrence
            ]

            for pattern in patterns:
                if pattern in content:
                    lines = content.split('\n')
                    for i, line in enumerate(lines, 1):
                        if pattern in line:
                            violations.append(
                                f"{trans_file.relative_to(project_root)}:{i} "
                                f"contains '{state}': {line.strip()[:80]}"
                            )

    assert not violations, (
        f"Found {len(violations)} occurrences in translation files:\n" +
        "\n".join(violations)
    )


def test_classify_error_state_never_returns_removed():
    """Verify classify_error_state function never returns removed states.

    Tests the function with various error inputs to ensure it only returns
    the 3 allowed states: 'banned', 'needs_config', 'error'.

    Per SPEC: classify_error_state must NEVER return session_expired or
    corrupted_session (these are handled by auto-reauth/auto-delete in connect flow).
    """
    from chatfilter.web.routers.sessions import classify_error_state

    # Test cases covering various error scenarios
    test_cases = [
        # Error message strings
        ("Session expired", None),
        ("session_expired", None),
        ("Corrupted session", None),
        ("corrupted_session", None),
        ("Session file is corrupted", None),
        ("Your session has expired", None),
        # Generic errors
        ("Connection timeout", None),
        ("Unknown error", None),
        ("Flood wait", None),
        (None, None),
        ("", None),
        # Banned account (should return 'banned')
        ("User banned", None),
        ("Account deactivated", None),
        # Configuration errors (should return 'needs_config')
        ("Proxy connection failed", None),
        ("OSError", None),
    ]

    allowed_states = {"banned", "needs_config", "error"}
    violations = []

    for error_msg, exception in test_cases:
        result = classify_error_state(error_msg, exception)

        if result in REMOVED_STATES:
            violations.append(
                f"classify_error_state('{error_msg}', {exception}) "
                f"returned forbidden state: '{result}'"
            )

        if result not in allowed_states:
            violations.append(
                f"classify_error_state('{error_msg}', {exception}) "
                f"returned unexpected state: '{result}' (not in {allowed_states})"
            )

    assert not violations, (
        f"classify_error_state returned forbidden or unexpected states:\n" +
        "\n".join(violations)
    )


def test_classify_error_state_exception_types():
    """Test classify_error_state with actual exception objects.

    Ensures the function handles exception types correctly without
    returning removed states.
    """
    from chatfilter.web.routers.sessions import classify_error_state

    # Test with actual exception types
    test_exceptions = [
        OSError("Connection failed"),
        ConnectionError("Proxy error"),
        ValueError("Invalid session"),
        RuntimeError("Session expired"),
        Exception("Corrupted session"),
    ]

    allowed_states = {"banned", "needs_config", "error"}
    violations = []

    for exc in test_exceptions:
        result = classify_error_state(str(exc), exc)

        if result in REMOVED_STATES:
            violations.append(
                f"classify_error_state with exception {type(exc).__name__} "
                f"returned forbidden state: '{result}'"
            )

        if result not in allowed_states:
            violations.append(
                f"classify_error_state with exception {type(exc).__name__} "
                f"returned unexpected state: '{result}'"
            )

    assert not violations, (
        f"classify_error_state with exceptions returned forbidden states:\n" +
        "\n".join(violations)
    )
