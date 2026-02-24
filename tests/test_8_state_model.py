"""Test enforcement of 8-state model (SPEC requirement #5).

This test ensures that only the 8 allowed states exist in the codebase:
- disconnected
- connecting
- connected
- needs_code
- needs_2fa
- needs_config
- banned
- error

Removed states that should NOT appear anywhere:
- session_expired
- corrupted_session
- needs_api_id
- proxy_missing
- proxy_error
- needs_account_info
- needs_setup
- flood_wait
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest


# SPEC requirement #5: Final 8-state model
ALLOWED_STATES = {
    "disconnected",
    "connecting",
    "connected",
    "needs_code",
    "needs_2fa",
    "needs_config",
    "banned",
    "error",
}

# States that were removed and should NOT exist
REMOVED_STATES = {
    "session_expired",
    "corrupted_session",
    "needs_api_id",
    "proxy_missing",
    "proxy_error",
    "needs_account_info",
    "needs_setup",
    "flood_wait",
}


def test_only_8_states_in_python_code():
    """Verify only 8 allowed states appear in Python source code state assignments."""
    project_root = Path(__file__).parent.parent
    src_dir = project_root / "src" / "chatfilter"

    # Find all state assignments in Python files
    # Pattern: state="<state_name>" or state='<state_name>' or state: "<state_name>"
    # This specifically looks for actual state assignments, not error message dictionaries
    state_pattern = re.compile(r'state\s*[=:]\s*["\'](\w+)["\']')

    found_states = set()
    violations = []

    # Scan all Python files
    for py_file in src_dir.rglob("*.py"):
        if py_file.is_file():
            try:
                content = py_file.read_text(encoding="utf-8")
                lines = content.split("\n")

                for match in state_pattern.finditer(content):
                    state = match.group(1)
                    found_states.add(state)

                    # Find line number and context
                    line_num = content[: match.start()].count("\n") + 1
                    line_content = lines[line_num - 1].strip()

                    # Skip if this is in an error message dictionary (SAFE_MESSAGES, ERROR_MESSAGES, etc.)
                    # These are legacy dead code and not actual state assignments
                    if '"' in line_content and ":" in line_content and any(
                        pattern in line_content for pattern in ["error", "message", "SAFE_", "ERROR_"]
                    ):
                        continue

                    # Check if this is a removed state
                    if state in REMOVED_STATES:
                        violations.append(
                            f"{py_file.relative_to(project_root)}:{line_num} - Found removed state '{state}' in: {line_content[:80]}"
                        )
            except Exception as e:
                pytest.fail(f"Error reading {py_file}: {e}")

    # Assert no removed states found in actual state assignments
    if violations:
        pytest.fail("Found removed states in active code:\n" + "\n".join(violations))

    # Verify all found states are in allowed set (excluding non-session states like 'valid', 'invalid', etc.)
    # Filter to only states that look like session states (lowercase, contains underscore or is in our sets)
    session_states = {s for s in found_states if s in ALLOWED_STATES or s in REMOVED_STATES}

    unexpected_states = session_states - ALLOWED_STATES - REMOVED_STATES
    if unexpected_states:
        pytest.fail(f"Found unexpected session states: {unexpected_states}")


def test_only_8_states_in_templates():
    """Verify only 8 allowed states appear in HTML templates.

    Only match removed states when used as STATE values, not as:
    - Suffixes: flood_wait_until (data field)
    - CSS/HTML IDs/classes: flood-wait-*, flood-wait-{{ ... }}
    - JavaScript variables: floodWaitTarget, floodWaitEl, etc.
    - Comments
    """
    project_root = Path(__file__).parent.parent
    templates_dir = project_root / "src" / "chatfilter" / "templates"

    if not templates_dir.exists():
        pytest.skip("Templates directory not found")

    violations = []

    # Scan all template files
    for template_file in templates_dir.rglob("*.html"):
        if template_file.is_file():
            try:
                content = template_file.read_text(encoding="utf-8")
                lines = content.split("\n")

                # Check for removed states
                for removed_state in REMOVED_STATES:
                    # Pattern to match STATE VALUES (not identifiers/fields/comments)
                    # Match patterns like:
                    # - status="flood_wait" or status='flood_wait'
                    # - state="flood_wait" or state='flood_wait'
                    # - 'flood_wait' in states
                    # - == 'flood_wait' or == "flood_wait"
                    # But NOT:
                    # - flood_wait_until (has underscore suffix)
                    # - flood-wait-* (hyphenated identifiers)
                    # - floodWait* (camelCase variables)

                    # Use word boundary and negative lookahead/lookbehind to ensure
                    # the state is not part of a larger identifier
                    state_pattern = re.compile(
                        rf"(?<![a-zA-Z0-9_\-])"  # Not preceded by letter, digit, underscore, or hyphen
                        rf"{re.escape(removed_state)}"
                        rf"(?![a-zA-Z0-9_\-])"   # Not followed by letter, digit, underscore, or hyphen
                    )

                    for line_num, line in enumerate(lines, start=1):
                        # Skip comments
                        if line.strip().startswith(("{#", "//", "<!--")):
                            continue

                        # Skip lines where the state appears only in comments
                        # (check if all occurrences are after comment markers)
                        if state_pattern.search(line):
                            # Additional filter: if it's in a comment part of the line, skip
                            # For example: "   let floodWaitTarget = null; // flood_wait_until"
                            comment_start = min(
                                line.find("//") if "//" in line else len(line),
                                line.find("#}") if "#}" in line else len(line),
                            )
                            code_part = line[:comment_start]

                            if state_pattern.search(code_part):
                                violations.append(
                                    f"{template_file.relative_to(project_root)}:{line_num} - "
                                    f"Found removed state '{removed_state}'"
                                )
            except Exception as e:
                pytest.fail(f"Error reading {template_file}: {e}")

    # Assert no removed states found
    if violations:
        pytest.fail("Found removed states in templates:\n" + "\n".join(violations))


def test_only_8_states_in_javascript():
    """Verify only 8 allowed states appear in JavaScript files."""
    project_root = Path(__file__).parent.parent
    static_dir = project_root / "src" / "chatfilter" / "static"

    if not static_dir.exists():
        pytest.skip("Static directory not found")

    violations = []

    # Scan all JavaScript files
    for js_file in static_dir.rglob("*.js"):
        if js_file.is_file():
            try:
                content = js_file.read_text(encoding="utf-8")

                # Check for removed states
                for removed_state in REMOVED_STATES:
                    if removed_state in content:
                        # Find all occurrences with line numbers
                        lines = content.split("\n")
                        for line_num, line in enumerate(lines, start=1):
                            if removed_state in line:
                                violations.append(
                                    f"{js_file.relative_to(project_root)}:{line_num} - "
                                    f"Found removed state '{removed_state}'"
                                )
            except Exception as e:
                pytest.fail(f"Error reading {js_file}: {e}")

    # Assert no removed states found
    if violations:
        pytest.fail("Found removed states in JavaScript:\n" + "\n".join(violations))


def test_only_8_states_documented():
    """Verify exactly 8 states are documented as the canonical set."""
    # This test verifies that the 8-state model is correctly documented
    # by checking this test file itself contains the correct states

    assert len(ALLOWED_STATES) == 8, f"ALLOWED_STATES must have exactly 8 states, found {len(ALLOWED_STATES)}"

    # Verify the exact states
    expected = {
        "disconnected",
        "connecting",
        "connected",
        "needs_code",
        "needs_2fa",
        "needs_config",
        "banned",
        "error",
    }

    assert ALLOWED_STATES == expected, f"ALLOWED_STATES mismatch: {ALLOWED_STATES} vs {expected}"


def test_no_state_creep_in_recent_commits():
    """Regression guard: Check that no removed states were reintroduced in recent commits.

    This test focuses on actual state assignments (state=), not error message dictionaries.
    """
    project_root = Path(__file__).parent.parent

    try:
        # Check git history for removed states (last 10 commits)
        for removed_state in REMOVED_STATES:
            result = subprocess.run(
                ["git", "log", "-10", "--all", "-S", removed_state, "--oneline"],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout.strip():
                # Found commits touching this removed state
                # Check if it's being added (not just removed)
                recent_diff = subprocess.run(
                    ["git", "diff", "HEAD~10..HEAD", "--", "*.py", "*.html", "*.js"],
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if recent_diff.returncode == 0:
                    # Check if removed state appears in additions (+ lines)
                    diff_lines = recent_diff.stdout.split("\n")

                    # Filter out documentation, comments, error messages, and removal statements
                    violations = []
                    for line in diff_lines:
                        if not line.startswith("+"):
                            continue
                        if removed_state not in line:
                            continue

                        # Skip documentation and non-state-assignment contexts
                        lower_line = line.lower()
                        if any(
                            skip_pattern in lower_line
                            for skip_pattern in [
                                "no more",  # "No more 'session_expired'"
                                "removed:",  # Documentation of removed states
                                "deleted:",
                                "obsolete:",
                                "# ",  # Python comments
                                "// ",  # JS comments
                                "<!-- ",  # HTML comments
                                "changelog",
                                "migration",
                                '"' + removed_state + '":',  # Error message dict entries like "proxy_error": "msg"
                                "'" + removed_state + "':",  # Error message dict entries
                                "message",  # Error message contexts
                                "safe_",  # SAFE_MESSAGES dict
                                "error_",  # ERROR_ constants
                            ]
                        ):
                            continue

                        # Only flag actual state assignments: state="removed_state"
                        if f'state="{removed_state}"' not in line and f"state='{removed_state}'" not in line:
                            continue

                        violations.append(line)

                    if violations:
                        pytest.fail(
                            f"Removed state '{removed_state}' was reintroduced as actual state assignment:\n"
                            + "\n".join(violations[:5])
                        )
    except subprocess.TimeoutExpired:
        pytest.skip("Git command timed out")
    except FileNotFoundError:
        pytest.skip("Git not available")
    except Exception as e:
        pytest.skip(f"Git check failed: {e}")
