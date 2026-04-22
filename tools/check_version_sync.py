#!/usr/bin/env python3
"""Verify that __version__ matches the latest CHANGELOG entry.

Single source of truth: src/chatfilter/__init__.py.
This hook fails the commit if CHANGELOG.md's most recent release header
does not match __version__ — prevents the VERSION-drift bug we fixed once.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = ROOT / "src" / "chatfilter" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"


def main() -> int:
    init_text = INIT_FILE.read_text()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
    if not m:
        print(f"ERROR: could not find __version__ in {INIT_FILE}", file=sys.stderr)
        return 1
    version = m.group(1)

    changelog_text = CHANGELOG.read_text()
    # First release heading after [Unreleased]: "## [x.y.z] - YYYY-MM-DD"
    m = re.search(r"^##\s*\[(\d+\.\d+\.\d+)\]", changelog_text, re.MULTILINE)
    if not m:
        print(f"ERROR: no release heading found in {CHANGELOG}", file=sys.stderr)
        return 1
    changelog_version = m.group(1)

    if version != changelog_version:
        print(
            f"ERROR: version drift — __version__={version} but CHANGELOG top={changelog_version}.\n"
            f"       Fix: update CHANGELOG.md with a '## [{version}]' section,\n"
            f"       or run tools/bump_version.py to do it automatically.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
