#!/usr/bin/env python3
"""Bump the project version in a single source of truth.

The only place the version lives is ``src/chatfilter/__init__.py`` — the wheel,
the CLI, and the deploy workflow all read from there. This script:

1. Reads the current version from ``__init__.py``.
2. Computes the new version (major / minor / patch).
3. Writes it back to ``__init__.py``.
4. Adds a new ``## [<version>] - <today>`` section to ``CHANGELOG.md``.

Usage:
    python tools/bump_version.py <major|minor|patch> [--message "Release notes"]

Example:
    python tools/bump_version.py patch -m "Fix chat count regression"
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT_FILE = ROOT / "src" / "chatfilter" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"

_VERSION_RE = re.compile(r'(__version__\s*=\s*")([^"]+)(")')


def read_version() -> tuple[int, int, int]:
    text = INIT_FILE.read_text()
    m = _VERSION_RE.search(text)
    if not m:
        raise SystemExit(f"Could not find __version__ in {INIT_FILE}")
    parts = m.group(2).split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(f"Unexpected version format: {m.group(2)}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def write_version(new_version: str) -> None:
    text = INIT_FILE.read_text()
    new_text, n = _VERSION_RE.subn(rf'\g<1>{new_version}\g<3>', text)
    if n != 1:
        raise SystemExit(f"Failed to update {INIT_FILE}")
    INIT_FILE.write_text(new_text)
    print(f"  {INIT_FILE.relative_to(ROOT)}  →  {new_version}")


def bump(major: int, minor: int, patch: int, kind: str) -> tuple[int, int, int]:
    if kind == "major":
        return major + 1, 0, 0
    if kind == "minor":
        return major, minor + 1, 0
    if kind == "patch":
        return major, minor, patch + 1
    raise SystemExit(f"Invalid bump kind: {kind}")


def update_changelog(new_version: str, message: str | None) -> None:
    if not CHANGELOG.exists():
        print(f"  (skipped: {CHANGELOG} not found)")
        return

    today = datetime.now(UTC).strftime("%Y-%m-%d")
    body = (message.strip() + "\n") if message else "### Changed\n- Version bump\n"
    section = f"\n## [{new_version}] - {today}\n\n{body}\n"

    text = CHANGELOG.read_text()
    if "## [Unreleased]" not in text:
        raise SystemExit("CHANGELOG.md must contain '## [Unreleased]' marker")
    text = text.replace("## [Unreleased]\n", f"## [Unreleased]\n{section}")
    CHANGELOG.write_text(text)
    print(f"  {CHANGELOG.relative_to(ROOT)}  →  section [{new_version}] - {today}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Bump the project version.")
    parser.add_argument("kind", choices=["major", "minor", "patch"])
    parser.add_argument("--message", "-m", help="Release notes for CHANGELOG")
    args = parser.parse_args()

    major, minor, patch = read_version()
    old = f"{major}.{minor}.{patch}"
    new_major, new_minor, new_patch = bump(major, minor, patch, args.kind)
    new = f"{new_major}.{new_minor}.{new_patch}"

    print(f"Bumping {old}  →  {new}")
    write_version(new)
    update_changelog(new, args.message)

    print(f"\nDone. Next steps:")
    print(f"  git add src/chatfilter/__init__.py CHANGELOG.md")
    print(f"  git commit -m 'chore: bump version to {new}'")
    print(f"  git tag v{new}")
    print(f"  git push && git push --tags")
    return 0


if __name__ == "__main__":
    sys.exit(main())
