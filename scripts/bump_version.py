#!/usr/bin/env python3
"""Version bumping script for ChatFilter.

Usage:
    python scripts/bump_version.py <major|minor|patch> [--message "Release message"]

Examples:
    python scripts/bump_version.py patch
    python scripts/bump_version.py minor --message "Add new feature"
    python scripts/bump_version.py major --message "Breaking changes"
"""

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path


def get_current_version(project_root: Path) -> tuple[int, int, int]:
    """Extract current version from pyproject.toml."""
    pyproject_path = project_root / "pyproject.toml"
    content = pyproject_path.read_text()

    match = re.search(r'version = "(\d+)\.(\d+)\.(\d+)"', content)
    if not match:
        raise ValueError("Could not find version in pyproject.toml")

    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def bump_version(major: int, minor: int, patch: int, bump_type: str) -> tuple[int, int, int]:
    """Calculate new version based on bump type."""
    if bump_type == "major":
        return major + 1, 0, 0
    elif bump_type == "minor":
        return major, minor + 1, 0
    elif bump_type == "patch":
        return major, minor, patch + 1
    else:
        raise ValueError(f"Invalid bump type: {bump_type}")


def update_pyproject(project_root: Path, old_version: str, new_version: str) -> None:
    """Update version in pyproject.toml."""
    pyproject_path = project_root / "pyproject.toml"
    content = pyproject_path.read_text()

    content = content.replace(f'version = "{old_version}"', f'version = "{new_version}"')

    pyproject_path.write_text(content)
    print(f"✓ Updated {pyproject_path}")


def update_init_py(project_root: Path, old_version: str, new_version: str) -> None:
    """Update version in __init__.py."""
    init_path = project_root / "src" / "chatfilter" / "__init__.py"
    content = init_path.read_text()

    content = content.replace(f'__version__ = "{old_version}"', f'__version__ = "{new_version}"')

    init_path.write_text(content)
    print(f"✓ Updated {init_path}")


def update_changelog(project_root: Path, new_version: str, message: str | None) -> None:
    """Update CHANGELOG.md with new version."""
    changelog_path = project_root / "CHANGELOG.md"

    if not changelog_path.exists():
        print("⚠ CHANGELOG.md not found, skipping")
        return

    content = changelog_path.read_text()
    today = datetime.now().strftime("%Y-%m-%d")

    # Create new version section
    new_section = f"\n## [{new_version}] - {today}\n\n"
    if message:
        new_section += f"{message}\n\n"
    else:
        new_section += "### Changed\n- Version bump\n\n"

    # Insert after [Unreleased] section
    content = content.replace("## [Unreleased]\n", f"## [Unreleased]\n{new_section}")

    # Update version comparison links at the bottom
    lines = content.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("[Unreleased]:"):
            # Update Unreleased link to compare with new version
            lines[i] = re.sub(
                r"\[Unreleased\]: .*/compare/v[\d.]+\.\.\.HEAD",
                f"[Unreleased]: https://github.com/Puremag1c/ChatFilter/compare/v{new_version}...HEAD",
                line,
            )
            # Add new version comparison link
            lines.insert(
                i + 1,
                f"[{new_version}]: https://github.com/Puremag1c/ChatFilter/releases/tag/v{new_version}",
            )
            break

    content = "\n".join(lines)
    changelog_path.write_text(content)
    print(f"✓ Updated {changelog_path}")


def main() -> int:
    """Main function."""
    parser = argparse.ArgumentParser(description="Bump version for ChatFilter")
    parser.add_argument(
        "bump_type", choices=["major", "minor", "patch"], help="Type of version bump"
    )
    parser.add_argument("--message", "-m", help="Release message for CHANGELOG")

    args = parser.parse_args()

    # Find project root
    project_root = Path(__file__).parent.parent

    try:
        # Get current version
        major, minor, patch = get_current_version(project_root)
        old_version = f"{major}.{minor}.{patch}"
        print(f"Current version: {old_version}")

        # Calculate new version
        new_major, new_minor, new_patch = bump_version(major, minor, patch, args.bump_type)
        new_version = f"{new_major}.{new_minor}.{new_patch}"
        print(f"New version: {new_version}")

        # Update files
        update_pyproject(project_root, old_version, new_version)
        update_init_py(project_root, old_version, new_version)
        update_changelog(project_root, new_version, args.message)

        print(f"\n✓ Version bumped from {old_version} to {new_version}")
        print("\nNext steps:")
        print("  1. Review changes: git diff")
        print(
            f"  2. Commit changes: git add -A && git commit -m 'chore: bump version to {new_version}'"
        )
        print(f"  3. Create tag: git tag v{new_version}")
        print("  4. Push changes: git push && git push --tags")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
