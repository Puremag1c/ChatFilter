# Versioning Guide

ChatFilter follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Version Format

Versions follow the format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Incremented for incompatible API changes or breaking changes
- **MINOR**: Incremented for new functionality in a backwards-compatible manner
- **PATCH**: Incremented for backwards-compatible bug fixes

## Bumping Version

### Automated Method

Use the provided version bump script:

```bash
# Bump patch version (0.1.0 -> 0.1.1)
python scripts/bump_version.py patch

# Bump minor version (0.1.0 -> 0.2.0)
python scripts/bump_version.py minor

# Bump major version (0.1.0 -> 1.0.0)
python scripts/bump_version.py major

# Include a custom release message
python scripts/bump_version.py minor --message "Add export to PDF feature"
```

The script will:
1. Update version in `pyproject.toml`
2. Update version in `src/chatfilter/__init__.py`
3. Update `CHANGELOG.md` with the new version
4. Display instructions for committing and tagging

### Manual Method

If you prefer to update manually:

1. Update version in `pyproject.toml`:
   ```toml
   [project]
   version = "0.2.0"
   ```

2. Update version in `src/chatfilter/__init__.py`:
   ```python
   __version__ = "0.2.0"
   ```

3. Update `CHANGELOG.md`:
   ```markdown
   ## [0.2.0] - 2026-01-20

   ### Added
   - New feature description

   ### Fixed
   - Bug fix description
   ```

## Creating a Release

After bumping the version:

1. **Review changes**:
   ```bash
   git diff
   ```

2. **Commit the version bump**:
   ```bash
   git add -A
   git commit -m "chore: bump version to 0.2.0"
   ```

3. **Create a git tag**:
   ```bash
   git tag v0.2.0
   ```

4. **Push changes and tag**:
   ```bash
   git push
   git push --tags
   ```

5. **GitHub Release**: The release workflow will automatically create a GitHub release when a tag is pushed.

## CHANGELOG Maintenance

The `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.

### Categories

- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security vulnerabilities

### Example Entry

```markdown
## [Unreleased]

### Added
- New export format for analysis results

### Fixed
- Memory leak in background task processor

## [0.2.0] - 2026-01-20

### Added
- PDF export functionality
- User preferences system
```

## Conventional Commits

We recommend using [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:

- `feat:` - New feature (triggers MINOR version bump)
- `fix:` - Bug fix (triggers PATCH version bump)
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks
- `BREAKING CHANGE:` - Breaking changes (triggers MAJOR version bump)

### Examples

```bash
git commit -m "feat: add PDF export for analysis results"
git commit -m "fix: prevent memory leak in task queue"
git commit -m "docs: update installation instructions"
git commit -m "feat!: redesign API endpoints

BREAKING CHANGE: API endpoints now use /api/v2 prefix"
```

## Version Display

The version is displayed in:
- Web UI footer (all pages)
- `--version` CLI flag
- Package metadata

## CI/CD Integration

The release workflow (`.github/workflows/release.yml`) automatically:
1. Creates a GitHub release when a version tag is pushed
2. Extracts changelog for the version
3. Triggers build workflows for distributable binaries

## Checking Current Version

### From CLI
```bash
chatfilter --version
```

### From Python
```python
from chatfilter import __version__
print(__version__)
```

### From Web UI
Check the footer on any page.
