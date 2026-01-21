# Cross-Platform Testing Strategy

## Overview

ChatFilter implements comprehensive cross-platform testing to ensure compatibility across different operating systems and Python versions. The testing matrix covers macOS (Intel and Apple Silicon), Windows, and various Python versions.

## Testing Matrix

### Operating Systems

#### macOS
- **macOS 11 (Big Sur)** - Intel - Minimum supported version
- **macOS 12 (Monterey)** - Intel
- **macOS 13 (Ventura)** - Intel
- **macOS 14 (Sonoma)** - ARM64/Apple Silicon
- **macOS latest** - Current stable release

#### Windows
- **Windows Server 2019** - Equivalent to Windows 10
- **Windows Server 2022** - Equivalent to Windows 11
- **Windows latest** - Current stable release

### Python Versions
- **Python 3.11** - Primary supported version
- **Python 3.12** - Latest stable version

## Platform-Specific Tests

### 1. Path Handling
Tests verify correct handling of platform-specific path separators and conventions:
- **Unix-like (macOS)**: Forward slashes (`/`)
- **Windows**: Backslashes (`\`)
- Home directory resolution
- Temporary directory paths
- Application config paths

### 2. Permissions
Tests ensure proper file permission handling:
- **Unix-like**: POSIX permissions (read/write/execute)
- **Windows**: ACL-based permissions
- File creation and access verification

### 3. Python Runtime Compatibility
Tests verify:
- Platform detection and system information
- Core module availability
- Architecture-specific features (x86_64 vs ARM64)
- Platform-specific APIs

### 4. Configuration Paths
Platform-specific config directory handling:
- **macOS**: `~/Library/Application Support/`
- **Windows**: `%APPDATA%` or `~/AppData/Roaming/`
- **Linux**: `~/.config/` (fallback)

## Workflows

### Main Cross-Platform Testing
**Workflow**: [`.github/workflows/cross-platform-tests.yml`](/.github/workflows/cross-platform-tests.yml)

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual workflow dispatch
- Weekly schedule (Mondays at 00:00 UTC)

**Jobs**:
1. **cross-platform-test**: Full test suite across all OS/Python combinations
2. **cross-platform-integration**: Integration tests on latest ARM64 macOS and Windows
3. **cross-platform-summary**: Aggregates results and reports status

### Platform-Specific Build Tests
- **macOS Build**: [`.github/workflows/build-macos.yml`](/.github/workflows/build-macos.yml)
- **Windows Build**: [`.github/workflows/build-windows.yml`](/.github/workflows/build-windows.yml)

## Benefits

### 1. Early Detection
Catches platform-specific issues before they reach users:
- Path separator problems
- Permission errors
- Runtime compatibility issues

### 2. Confidence in Deployments
Ensures binaries work correctly on:
- Older macOS versions (Intel Macs)
- New Apple Silicon Macs (ARM64)
- Different Windows versions

### 3. Clean Environment Testing
GitHub Actions runners are clean VMs without development tools, ensuring:
- No dependency on local dev environments
- Tests run as end-users would experience
- Catches missing dependencies

## Matrix Strategy Optimizations

### Exclusions
To balance coverage and CI time, some combinations are excluded:
- Python 3.12 on older macOS versions (11, 12)

### Fail-Fast Disabled
`fail-fast: false` ensures all platform tests run even if one fails, providing complete visibility into platform-specific issues.

## Running Tests Locally

### Prerequisites
```bash
pip install -e ".[dev]"
```

### Run Full Test Suite
```bash
pytest --cov=src/chatfilter --cov-report=term-missing --cov-fail-under=80
```

### Run Smoke Tests
```bash
python tests/smoke_test.py --verbose
```

### Test Platform Compatibility
```python
python -c "
import sys
import platform
print(f'Platform: {platform.platform()}')
print(f'Python: {sys.version}')
"
```

## Coverage Reports

Coverage reports are generated for each platform combination and uploaded as artifacts:
- Artifact name: `coverage-{os}-py{version}`
- Retention: 7 days
- Format: XML (Cobertura format)

## Maintenance

### Adding New Platforms
To add a new platform to the matrix:
1. Update `matrix.os` in `.github/workflows/cross-platform-tests.yml`
2. Add any platform-specific test steps if needed
3. Update this documentation

### Handling Platform-Specific Failures
When a test fails on a specific platform:
1. Check the platform-specific logs in GitHub Actions
2. Review path handling, permissions, or runtime differences
3. Add platform-specific code paths if necessary
4. Add regression tests to prevent recurrence

## Related Documentation
- [Testing Guide](TESTING.md) - General testing documentation
- [Development Guide](DEVELOPMENT.md) - Development setup and practices
- [Deployment Guide](DEPLOYMENT.md) - Build and release process
