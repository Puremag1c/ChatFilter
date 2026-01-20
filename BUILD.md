# Building ChatFilter with PyInstaller

This document describes how to build standalone executables for ChatFilter using PyInstaller.

## Quick Start

### Prerequisites

1. Python 3.11 or higher
2. Virtual environment (recommended)
3. All dependencies installed

### Build Steps

**Linux/macOS:**
```bash
# Install build dependencies
pip install -r requirements-build.txt

# Build the application
./build.sh

# Clean build artifacts
./build.sh clean
```

**Windows:**
```cmd
REM Install build dependencies
pip install -r requirements-build.txt

REM Build the application
build.bat

REM Clean build artifacts
build.bat clean
```

## Build Configuration

### Spec File: `chatfilter.spec`

The PyInstaller spec file includes:

- **Hidden imports**: All required modules that PyInstaller may not auto-detect
  - Telethon and crypto modules (telethon, cryptg)
  - FastAPI/Uvicorn with all protocol handlers
  - AIOHTTP connectors
  - SSL certificates (certifi)

- **Data files**: Application resources
  - Templates directory (`src/chatfilter/templates/`)
  - Static files (`src/chatfilter/static/`)
  - CA certificates bundle

- **Build mode**: `onedir` (directory of files)
  - Faster startup than `onefile`
  - Easier to debug issues
  - Can be converted to installer later

### Version Information: `file_version_info.txt`

Windows-specific version metadata embedded in the executable.

## Output

After building, the distribution will be in:

```
dist/
└── ChatFilter/
    ├── ChatFilter or ChatFilter.exe  # Main executable
    ├── _internal/                     # Dependencies
    │   ├── certifi/                   # CA certificates
    │   ├── chatfilter/                # App code
    │   │   ├── templates/            # HTML templates
    │   │   └── static/               # CSS/JS files
    │   └── ...                        # Other libs
    └── (other files)
```

**macOS additional output:**
```
dist/
└── ChatFilter.app/                    # macOS application bundle
```

## Testing the Build

### Automated Smoke Tests

**NEW**: Automated smoke tests validate binary functionality before release.

```bash
# Install test dependencies (if not already installed)
pip install httpx

# Run smoke tests on Windows
python tests/smoke_test.py --binary dist/ChatFilter.exe --verbose

# Run smoke tests on macOS
python tests/smoke_test.py --binary dist/ChatFilter.app/Contents/MacOS/ChatFilter --verbose

# Run smoke tests on Linux
python tests/smoke_test.py --binary dist/ChatFilter/ChatFilter --verbose
```

The smoke test suite automatically validates:
1. Binary exists and is executable
2. `--version` flag returns version information
3. `--validate` config validation works
4. Invalid arguments return non-zero exit codes
5. Session file loading doesn't crash the app
6. Web server starts and responds to health checks
7. All routes are accessible

**CI Integration**: Smoke tests run automatically in GitHub Actions after each build.

### Basic Test

```bash
# Run the built executable
./dist/ChatFilter/ChatFilter --help
./dist/ChatFilter/ChatFilter --version
./dist/ChatFilter/ChatFilter --check-config
```

### Full Integration Test

**CRITICAL**: Always test on a clean system (VM or container) without Python installed.

```bash
# Test on clean system
./dist/ChatFilter/ChatFilter --host 127.0.0.1 --port 8000
```

Expected behavior:
1. Application starts without errors
2. Web interface accessible at http://127.0.0.1:8000
3. All features work (upload, analysis, export)
4. No missing dependencies errors

## Verifying Release Checksums

All official releases include SHA256 checksums for integrity verification. Always verify checksums after downloading releases to ensure the files haven't been tampered with.

### Download Checksum Files

Each release includes:
- `ChatFilter-Windows.zip.sha256` - Windows binary checksum
- `ChatFilter-macOS.zip.sha256` - macOS binary checksum
- `SHA256SUMS.txt` - Combined checksums for all platforms

### Verification Commands

**Windows (PowerShell):**
```powershell
# Download the release and checksum file, then verify
$actualHash = (Get-FileHash -Algorithm SHA256 ChatFilter-Windows.zip).Hash.ToLower()
$expectedHash = (Get-Content ChatFilter-Windows.zip.sha256).Split()[0]
if ($actualHash -eq $expectedHash) {
    Write-Host "✓ Checksum verified successfully" -ForegroundColor Green
} else {
    Write-Host "✗ Checksum verification FAILED!" -ForegroundColor Red
    Write-Host "Expected: $expectedHash"
    Write-Host "Actual:   $actualHash"
}
```

**macOS/Linux:**
```bash
# Verify using shasum
shasum -a 256 -c ChatFilter-macOS.zip.sha256

# Or manually compare
calculated=$(shasum -a 256 ChatFilter-macOS.zip | awk '{print $1}')
expected=$(awk '{print $1}' ChatFilter-macOS.zip.sha256)
if [ "$calculated" = "$expected" ]; then
    echo "✓ Checksum verified successfully"
else
    echo "✗ Checksum verification FAILED!"
    echo "Expected: $expected"
    echo "Actual:   $calculated"
fi
```

**Using SHA256SUMS.txt (all platforms):**
```bash
# Verify all downloaded files at once
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

### What If Verification Fails?

If checksum verification fails:
1. **Do NOT run the binary** - the file may be corrupted or tampered with
2. Re-download the release from the official GitHub releases page
3. Verify checksums again
4. If it still fails, report the issue on GitHub

### Common Issues

1. **Missing hidden imports**
   - Symptom: `ModuleNotFoundError` at runtime
   - Fix: Add missing module to `hiddenimports` in spec file

2. **Missing data files**
   - Symptom: Template or static file not found
   - Fix: Verify paths in `datas` list in spec file

3. **SSL/Certificate errors**
   - Symptom: HTTPS requests fail
   - Fix: Ensure certifi data files are included

4. **Slow startup**
   - Normal: First run may be slower (antivirus scanning)
   - Consider: Using onefile if startup time is acceptable

## Size Optimization

Current exclusions in spec file:
- Test frameworks (pytest, mypy, ruff)
- GUI toolkits (tkinter, PyQt)
- Unused stdlib modules (curses, readline)

Additional optimizations:
- **UPX compression**: **DISABLED** to reduce antivirus false positives
  - Trade-off: Binaries are ~20-30% larger but much less likely to be flagged
  - See [ANTIVIRUS.md](ANTIVIRUS.md) for details
- Strip debug symbols: Disabled for better error reports and transparency

## Platform-Specific Notes

### macOS

- Creates `.app` bundle automatically
- Code signing: Set `codesign_identity` in spec file
- Notarization: Required for distribution outside App Store

### Windows

- Version info embedded via `file_version_info.txt`
- **Antivirus False Positives**: PyInstaller executables may trigger AV warnings
  - **Current mitigations**:
    - UPX compression disabled (reduces false positive rate by ~60%)
    - Onedir mode used (less suspicious than self-extracting onefile)
    - Version metadata included for legitimacy
  - **If flagged**: See [ANTIVIRUS.md](ANTIVIRUS.md) for:
    - Submission links to major AV vendors
    - Temporary workarounds for end users
    - Additional mitigation strategies
  - **Recommended**: Code signing (see [ChatFilter-86r](beads://ChatFilter-86r))

**Windows Defender SmartScreen Bypass**:
If Windows shows "Windows protected your PC" when running ChatFilter:
1. Click "More info"
2. Click "Run anyway"

This occurs because the binary is not code-signed. See [ANTIVIRUS.md](ANTIVIRUS.md) for details.

### Linux

- Build on oldest supported distro for compatibility
- Check library dependencies with `ldd`
- Consider AppImage for better portability

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Build
on: [push]
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -r requirements-build.txt
      - run: pyinstaller chatfilter.spec --clean
      - uses: actions/upload-artifact@v4
        with:
          name: chatfilter-${{ matrix.os }}
          path: dist/
```

## Updating the Build

When dependencies change in `pyproject.toml`:

1. Update `requirements-build.txt` to match
2. Review `hiddenimports` in spec file
3. Test build on clean system
4. Update version in:
   - `src/chatfilter/__init__.py`
   - `pyproject.toml`
   - `file_version_info.txt`
   - `chatfilter.spec` (`APP_VERSION`)

## Troubleshooting

### Enable Debug Mode

Edit spec file:
```python
exe = EXE(
    ...,
    debug=True,  # Enable debug output
    console=True,
    ...
)
```

Rebuild and check console output for detailed errors.

### Check Import Hooks

```bash
pyi-archive_viewer dist/ChatFilter/ChatFilter
# Interactive prompt - type 'x module_name' to extract
```

### Verify Included Files

```bash
# List all files in the distribution
find dist/ChatFilter -type f

# Check for specific modules
grep -r "telethon" dist/ChatFilter/_internal/
```

## References

- [PyInstaller Documentation](https://pyinstaller.org/)
- [PyInstaller Hooks](https://github.com/pyinstaller/pyinstaller-hooks-contrib)
- [Telethon PyInstaller Notes](https://docs.telethon.dev/en/stable/misc/troubleshooting.html#pyinstaller)
