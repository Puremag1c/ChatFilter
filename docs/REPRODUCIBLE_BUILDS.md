# Reproducible Builds Analysis

**Document Version:** 1.0
**Last Updated:** 2026-01-21
**Status:** Security Audit Complete

## Executive Summary

This document analyzes the reproducibility of ChatFilter's PyInstaller-based build process and provides recommendations for achieving deterministic builds. Reproducible builds are critical for security audits, allowing independent verification that distributed binaries match the source code.

**Current Status:** Builds are **NOT fully reproducible** due to:
- Embedded timestamps in Python bytecode and archives
- Unpinned dependency versions
- Non-deterministic build environment variables
- Variable file ordering in archives

**Risk Level:** Medium - While checksums are generated for verification, the inability to independently reproduce builds limits third-party security audits.

## Background

### Why Reproducible Builds Matter

Reproducible (deterministic) builds ensure that:
1. **Verifiability**: Anyone can rebuild from source and verify the binary matches the published version
2. **Supply Chain Security**: Detects tampering or compromised build systems
3. **Audit Confidence**: Security researchers can verify that distributed binaries contain only declared source code
4. **Trust**: Users can independently verify binaries haven't been backdoored

### What is a Reproducible Build?

A build is reproducible when:
```
Same Source Code + Same Build Process + Same Dependencies = Identical Binary
```

Even minor differences (timestamps, metadata) prevent byte-for-byte reproduction.

## Current Build Process Analysis

### Build Configuration

**Build Tool:** PyInstaller 6.0+
**Spec File:** [chatfilter.spec](chatfilter.spec:1:0)
**Build Scripts:**
- Unix/macOS: [build.sh](build.sh:1:0)
- Windows: `build.bat`
- CI/CD: GitHub Actions workflows

**PyInstaller Settings:**
```python
debug=False          # No debug output
strip=False          # Debug symbols retained (may include build paths)
upx=False           # UPX compression disabled (good for reproducibility)
onedir=True         # Directory mode (exclude_binaries=True)
console=True        # Console application
```

### Dependencies Management

**Installation:** `pip install -r requirements-build.txt`

**Current Constraints:**
```
pyinstaller>=6.0.0    # Minimum version, not pinned
telethon>=1.34.0      # Minimum version, not pinned
fastapi>=0.109.0      # Minimum version, not pinned
# ... (all dependencies use >= constraints)
```

**Issue:** Using `>=` constraints means different build environments may resolve to different dependency versions, causing non-reproducible builds.

### CI/CD Build Environment

**GitHub Actions Workflows:**
- [.github/workflows/build-windows.yml](.github/workflows/build-windows.yml:1:0)
- [.github/workflows/build-macos.yml](.github/workflows/build-macos.yml:1:0)
- [.github/workflows/release.yml](.github/workflows/release.yml:1:0)

**Fixed Parameters:**
- Python version: 3.11 (pinned)
- Runner OS: `windows-latest`, `macos-latest`, `ubuntu-latest`
- Build flags: `--clean --noconfirm`

**Variable Parameters:**
- Exact Python 3.11.x patch version (updates over time)
- Dependency versions (resolved at build time)
- Build timestamp
- Runner-specific paths

## Sources of Non-Determinism

### 1. Timestamps

**Impact:** HIGH

PyInstaller embeds timestamps in multiple locations:

**Python Bytecode (.pyc files):**
- Each `.pyc` file includes compilation timestamp
- Stored in first 4 bytes of bytecode header
- Changes with every build

**ZIP Archive Members:**
- PyInstaller creates `.pyz` archive with embedded .pyc files
- Each archive member has a modification timestamp
- File ordering may vary

**Build Metadata:**
- Build time recorded in various metadata structures

**Evidence:**
```bash
# Comparing two builds of the same source
$ diff build1/dist/ChatFilter/_internal/*.pyz build2/dist/ChatFilter/_internal/*.pyz
Binary files differ (timestamps)
```

### 2. Build Paths

**Impact:** MEDIUM

**Absolute Paths Embedded:**
- Debug symbols may include build directory paths
- Python module `__file__` attributes
- Traceback information

**Example:**
```python
# In frozen executable
/Users/runner/work/ChatFilter/ChatFilter/src/chatfilter/main.py
vs
/home/user/projects/ChatFilter/src/chatfilter/main.py
```

**Current Mitigation:**
- `strip=False` retains symbols (increases risk)
- Onedir mode reduces path embedding vs onefile

### 3. Python Hash Randomization

**Impact:** MEDIUM

**Issue:** Python's hash randomization affects:
- Dictionary iteration order
- Set iteration order
- Module import order (in some cases)

**Environment Variable:** `PYTHONHASHSEED`
- Default: random seed per process
- Not set in current builds
- Can cause different bytecode ordering

### 4. Dependency Version Drift

**Impact:** HIGH

**Current State:**
- All dependencies use `>=` constraints
- Transitive dependencies completely unpinned
- Pip resolves latest compatible versions at build time

**Example Scenario:**
```
Build on 2026-01-15: telethon==1.34.0, uvicorn==0.27.0
Build on 2026-01-30: telethon==1.34.2, uvicorn==0.27.1
→ Different binaries
```

**Impact on Reproducibility:**
- Different machines get different versions
- Builds weeks apart get different versions
- No guarantee of identical dependencies

### 5. File Ordering

**Impact:** LOW

**Issue:**
- Filesystem directory listing order varies by:
  - Operating system
  - Filesystem type
  - Locale settings
- Archive member ordering may be non-deterministic

**PyInstaller Behavior:**
- Collects files via filesystem traversal
- Order affects archive structure
- May impact binary layout

### 6. Build Environment Variables

**Impact:** LOW-MEDIUM

**Variables That May Affect Build:**
- `$HOME`, `$USER`, `$HOSTNAME` (may be embedded in metadata)
- `$PYTHONPATH` (affects module resolution)
- `$PATH` (affects external tool discovery)
- Locale settings (`$LC_ALL`, `$LANG`)

## Verification Testing Methodology

To verify reproducibility, the following test should be performed:

### Test Procedure

```bash
# 1. Clean build
./build.sh clean
pyinstaller chatfilter.spec --clean --noconfirm

# 2. Calculate checksums
find dist/ChatFilter -type f -exec sha256sum {} \; | sort > checksums1.txt

# 3. Clean again
./build.sh clean

# 4. Rebuild (same source, same environment)
pyinstaller chatfilter.spec --clean --noconfirm

# 5. Calculate checksums again
find dist/ChatFilter -type f -exec sha256sum {} \; | sort > checksums2.txt

# 6. Compare
diff checksums1.txt checksums2.txt
```

### Expected Results (Current State)

**Expected Outcome:** Files WILL differ

**Files Expected to Differ:**
- `ChatFilter` or `ChatFilter.exe` (main executable)
- `_internal/*.pyz` (Python bytecode archive)
- `_internal/*.pyc` (Python bytecode files)
- Timestamp metadata in all archives

**Files That Should Match:**
- Static assets (templates, CSS, JS)
- CA certificates
- Data files

### Verification Tools

**diffoscope:**
- Tool for deep binary comparison
- Shows exactly what differs between builds
- Available at: https://diffoscope.org/

```bash
# Install
pip install diffoscope

# Compare builds
diffoscope dist1/ChatFilter dist2/ChatFilter
```

## Recommendations for Achieving Reproducibility

### Priority 1: Critical Changes

#### 1.1 Set SOURCE_DATE_EPOCH

**Description:** Unix timestamp used as fixed build time for all operations.

**Implementation:**

**In GitHub Actions workflows:**
```yaml
# Add to each build job
- name: Set reproducible build timestamp
  run: |
    # Use commit timestamp as SOURCE_DATE_EPOCH
    echo "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" >> $GITHUB_ENV

- name: Build with fixed timestamp
  env:
    SOURCE_DATE_EPOCH: ${{ env.SOURCE_DATE_EPOCH }}
    PYTHONHASHSEED: 0
  run: |
    pyinstaller chatfilter.spec --clean --noconfirm
```

**In build.sh:**
```bash
# Add after line 8
# Set fixed timestamp for reproducibility
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export PYTHONHASHSEED=0
```

#### 1.2 Pin All Dependencies

**Description:** Use exact version constraints for all dependencies.

**Implementation:**

1. Generate locked requirements:
```bash
# Install pip-tools
pip install pip-tools

# Generate locked requirements from pyproject.toml
pip-compile --generate-hashes --output-file=requirements-build.lock pyproject.toml
```

2. Update workflows to use locked file:
```yaml
- name: Install dependencies
  run: |
    python -m pip install --upgrade pip
    pip install --require-hashes -r requirements-build.lock
```

3. Create `requirements-build.lock`:
```
# This file is autogenerated by pip-compile
# To update, run: pip-compile --generate-hashes pyproject.toml
pyinstaller==6.3.0 \
    --hash=sha256:abc123...
telethon==1.34.0 \
    --hash=sha256:def456...
# ... (exact versions with hashes for verification)
```

#### 1.3 Fix Python Patch Version

**Description:** Pin exact Python version, not just major.minor.

**Implementation:**
```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.11.7'  # Exact version, not '3.11'
```

### Priority 2: Important Improvements

#### 2.1 Enable strip_binaries

**Description:** Remove debug symbols to avoid embedded paths.

**Implementation in chatfilter.spec:**
```python
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    strip=True,  # Changed from False - removes debug symbols
    # ... rest unchanged
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=True,  # Changed from False
    # ... rest unchanged
)
```

**Trade-off:** Less detailed error tracebacks, but more reproducible.

#### 2.2 Set Build Environment Variables

**Description:** Normalize environment variables that may affect build.

**Implementation in build.sh and workflows:**
```bash
# Add to build.sh after line 8
export LC_ALL=C
export TZ=UTC
export PYTHONHASHSEED=0
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)

# Ensure consistent Python bytecode
export PYTHONDONTWRITEBYTECODE=1  # Don't create .pyc during build
```

#### 2.3 Use Reproducible Archive Creation

**Description:** Ensure ZIP/tar archives have consistent ordering and timestamps.

**Implementation:**
```bash
# For ZIP files (Windows, macOS)
# Add --reproducible flag if available, or use custom script

# For tar files (Linux)
tar --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --owner=0 --group=0 --numeric-owner \
    -czf ChatFilter-Linux.tar.gz ChatFilter
```

### Priority 3: Optional Enhancements

#### 3.1 Build in Clean Container

**Description:** Use Docker to ensure consistent build environment.

**Implementation:**
```dockerfile
# Dockerfile.build
FROM python:3.11.7-slim

# Set reproducible build environment
ENV SOURCE_DATE_EPOCH=1234567890 \
    PYTHONHASHSEED=0 \
    LC_ALL=C \
    TZ=UTC

WORKDIR /build
COPY . .

RUN pip install --require-hashes -r requirements-build.lock
RUN pyinstaller chatfilter.spec --clean --noconfirm

CMD ["bash"]
```

```bash
# Build in container
docker build -t chatfilter-builder -f Dockerfile.build .
docker run --rm -v $(pwd)/dist:/build/dist chatfilter-builder
```

#### 3.2 Implement Build Verification

**Description:** Automated reproducibility testing in CI.

**Implementation:**
```yaml
# Add to workflow
- name: Verify reproducibility
  run: |
    # First build
    pyinstaller chatfilter.spec --clean --noconfirm
    mv dist dist1

    # Second build (same source)
    pyinstaller chatfilter.spec --clean --noconfirm
    mv dist dist2

    # Compare
    if diff -r dist1/ChatFilter dist2/ChatFilter; then
      echo "✓ Build is reproducible"
    else
      echo "✗ Build is NOT reproducible"
      diffoscope dist1/ChatFilter/ChatFilter dist2/ChatFilter/ChatFilter || true
      exit 1
    fi
```

#### 3.3 Document Build Process

**Description:** Provide detailed build instructions for independent verification.

**Add to BUILD.md:**
```markdown
## Reproducing Official Builds

To independently verify an official release:

1. Check out the exact release tag:
   ```bash
   git clone https://github.com/username/ChatFilter.git
   cd ChatFilter
   git checkout v0.1.0
   ```

2. Install exact dependencies:
   ```bash
   pip install --require-hashes -r requirements-build.lock
   ```

3. Set environment variables:
   ```bash
   export SOURCE_DATE_EPOCH=1737457200  # Release timestamp
   export PYTHONHASHSEED=0
   export LC_ALL=C
   export TZ=UTC
   ```

4. Build:
   ```bash
   pyinstaller chatfilter.spec --clean --noconfirm
   ```

5. Compare checksums:
   ```bash
   sha256sum dist/ChatFilter/ChatFilter
   # Should match published checksum
   ```
```

## Implementation Roadmap

### Phase 1: Quick Wins (1-2 days)

- [ ] Set `SOURCE_DATE_EPOCH` in all build workflows
- [ ] Set `PYTHONHASHSEED=0` in all build workflows
- [ ] Pin exact Python version (3.11.7)
- [ ] Document current limitations

**Expected Improvement:** Reduces timestamp-based differences

### Phase 2: Dependency Management (3-5 days)

- [ ] Generate `requirements-build.lock` with pip-compile
- [ ] Update workflows to use locked requirements
- [ ] Add `--require-hashes` to pip install
- [ ] Test builds with locked dependencies

**Expected Improvement:** Eliminates dependency version drift

### Phase 3: Environment Hardening (1 week)

- [ ] Enable `strip=True` in spec file
- [ ] Set all environment variables for reproducibility
- [ ] Implement reproducible archive creation
- [ ] Add build verification to CI

**Expected Improvement:** Eliminates most remaining sources of non-determinism

### Phase 4: Full Reproducibility (2 weeks)

- [ ] Create Docker-based build environment
- [ ] Document complete reproduction process
- [ ] Add automated reproducibility testing
- [ ] Publish verification guide for security researchers

**Expected Result:** Fully reproducible builds achievable by third parties

## Testing & Verification

### After Implementing Changes

```bash
# 1. Build twice on same machine
./build.sh
mv dist dist1
./build.sh
mv dist dist2

# 2. Compare binaries
cmp dist1/ChatFilter/ChatFilter dist2/ChatFilter/ChatFilter
# Expected: No differences

# 3. Verify checksums
sha256sum dist1/ChatFilter/ChatFilter
sha256sum dist2/ChatFilter/ChatFilter
# Expected: Identical hashes

# 4. Deep comparison (if available)
diffoscope dist1/ChatFilter dist2/ChatFilter
# Expected: No differences or only expected differences
```

### Cross-Platform Reproducibility

**Note:** Perfect cross-platform reproducibility (same binary from Windows, macOS, Linux) is **not achievable** with PyInstaller because:

1. Platform-specific executable formats (.exe vs Mach-O vs ELF)
2. Platform-specific system libraries bundled
3. Platform-specific Python builds

**Goal:** Each platform should have reproducible builds **within that platform**.

## Security Considerations

### Current Risk Assessment

**Without Reproducible Builds:**
- ✗ Third parties cannot verify binaries match source
- ✗ Compromised build system could inject backdoors undetected
- ✗ Supply chain attacks harder to detect
- ✓ Checksums provide basic integrity verification (but only of published binary)

**With Reproducible Builds:**
- ✓ Independent verification possible
- ✓ Build system compromises detectable
- ✓ Supply chain security improved
- ✓ Increased trust from security community

### Threat Scenarios Mitigated

1. **Compromised CI/CD:**
   - Attacker gains access to GitHub Actions
   - Injects malicious code during build
   - **With reproducibility:** Independent builders detect different binary

2. **Dependency Confusion:**
   - Attacker publishes malicious package with same name
   - Build system downloads malicious version
   - **With locked deps + hashes:** Attack prevented

3. **Time-based Attacks:**
   - Attacker modifies code temporarily during build window
   - **With reproducibility:** Later rebuilds show discrepancy

## References

### Standards & Best Practices

- [Reproducible Builds Project](https://reproducible-builds.org/)
- [SOURCE_DATE_EPOCH Specification](https://reproducible-builds.org/specs/source-date-epoch/)
- [Python Reproducibility Documentation](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONHASHSEED)
- [PyInstaller Documentation](https://pyinstaller.org/)

### Tools

- **diffoscope** - In-depth binary comparison tool
  - https://diffoscope.org/
  - `pip install diffoscope`

- **pip-tools** - Dependency locking and management
  - https://github.com/jazzband/pip-tools
  - `pip install pip-tools`

- **reprotest** - Automated reproducibility testing
  - https://salsa.debian.org/reproducible-builds/reprotest

### Related Issues

- [ChatFilter-86r] - Windows code signing (completed)
- [SECURITY.md](../SECURITY.md) - Overall security documentation

## Changelog

### 2026-01-21 - Initial Analysis

- Analyzed current PyInstaller build process
- Identified sources of non-determinism
- Documented recommendations for reproducibility
- Created implementation roadmap

---

**Document Status:** Initial audit complete, awaiting implementation
**Next Review:** After Phase 1 implementation
**Owner:** Security Team
