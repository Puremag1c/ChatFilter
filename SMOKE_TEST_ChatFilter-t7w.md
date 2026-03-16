# SMOKE TEST: Dev Server Startup

**Issue:** ChatFilter-t7w
**Status:** ✅ VERIFIED WORKING

## Problem Description
Dev server failed to start in fresh worktree with error:
```
.venv/bin/python: No such file or directory
```

## Root Cause
Fresh worktrees don't have `.venv` directory (gitignored).
Test runner was not executing `build_command` before `start_command`.

## Configuration Status

### testing.yaml ✅
```yaml
type: web
build_command: if [ ! -d .venv ]; then python3 -m venv .venv; fi && .venv/bin/pip install -e .
start_command: .venv/bin/python -m chatfilter.main --host 127.0.0.1 --port 8000
test_url: http://localhost:8000
health_check: /
startup_timeout: 30
```

**Verdict:** Configuration is CORRECT.

## Verification Steps

1. **Build step:**
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -e .
   ```
   ✅ Completed successfully

2. **Start server:**
   ```bash
   .venv/bin/python -m chatfilter.main --host 127.0.0.1 --port 8000
   ```
   ✅ Server started on http://127.0.0.1:8000

3. **Health check:**
   ```bash
   curl -f http://localhost:8000/
   ```
   ✅ Returns 200 OK

## Conclusion

**No code changes required.**

The testing.yaml configuration is correct and follows best practices:
- `build_command` creates venv if missing
- `start_command` uses venv python
- Health check endpoint properly configured

**Action Required:**
Test runner infrastructure must execute `build_command` before `start_command` in worktree environments.

---
**Verified:** 2026-03-16
**Server Version:** ChatFilter v0.19.0
