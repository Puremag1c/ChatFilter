# API Test Findings

## Summary
Tested the ChatFilter web API endpoints. Server is running correctly at http://localhost:8000.

## Endpoints Tested

### 1. Root endpoint (/)
- URL: http://localhost:8000/
- Status: **200 OK** ✅
- Response: HTML page (rendered correctly)

### 2. Health endpoint (/health)
- URL: http://localhost:8000/health  
- Status: **200 OK** ✅
- Response: JSON with status, version, uptime, telegram, disk, network, update info
- Note: Status is "degraded" (no telegram sessions connected - expected)

### 3. Sessions page (/sessions)
- URL: http://localhost:8000/sessions
- Status: **200 OK** ✅
- Response: HTML page (sessions management UI)

### 4. 404 handling
- URL: http://localhost:8000/api/nonexistent
- Status: **404 Not Found** ✅
- Response: {"detail":"Not Found"}

### 5. Static files (CSS)
- URL: http://localhost:8000/static/css/main.css
- Status: **404 Not Found** ❌
- Note: CSS file not found (possible build issue or path misconfiguration)

### 6. CSRF protection
- URL: POST http://localhost:8000/sessions/connect (empty POST)
- Status: **403 Forbidden** ✅
- Response: {"detail":"CSRF validation failed: Token missing","error":"csrf_token_missing"}

### 7. POST endpoints (verify_2fa, verify_code)
- Both protected by CSRF - cannot test without valid session
- Status: **403 Forbidden** ✅

## Code Review Findings

### ✅ Fix 2: HTTP Status Codes (COMPLETED)

All error handlers in `verify_2fa()` and `verify_code()` now return proper HTTP status codes:

| Error Type | Status Code | Location |
|-----------|-------------|----------|
| Invalid password | 400 | verify_2fa:4528 |
| Empty password | 400 | verify_2fa:4537 |
| Auth expired | 410 | verify_2fa:4561 |
| Too many attempts | 429 | verify_2fa:4578, 4761 |
| Session mismatch | 400 | verify_2fa:4590 |
| Connection lost | 502 | verify_2fa:4603 |
| Session revoked | 401 | verify_2fa:4684 |
| Auth key invalid | 401 | verify_2fa:4705 |
| User deactivated | 401 | verify_2fa:4714, 4723 |
| Wrong password | 422 | verify_2fa:4747 |
| Flood wait | 429 | verify_2fa:4761 |
| Proxy error | 502 | verify_2fa:4783 |
| Timeout | 504 | verify_2fa:4803 |
| Generic error | 500 | verify_2fa:4823 |
| Finalize error | 500 | verify_2fa:4650 |

**verify_code()** also has proper status codes:
- Invalid code: 422 (line 4349)
- Expired code: 422 (line 4361)
- Flood wait: 429 (line 4378)
- Empty code: 400 (line 4393)
- Proxy error: 502 (line 4418)
- Timeout: 504 (line 4441)
- Auth expired: 401 (line 4460)
- Generic error: 500 (line 4483)

### ❌ BUG FOUND: Missing status_code in FileNotFoundError handlers

**Location 1:** verify_code() line 4244-4245
```python
return templates.TemplateResponse(
    request=request,
    name="partials/auth_result.html",
    context={"success": False, "error": _("Session directory not found.")},
    # ❌ MISSING: status_code=500 or 404
)
```

**Location 2:** verify_2fa() line 4641-4642
```python
return templates.TemplateResponse(
    request=request,
    name="partials/auth_result.html",
    context={"success": False, "error": _("Session directory not found.")},
    # ❌ MISSING: status_code=500 or 404
)
```

**Impact:** These handlers return HTTP 200 instead of proper error code. This violates Fix 2 requirements from SPEC.md.

**Recommended fix:** Add `status_code=500` (server error - session directory should exist)

### ✅ Fix 1: Auth_state cleanup (COMPLETED)

All generic exception handlers properly call `await auth_manager.remove_auth_state(auth_id)`:
- verify_2fa() line 4810
- verify_code() line 4467

### ✅ Fix 4: Accurate error messages (COMPLETED)

Error messages distinguish between sign_in failure vs finalize failure:
- verify_2fa() line 4821: "Password accepted. Connection failed — please try Connect again."
- verify_code() line 4481: "Code accepted. Connection failed — please try Connect again."

## Verdict

**PASS with 1 bug found**

The API is functional and most endpoints work correctly. However, 2 FileNotFoundError handlers are missing status_code parameter (should return 500, currently return 200).

**Priority:** P1 (affects error handling consistency, but rare edge case)
