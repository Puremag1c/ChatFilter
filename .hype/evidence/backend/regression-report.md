# REGRESSION DETECTED

## Summary
Task `ChatFilter-pz3e8` (Update _do_connect_in_background_v2: auto-handle expired/corrupted sessions) was marked as CLOSED on 2026-02-10, but **the auto-recovery flow is NOT working** due to config check blocking recovery.

## Evidence
### Failed Tests
1. `test_scenario_3_expired_session_auto_send_code` - secure_delete_file NOT called
2. `test_scenario_4_normal_connect_success` - connect() NOT called, blocked at config check
3. `test_scenario_5_banned_account` - banned status NOT detected, config check first
4. `test_authkey_unregistered_triggers_recovery` - secure_delete_file NOT called
5. `test_session_revoked_triggers_recovery` - secure_delete_file NOT called
6. `test_session_expired_triggers_recovery` - secure_delete_file NOT called
7. `test_recovery_without_phone_publishes_error` - secure_delete_file NOT called

All tests show same log: `WARNING  chatfilter.web.routers.sessions:sessions.py:2831 Session 'test_session' has config issue: API credentials required`

## Root Cause
**File:** `src/chatfilter/web/routers/sessions.py`
**Line:** 2828

```python
# CASE 1: Check config validity (no api_id/api_hash or proxy missing)
# This catches ApiIdInvalidError BEFORE attempting connection
config_status, config_reason = get_session_config_status(session_dir)
if config_status == "needs_config":
    # Missing credentials or proxy → needs_config
    logger.warning(f"Session '{session_id}' has config issue: {config_reason}")
    error_message = config_reason or "Configuration incomplete"
    safe_error_message = sanitize_error_message_for_client(error_message, "needs_config")
    if config_path:
        _save_error_to_config(config_path, safe_error_message, retry_available=False)
    await get_event_bus().publish(session_id, "needs_config")
    return  # ← EARLY RETURN, never reaches recovery code
```

Config check happens at line 2828, **BEFORE** session file validity check.

Recovery code exists at line 2881-2920, but is **NEVER REACHED** when config is incomplete.

## Order Violation
**Current order:**
1. Check config (api_id, api_hash, proxy) ← returns early if missing
2. Check session file (never reached if config missing)
3. Recovery logic (never reached if config missing)

**SPEC required order (Must Have #4):**
1. Check if session file exists (first time auth)
2. Check if session file is valid (expired → auto-recover)
3. Check config validity
4. Connect

## Why Tests Fail
Tests mock session recovery errors (AuthKeyUnregisteredError, SessionRevokedError) but **don't mock proxy_id in config**, so:
1. `get_session_config_status()` returns `("needs_config", "Proxy configuration required")`
2. Early return at line 2837
3. Recovery code at line 2881 never executes
4. `secure_delete_file()` never called

## Impact
- SPEC Must Have #2: "Убрать session_expired состояние" - NOT working
- SPEC Must Have #4: "Упрощённый Connect flow" - blocked by wrong order
- All expired/revoked/corrupted sessions show `needs_config` instead of auto-recovering

## Required Fix
Move config check AFTER session validity check:
1. Check session file exists
2. Try to connect (will catch expired/revoked errors)
3. On expired/revoked → auto-delete, send_code (existing code at line 2881)
4. If still fails → check config
