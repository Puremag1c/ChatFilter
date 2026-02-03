# Session Status Transitions Matrix

## Overview

This document maps all possible session statuses in ChatFilter and their allowed transitions. The status system is **layered**:

1. **Runtime Layer** (`SessionState` enum): 5 core connection states
2. **Computed Layer** (user-visible): 14 distinct statuses derived from runtime + config + auth state
3. **Classification Layer**: Error classification maps exceptions to user-friendly statuses
4. **Priority Layer**: Auth flow > Runtime state > Config state determines displayed status

All status transitions emit events through `SessionEventBus` for real-time UI updates.

---

## 1. Core Runtime States (SessionState Enum)

Defined in `src/chatfilter/telegram/session_manager.py:29-36`

| State | Description | Transitions From | Transitions To |
|-------|-------------|------------------|-----------------|
| `disconnected` | No active Telegram connection, config valid | CONNECTING (failed), ERROR, DISCONNECTING | CONNECTING |
| `connecting` | Connection attempt in progress | DISCONNECTED, ERROR, DISCONNECTING | CONNECTED, ERROR |
| `connected` | Active Telegram connection | CONNECTING (success) | DISCONNECTING, ERROR |
| `disconnecting` | Disconnection in progress | CONNECTED, ERROR | DISCONNECTED, ERROR |
| `error` | Connection failed or lost | CONNECTING (failed), CONNECTED (health check failed) | DISCONNECTED, CONNECTING |

**Key Invariants:**
- Only one state can be active at a time
- Transitions are atomic (handled by SessionManager)
- Error can occur from CONNECTING, CONNECTED, or DISCONNECTING
- To reconnect from ERROR: must pass through DISCONNECTED first

---

## 2. Computed User-Visible Statuses

Derived from `src/chatfilter/web/routers/sessions.py:857-952` (`list_stored_sessions()`)

All 14 possible session statuses:

### 2.1 Configuration-Level Statuses (Invalid/Incomplete Setup)

| Status | Meaning | Visible When | User Action Required |
|--------|---------|--------------|----------------------|
| `needs_api_id` | Missing required config (api_id, api_hash, phone, or proxy_id) | Session exists but config incomplete | User must update Session Settings (POST `/api/sessions/{id}/update`) |
| `proxy_missing` | proxy_id references a proxy that no longer exists | Config exists but referenced proxy deleted | User must select valid proxy in Session Settings |

### 2.2 Authentication Flow Statuses (Active Auth in Progress)

| Status | Meaning | Visible When | Available Actions | Next Status |
|--------|---------|--------------|-------------------|------------|
| `needs_code` | Awaiting Telegram verification code | After `send_code` endpoint called, code not yet sent to app | User submits code via form (POST `/api/sessions/{id}/verify-code`) | `needs_2fa` or `connected` |
| `needs_2fa` | Awaiting 2FA password | Code verified, but account has 2FA enabled | User submits 2FA password (POST `/api/sessions/{id}/verify-2fa`) | `connected` |

**Note:** Auth flow states take priority over runtime states. A session in `connecting` runtime state with active `AuthStep.PHONE_SENT` will display as `needs_code`.

### 2.3 Connection Lifecycle Statuses (Valid Config)

| Status | Meaning | Runtime State | User Actions Available | Possible Next States |
|--------|---------|---------------|------------------------|----------------------|
| `disconnected` | Ready to connect, no active connection | SessionState.DISCONNECTED | - Connect (POST `/api/sessions/{id}/connect`) | `connecting` |
| `connecting` | Connection attempt in progress | SessionState.CONNECTING | - Cancel (POST `/api/sessions/{id}/disconnect`) | `connected`, `error` |
| `connected` | Active Telegram connection established | SessionState.CONNECTED | - Disconnect (POST `/api/sessions/{id}/disconnect`) | `disconnecting`, `error` |
| `disconnecting` | Graceful disconnection in progress | SessionState.DISCONNECTING | - (none, waiting for completion) | `disconnected`, `error` |

**Note:** During `connecting`, if user initiates `send_code` (auth needed), system transitions auth flow and status becomes `needs_code`.

### 2.4 Error Statuses (Classified Error States)

Derived from `src/chatfilter/telegram/session_manager.py:50-154` (`classify_error_state()`)

| Status | Meaning | When It Occurs | Causes | Recovery Path |
|--------|---------|---|--------|---|
| `error` | Generic connection error (no specific cause identified) | Connection fails with unmapped exception | Timeout, network issue, unknown Telethon error | Retry: POST `/api/sessions/{id}/connect` |
| `banned` | Telegram account banned/deactivated | connect() fails with ban-related exception | Account deactivated, phone number banned, or suspended | **Non-recoverable** - User must create new Telegram account |
| `session_expired` | Session revoked or invalidated | connect() fails with session revocation exception | Account security action, app authorization revoked, or stored session invalid | Recover via `send_code` flow: POST `/api/sessions/{id}/reconnect/start` |
| `flood_wait` | Temporary Telegram rate limit active | connect() fails with FloodWaitError | Too many connection attempts in short time | Wait then retry: POST `/api/sessions/{id}/connect` (after delay) |
| `proxy_error` | Proxy connection failed | connect() fails with proxy-related exception | Proxy unreachable, refused connection, or invalid configuration | Check proxy pool, verify proxy credentials |
| `corrupted_session` | Session file corrupted/unreadable | connect() fails with SessionFileError | Disk I/O error, corrupted sqlite file, or permission issue | Delete and recreate: POST `/api/sessions/{id}` (new session) |

**Classification Logic Flow:**
```
connect() exception occurs
    ↓
check exception type (highest priority):
    ├─ SessionFileError → "corrupted_session"
    ├─ SessionExpiredError, AuthKeyUnregisteredError → "session_expired"
    ├─ FloodWaitError, SlowModeWaitError → "flood_wait"
    ├─ UserDeactivatedBanError, PhoneNumberBannedError → "banned"
    └─ Other → check error message for patterns
        ├─ /banned|deactivated/i → "banned"
        ├─ /session.*expired|revoked|reauth/i → "session_expired"
        ├─ /proxy|socks|connection refused/i → "proxy_error"
        └─ (no pattern) → "error"
```

---

## 3. Status Transition Rules

### 3.1 Valid Transitions (Allowed State Changes)

```
                    ┌─────────────────────────────────────┐
                    │                                     │
                    ▼                                     │
        ┌──────────────────┐                             │
        │  needs_api_id    │  (config invalid)           │
        └─────────┬────────┘                             │
                  │ (config updated)                     │
                  ▼                                      │
        ┌──────────────────┐                             │
        │  disconnected    │◄──────────────────────┐     │
        └─────────┬────────┘                       │     │
                  │ (POST /connect)                │     │
                  ▼                                │     │
        ┌──────────────────┐                       │     │
        │   connecting     │                       │     │
        └──────┬──────┬────┘                       │     │
               │      └───── (error) ─────────────┤     │
               │                      ▼            │     │
               │              ┌──────────────┐    │     │
        (success)             │ error*       │────┘     │
               │              └──────────────┘          │
               ▼                                        │
        ┌──────────────────┐                           │
        │    connected     │                           │
        └──────┬──────┬────┘                           │
               │      └──── (health check fails)       │
               │                  ▼ error              │
        (POST /disconnect)  ┌──────────────┐           │
               │            │ error*       │───────────┘
               ▼            └──────────────┘
        ┌──────────────────┐
        │  disconnecting   │
        └──────┬───────────┘
               │
               ▼
        ┌──────────────────┐
        │  disconnected    │
        └──────────────────┘

* error can be classified as: "error", "banned", "session_expired",
  "flood_wait", "proxy_error", "corrupted_session"
```

### 3.2 Auth Flow Overlay

Auth statuses have priority and overlay runtime states:

```
User initiates auth flow (POST /send-code):

    ┌─────────────────────────┐
    │ disconnected or error   │
    │ + config valid          │
    └────────────┬────────────┘
                 │ (POST /send-code)
                 ▼
    ┌──────────────────────────┐
    │ needs_code               │
    │ (awaiting verification)  │
    └────────────┬─────────────┘
                 │ (POST /verify-code)
                 ├─────────────────────┬─────────────────┐
                 │                     │                 │
         (no 2FA enabled)      (2FA enabled)        (error)
                 │                     │                 │
                 ▼                     ▼                 ▼
    ┌──────────────────────────┐  ┌──────────────┐  error*
    │ connected                │  │ needs_2fa    │
    │ (auth success)           │  └──────┬───────┘
    └──────────────────────────┘         │ (POST /verify-2fa)
                                    ┌────┴─────┐
                                    │           │
                              (success)     (error)
                                    │           │
                                    ▼           ▼
                        ┌──────────────────┐  error*
                        │ connected        │
                        └──────────────────┘
```

---

## 4. Endpoint Response Matrix

All endpoints that transition status return HTML partial templates via HTMX:

### 4.1 Session Control Endpoints

| Endpoint | Method | Precondition | Action | Response HTML | New Status |
|----------|--------|--------------|--------|---------------|------------|
| `/api/sessions/{id}/connect` | POST | `disconnected` \| `error` | Initiate connect | `partials/session_row.html` | → `connecting` → `connected` or `error*` |
| `/api/sessions/{id}/disconnect` | POST | `connected` \| `connecting` | Initiate graceful disconnect | `partials/session_row.html` | → `disconnecting` → `disconnected` |
| `/api/sessions/{id}/reconnect/start` | POST | `error*` (session_expired) | Re-auth after expired session | `partials/auth_code_form_reconnect.html` | → `needs_code` |

### 4.2 Authentication Endpoints

| Endpoint | Method | Precondition | Action | Response HTML | New Status |
|----------|--------|--------------|--------|---------------|------------|
| `/api/sessions/{id}/send-code` | POST | Valid config | Send code to Telegram | `partials/auth_code_form_reconnect.html` | `needs_code` |
| `/api/sessions/{id}/verify-code` | POST | `needs_code` | Verify SMS/app code | Form or `partials/modals/modal_2fa.html` | → `needs_2fa` or `connected` |
| `/api/sessions/{id}/verify-2fa` | POST | `needs_2fa` | Verify 2FA password | Success message/redirect | → `connected` or `error*` |

### 4.3 Configuration Endpoints

| Endpoint | Method | Action | Effect on Status |
|----------|--------|--------|------------------|
| `/api/sessions/{id}/update` | POST | Update config (api_id, api_hash, phone, proxy_id) | `needs_api_id` → `disconnected` (if config now valid) |

---

## 5. Status to HTML Response Mapping

When `list_stored_sessions()` is called (e.g., on page load), rendered status determines which button/form is shown:

| Status | Primary Template | Secondary Template | Button Label | UI State |
|--------|------------------|-------------------|--------------|----------|
| `needs_api_id` | `partials/session_row.html` | `partials/session_connection_button.html` | "Configure" | Settings form enabled |
| `proxy_missing` | `partials/session_row.html` | `partials/session_connection_button.html` | "Configure" | Proxy selector enabled |
| `disconnected` | `partials/session_row.html` | `partials/session_connection_button.html` | "Connect" | Connect button enabled |
| `connecting` | `partials/session_row.html` | `partials/session_connection_button.html` | "Connecting..." | Spinner, disconnect button enabled |
| `connected` | `partials/session_row.html` | `partials/session_connection_button.html` | "Disconnect" | Disconnect button enabled, upload ready |
| `disconnecting` | `partials/session_row.html` | `partials/session_connection_button.html` | "Disconnecting..." | Spinner, buttons disabled |
| `needs_code` | `partials/auth_code_form_reconnect.html` | (inline in form) | "Verify Code" | Code input field focused, submit enabled |
| `needs_2fa` | `partials/modals/modal_2fa.html` | (modal overlay) | "Verify 2FA" | Password field in modal, submit enabled |
| `error` | `partials/session_row.html` | `partials/session_connection_button.html` | "Retry" | Retry button enabled, error message shown |
| `banned` | `partials/session_row.html` | `partials/session_connection_button.html` | (disabled) | Error message: "Account banned", no recovery action |
| `session_expired` | `partials/session_row.html` | `partials/session_connection_button.html` | "Re-authenticate" | Reconnect button enabled |
| `flood_wait` | `partials/session_row.html` | `partials/session_connection_button.html` | "Retry (wait)" | Retry button with countdown |
| `proxy_error` | `partials/session_row.html` | `partials/session_connection_button.html` | "Check Proxy" | Error message shown, proxy settings link |
| `corrupted_session` | `partials/session_row.html` | `partials/session_connection_button.html` | "Delete & Recreate" | Option to delete and create new session |

---

## 6. Event Publishing on Status Transitions

Implemented in `src/chatfilter/web/events.py` (SessionEventBus)

Each status transition publishes events for real-time UI updates:

| Transition | Event Published | Data | Subscriber Use Case |
|-----------|-----------------|------|---|
| → `connecting` | `(session_id, "connecting")` | session_id | Update UI: show spinner, disable config |
| → `connected` | `(session_id, "connected")` | session_id | Update UI: show disconnect button, enable upload |
| → `disconnecting` | `(session_id, "disconnecting")` | session_id | Update UI: show spinner, disable buttons |
| → `disconnected` | `(session_id, "disconnected")` | session_id | Update UI: show connect button |
| → `error` | `(session_id, "error")` | session_id + error_message | Update UI: show error, retry button |
| → `needs_code` | `(session_id, "needs_code")` | session_id | Render code input form |
| → `needs_2fa` | `(session_id, "needs_2fa")` | session_id | Render 2FA modal |

**Event Bus Features:**
- **Deduplication:** Consecutive identical events dropped
- **Rate Limiting:** Max 10 events/second per session
- **Isolation:** One failing subscriber doesn't block others
- **Timeout:** Each subscriber handler has 5-second timeout

---

## 7. State Classification Decision Tree

When connection fails, `classify_error_state()` determines the error status:

```
IF exception is SessionFileError
  → return "corrupted_session"
ELSE IF exception is one of [SessionExpiredError, AuthKeyUnregisteredError, SessionRevokedError, SessionReauthRequiredError, SessionInvalidError]
  → return "session_expired"
ELSE IF exception is [FloodWaitError, SlowModeWaitError]
  → return "flood_wait"
ELSE IF exception is [UserDeactivatedBanError, PhoneNumberBannedError]
  → return "banned"
ELSE IF exception has __cause__ (recursive)
  → classify_error_state(__cause__)
ELSE IF error message matches /banned|deactivated/i
  → return "banned"
ELSE IF error message matches /session.*expired|revoked|reauth/i
  → return "session_expired"
ELSE IF error message matches /proxy|socks|connection refused/i
  → return "proxy_error"
ELSE
  → return "error"
```

---

## 8. Complete State Transition Truth Table

| Current Status | Trigger Event | Preconditions | State Change | Response | New Status |
|---|---|---|---|---|---|
| `needs_api_id` | User updates config | Config becomes valid | config_status changes | Settings accepted | `disconnected` |
| `proxy_missing` | User selects valid proxy | Proxy exists in pool | config references valid proxy | Settings accepted | `disconnected` |
| `disconnected` | POST `/connect` | - | SessionState: DISCONNECTED → CONNECTING | `partials/session_row.html` | `connecting` |
| `connecting` | Success | - | SessionState: CONNECTING → CONNECTED | `partials/session_row.html` | `connected` |
| `connecting` | Failure | - | SessionState: CONNECTING → ERROR + classify error | `partials/session_row.html` | `error*` |
| `connecting` | POST `/disconnect` | - | SessionState: CONNECTING → DISCONNECTING | `partials/session_row.html` | `disconnecting` |
| `connected` | Health check succeeds | Periodic check | SessionState: CONNECTED (unchanged) | - | `connected` |
| `connected` | Health check fails | Periodic check | SessionState: CONNECTED → ERROR | Event published | `error*` |
| `connected` | POST `/disconnect` | - | SessionState: CONNECTED → DISCONNECTING | `partials/session_row.html` | `disconnecting` |
| `disconnecting` | Success | - | SessionState: DISCONNECTING → DISCONNECTED | `partials/session_row.html` | `disconnected` |
| `disconnecting` | Failure | - | SessionState: DISCONNECTING → ERROR | `partials/session_row.html` | `error*` |
| `error*` | POST `/connect` | - | SessionState: ERROR → CONNECTING | `partials/session_row.html` | `connecting` |
| `error` (generic) | Retry succeeds | - | SessionState: ERROR → CONNECTED | `partials/session_row.html` | `connected` |
| `session_expired` | POST `/reconnect/start` | - | Initiate auth flow | `partials/auth_code_form_reconnect.html` | `needs_code` |
| `flood_wait` | Wait + POST `/connect` | Delay elapsed | SessionState: ERROR → CONNECTING | `partials/session_row.html` | `connecting` |
| `banned` | - | (no recovery) | - | - | (no transition) |
| `proxy_error` | Proxy restored/reconfigured | - | SessionState: ERROR → DISCONNECTED | - | `disconnected` |
| `corrupted_session` | User deletes session | - | Session deleted, recreate new | Redirect | (new session) |
| `disconnected` | POST `/send-code` | Config valid | AuthStep: PHONE_SENT | `partials/auth_code_form_reconnect.html` | `needs_code` |
| `needs_code` | POST `/verify-code` with code | Code sent to app | Auth success without 2FA | Redirect or success msg | `connected` |
| `needs_code` | POST `/verify-code` with code | Code sent to app | Auth requires 2FA | `partials/modals/modal_2fa.html` | `needs_2fa` |
| `needs_code` | POST `/verify-code` with wrong code | - | SubmitedCodeError | Error form message | `needs_code` (retry) |
| `needs_2fa` | POST `/verify-2fa` with password | Password entered | Auth success | Success message | `connected` |
| `needs_2fa` | POST `/verify-2fa` wrong password | - | PasswordHashInvalidError | Error modal message | `needs_2fa` (retry) |

---

## 9. Verification Checklist

✅ All statuses documented: 5 runtime + 14 computed + endpoint responses
✅ All transitions mapped: config status → runtime → auth flow → error classification
✅ All endpoints return correct HTML partials
✅ Event publishing on transitions confirmed
✅ Error classification logic traced end-to-end
✅ UI state per status documented

---

## 10. References

- **SessionState enum:** `src/chatfilter/telegram/session_manager.py:29-36`
- **Computed statuses:** `src/chatfilter/web/routers/sessions.py:857-952`
- **Error classification:** `src/chatfilter/telegram/session_manager.py:50-154`
- **Event bus:** `src/chatfilter/web/events.py`
- **Endpoints:** `src/chatfilter/web/routers/sessions.py` (all `/api/sessions/{id}/*` routes)
- **HTML templates:** `src/chatfilter/web/templates/partials/`
