# Session Status Transitions Matrix

## Overview

The session state management system defines all valid status transitions in the ChatFilter Telegram session lifecycle. The core state machine is defined in `src/chatfilter/telegram/session_manager.py:SessionState`.

This document provides a complete audit of:
1. **Core SessionState** (5 internal states)
2. **Extended User Status** (computed from core state + configuration + auth flow)
3. **Valid state transitions** for each API endpoint
4. **Error classification** (6 error subtypes)
5. **Concurrency and locking** mechanisms

---

## Part 1: Core SessionState

### Defined States

All session state is an instance of `SessionState` enum with 5 valid values:

| State | Source Line | Description | Lifecycle |
|-------|---|---|---|
| `DISCONNECTED` | Line 32 | Session exists but not connected to Telegram | Initial state, or after disconnect completes |
| `CONNECTING` | Line 33 | Connection attempt in progress | Transient state during `connect()` call |
| `CONNECTED` | Line 34 | Active connection to Telegram, operations possible | Stable state after successful connect |
| `DISCONNECTING` | Line 35 | Disconnection in progress | Transient state during `disconnect()` call |
| `ERROR` | Line 36 | Connection failed or auth issue detected | Terminal state from failed connect or health check |

**Source:** `src/chatfilter/telegram/session_manager.py:29-36`

---

## Part 2: State Transitions (Core Logic)

All state transitions are controlled by the `SessionManager` class. States change only via:
1. `async def connect()` - initiates connection
2. `async def disconnect()` - initiates disconnection
3. `async def is_healthy()` - health checks that may set ERROR
4. Background monitor task - checks health periodically

### Connect Flow

```
DISCONNECTED
    ↓ [SessionManager.connect() called]
CONNECTING
    │
    ├─→ [Line 309: success] CONNECTED
    │   - Session.client.connect() succeeds
    │   - Session.client.iter_dialogs(limit=1) succeeds (account active check)
    │   - Event "connected" published
    │
    └─→ [failure] ERROR
        ├─ [Line 319] TimeoutError → state = ERROR, error_msg = "Connection timeout"
        ├─ [Line 335] Session invalid (revoked/banned) → state = ERROR, error_msg = "Session is invalid"
        ├─ [Line 372] Session needs re-auth (2FA/expired) → state = ERROR, error_msg = "2FA required" or "Expired"
        └─ [Line 398] Generic exception → state = ERROR, error_msg = str(exception)
        - Event "error" published in all cases
```

**Timeout:** 30 seconds (DEFAULT_CONNECT_TIMEOUT = 30.0, line 23)

### Disconnect Flow

```
[CONNECTED or ERROR or DISCONNECTING]
    ↓ [SessionManager.disconnect() called]
DISCONNECTING
    │ [Line 423: set state]
    │ [Line 426-428: client.disconnect() with 10s timeout]
    │
    └─→ [Line 435: complete]
DISCONNECTED
    - Event "disconnected" published
```

**Timeout:** 10 seconds (DEFAULT_DISCONNECT_TIMEOUT = 10.0, line 25)

### Health Check Flow

The background monitor (`_monitor_connections`) runs continuously, checking each `CONNECTED` session every 60 seconds:

```
CONNECTED
    ↓ [Health check scheduled]
    │ [_check_session_health() / is_healthy()]
    │
    ├─→ [Line 474: success] CONNECTED (stay connected)
    │   - session.get_me() succeeds (auth valid)
    │
    └─→ [auth error detected] ERROR
        ├─ [Line 486] Session invalid errors
        ├─ [Line 497] Session needs re-auth
        └─ [Line 522] Other errors
        - Event "error" published
```

**Health check timeout:** 5 seconds (DEFAULT_HEALTH_CHECK_TIMEOUT = 5.0, line 26)

**Heartbeat interval:** 60 seconds (default, configurable)

**Zombie connection recovery:** After 3 consecutive failed health checks, the monitor:
1. Calls `disconnect()` (move to DISCONNECTING)
2. Waits 0.5 seconds (line 674)
3. Calls `connect()` (move to CONNECTING)

---

## Part 3: Extended User Status (Web API Layer)

While the core SessionState has 5 values, the web layer returns 12+ statuses that combine:
- Core SessionState value
- Configuration validity (api_id, api_hash, proxy presence)
- Auth flow state (code sent, 2FA required)
- Error type classification (if in ERROR state)

### All Possible User-Facing Statuses

| Status | Condition | Use Case |
|---|---|---|
| `disconnected` | Core state DISCONNECTED + config valid | Session ready to connect |
| `needs_api_id` | Config missing api_id, api_hash, or proxy_id | User must provide Telegram API credentials |
| `proxy_missing` | Config references proxy that doesn't exist | User must select valid proxy |
| `connecting` | Core state CONNECTING | Connection attempt in progress |
| `connected` | Core state CONNECTED | Session operational, ready for operations |
| `disconnecting` | Core state DISCONNECTING | Disconnection in progress |
| `needs_code` | Auth flow waiting for SMS/Telegram code | User must enter verification code |
| `needs_2fa` | Auth flow waiting for 2FA password | User must enter 2FA password |
| `error` | Core state ERROR (generic, uncategorized) | Unknown connection error |
| `session_expired` | Core state ERROR + classified as expired | Session revoked or auth key invalid |
| `banned` | Core state ERROR + classified as banned | Account deactivated or banned |
| `flood_wait` | Core state ERROR + classified as flood wait | Rate limited by Telegram |
| `proxy_error` | Core state ERROR + classified as proxy error | Proxy connection failed |
| `corrupted_session` | Core state ERROR + classified as corrupted | Session file is invalid/locked |

**Source:** `src/chatfilter/web/routers/sessions.py:53-157` (error classification), lines 860-955 (status resolution)

---

## Part 4: Endpoint Status Transitions

### 1. `POST /api/sessions/{session_id}/connect`

**Purpose:** Initiate connection from DISCONNECTED state

**Source:** Line 2461

| From Status | Precondition | Action | To Status | HTTP |
|---|---|---|---|---|
| `disconnected` | config valid | Call SessionManager.connect() | → `connecting` → `connected` | 200 |
| `disconnected` | config invalid | N/A | stays `needs_api_id` | 400 |
| `connected` | already connected | Return error | stays `connected` | 400 |

---

### 2. `POST /api/sessions/{session_id}/disconnect`

**Purpose:** Disconnect from CONNECTED, ERROR, or CONNECTING states

**Source:** Line 2606

| From Status | Action | To Status | HTTP |
|---|---|---|---|
| `connected` | Call SessionManager.disconnect() | → `disconnecting` → `disconnected` | 200 |
| `error` | Call SessionManager.disconnect() | → `disconnecting` → `disconnected` | 200 |
| `connecting` | Call SessionManager.disconnect() | → `disconnecting` → `disconnected` | 200 |
| `disconnected` | Already disconnected | stays `disconnected` | 400 |

---

### 3. `POST /api/sessions/{session_id}/send-code`

**Purpose:** Start SMS/Telegram code authentication flow

**Source:** Line 2691

| From Status | Action | To Status | HTTP |
|---|---|---|---|
| `disconnected` | Initiate auth via phone | → `connecting` → `needs_code` | 200 |
| `needs_code` | Resend code (rate limited: 30s) | stays `needs_code` | 200 or 429 |

---

### 4. `POST /api/sessions/{session_id}/verify-code`

**Purpose:** Submit verification code from SMS/Telegram

**Source:** Line 3320

| From Status | Input | To Status | HTTP |
|---|---|---|---|
| `needs_code` | valid code | → `connected` (if no 2FA) or `needs_2fa` (if 2FA enabled) | 200 |
| `needs_code` | invalid code | stays `needs_code` | 400 |

---

### 5. `POST /api/sessions/{session_id}/verify-2fa`

**Purpose:** Submit 2FA password

**Source:** Line 3654

| From Status | Input | To Status | HTTP |
|---|---|---|---|
| `needs_2fa` | valid password | → `connected` | 200 |
| `needs_2fa` | invalid password | stays `needs_2fa` | 400 |

---

### 6. `PUT /api/sessions/{session_id}/config`

**Purpose:** Update session configuration (API credentials, proxy)

**Source:** Line 1350

| From Status | Action | To Status | HTTP |
|---|---|---|---|
| `needs_api_id` | Provide missing credentials | → `disconnected` | 200 |
| `proxy_missing` | Provide proxy | → `disconnected` | 200 |
| `disconnected` | Update credentials | stays `disconnected` | 200 |
| `connected` | Update triggers reconnect | → `disconnecting` → `connecting` → `connected` | 200 |

---

### 7. `PUT /api/sessions/{session_id}/credentials`

**Purpose:** Update session credentials (inline)

**Source:** Line 1531

| From Status | Action | To Status | HTTP |
|---|---|---|---|
| `connected` | Update credentials | stays `connected` | 200 |
| `disconnected` | Update credentials | stays `disconnected` | 200 |

---

### 8. `GET /api/sessions`

**Purpose:** List all sessions with current status

**Source:** Line 963

Returns: JSON array of `{ session_id, state, error_message?, auth_id? }` for each registered session

No state transitions (read-only)

---

### 9. `GET /api/sessions/{session_id}/config`

**Purpose:** Get session configuration and validation status

**Source:** Line 1290

No state transitions (read-only)

---

### 10. `GET /api/sessions/events`

**Purpose:** Server-sent events stream for real-time status updates

**Source:** Line 4140

**Events published:**
- `connected` - when state changes to CONNECTED
- `disconnected` - when state changes to DISCONNECTED
- `error` - when state changes to ERROR

---

## Part 5: Error Classification

When core state is `ERROR`, the system classifies the error into one of 6 specific types:

### Classification Logic

**Source:** `src/chatfilter/web/routers/sessions.py:53-157`

#### 1. `corrupted_session`
Triggered by:
- `SessionFileError` exception
- Error message contains: "invalid session file", "not a valid database", "corrupted", "locked", "incompatible", "database error"

User action: Delete and re-upload session file

#### 2. `session_expired`
Triggered by:
- `SessionExpiredError`, `SessionRevokedError`, `AuthKeyUnregisteredError`, `AuthKeyInvalidError`, `UnauthorizedError`, `SessionReauthRequiredError`, `SessionInvalidError`
- Error message contains: "sessionexpired", "authkeyunregistered", "sessionrevoked", "expired", "revoked", "re-authorization", "reauthentication", "auth key"

User action: Upload new session file or re-authenticate

#### 3. `banned`
Triggered by:
- `UserDeactivatedBanError`, `PhoneNumberBannedError`, `UserDeactivatedError`
- Error message contains: "banned", "deactivated", "phonenumberbanned"

User action: Contact Telegram support (account issue is permanent)

#### 4. `flood_wait`
Triggered by:
- `FloodWaitError`, `SlowModeWaitError`
- Error message contains: "floodwait", "flood"

User action: Wait for timeout, then retry

#### 5. `proxy_error`
Triggered by:
- Error message contains: "proxy", "socks5", "connection refused", "host unreachable"
- Network-related errors when proxy is configured

User action: Check proxy configuration and availability

#### 6. `error`
Fallback for any error not classified above

User action: Retry or check logs

---

## Part 6: Concurrency & Session Locking

### Lock Mechanism

**Source:** `src/chatfilter/telegram/session_manager.py:72, 299`

Each `ManagedSession` has an `asyncio.Lock`:

```python
session.lock: asyncio.Lock = field(default_factory=asyncio.Lock)
```

All state-changing operations acquire this lock:
- `connect()` - acquires lock at line 299
- `disconnect()` - acquires lock at line 419
- `is_healthy()` - calls operations that may check lock

### Busy Error

**Source:** Line 293-297

If a lock is already held, the next `connect()` call raises `SessionBusyError`:

```python
if session.lock.locked():
    raise SessionBusyError(
        f"Session '{session_id}' is already busy with another operation. "
        "Please wait for the current operation to complete."
    )
```

This prevents:
- Multiple concurrent `connect()` calls
- `connect()` + `disconnect()` race conditions
- Invalid state transitions

---

## Part 7: State Machine Diagram

```
                    ┌─────────────────┐
                    │  DISCONNECTED   │ (initial)
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │ connect()       │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
            ┌──────▶│   CONNECTING    │◀──────┐
            │       └────────┬────────┘       │
            │                │                │
            │    ┌───────────┴───────────┐    │
            │    │                       │    │
            │    │ (success)  (failure)  │    │
            │    ▼                       ▼    │
            │  ┌──────────────┐      ┌─────────┐
            │  │  CONNECTED   │      │  ERROR  │
            │  └───┬────┬─────┘      └────┬────┘
            │      │    │                 │
            │      │    │ disconnect()    │
            │      │    └─────────┬───────┘
            │      │              │
            │      │ disconnect() │
            │      │              │
            │      └──────┬───────┴─────┐
            │             │             │
            │             ▼             │
            │       ┌──────────────┐    │
            │       │DISCONNECTING │    │
            │       └───────┬──────┘    │
            │               │           │
            │               ▼           │
            └─────DISCONNECTED◀────────┘

Legend:
→   = normal transition
◀───= health check error or recovery path
```

---

## Part 8: Verification Checklist

This document has been verified against the following source files:

- [x] `src/chatfilter/telegram/session_manager.py` - SessionState enum and transitions (all verified)
- [x] `src/chatfilter/web/routers/sessions.py` - Endpoint handlers and status logic (spot-checked)
- [x] `src/chatfilter/web/events.py` - Event publishing (referenced)
- [x] Timeout values verified:
  - [x] Connect timeout: 30 seconds (not 120)
  - [x] Disconnect timeout: 10 seconds
  - [x] Health check timeout: 5 seconds
  - [x] Heartbeat interval: 60 seconds
- [x] All 5 core states documented
- [x] All 12+ user-facing statuses documented
- [x] All endpoint transitions documented
- [x] Error classification logic documented
- [x] Lock mechanism documented
- [x] Event system documented

### HTML Response Verification

All endpoints in Part 4 return HTML partials (HTMX responses) with status code 200 on success or 400 on validation error:

- [x] Connect endpoint (`POST /api/sessions/{session_id}/connect`) - Returns HTMLResponse with button state (line 2461)
- [x] Disconnect endpoint (`POST /api/sessions/{session_id}/disconnect`) - Returns HTMLResponse with updated UI (line 2606)
- [x] Send code endpoint (`POST /api/sessions/{session_id}/send-code`) - Returns HTMLResponse with auth form (line 2691)
- [x] Verify code endpoint (`POST /api/sessions/{session_id}/verify-code`) - Returns HTMLResponse with status (line 3320)
- [x] Verify 2FA endpoint (`POST /api/sessions/{session_id}/verify-2fa`) - Returns HTMLResponse with result (line 3654)
- [x] Config update endpoint (`PUT /api/sessions/{session_id}/config`) - Returns HTMLResponse with validation (line 1350)
- [x] Credentials update endpoint (`PUT /api/sessions/{session_id}/credentials`) - Returns HTMLResponse (line 1531)

All endpoints use `response_class=HTMLResponse` decorator and return HTML partials for HTMX integration.

---

## Part 9: Testing Checklist

To verify these transitions work, test these scenarios:

### Core Transitions
- [ ] DISCONNECTED → CONNECTING → CONNECTED (normal `connect()`)
- [ ] DISCONNECTED → CONNECTING → ERROR (timeout or invalid auth)
- [ ] CONNECTED → DISCONNECTING → DISCONNECTED (normal `disconnect()`)
- [ ] CONNECTED → ERROR (health check fails)
- [ ] ERROR → DISCONNECTING → DISCONNECTED (recover from error)

### Auth Flow
- [ ] Send code: DISCONNECTED → CONNECTING → needs_code
- [ ] Verify code: needs_code → CONNECTED (if no 2FA) or needs_2fa (if enabled)
- [ ] Verify 2FA: needs_2fa → CONNECTED
- [ ] Invalid code: needs_code stays needs_code

### Config Errors
- [ ] needs_api_id → disconnected (provide credentials)
- [ ] proxy_missing → disconnected (provide proxy)

### Concurrent Operations
- [ ] Multiple `connect()` calls: second raises SessionBusyError
- [ ] `connect()` + `disconnect()` during CONNECTING: handled by lock

### Health Check & Monitoring
- [ ] Health check passes: CONNECTED stays CONNECTED
- [ ] Health check fails (3x): triggers zombie recovery
- [ ] Network switch error: fast reconnection triggered

### Event Streaming
- [ ] `connected` event emitted when state→CONNECTED
- [ ] `disconnected` event emitted when state→DISCONNECTED
- [ ] `error` event emitted when state→ERROR

---

## Related Documentation

- Session Management: `docs/SESSION_MANAGEMENT.md`
- Network & Firewall: `docs/NETWORK_AND_FIREWALL.md`
- Key Management: `docs/KEY_MANAGEMENT.md`

## Source Code References

All line numbers refer to the current version of these files:
- `src/chatfilter/telegram/session_manager.py` - SessionState enum and state machine
- `src/chatfilter/web/routers/sessions.py` - HTTP endpoints and status resolution
- `src/chatfilter/web/events.py` - Event bus for state transitions
