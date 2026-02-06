# ChatFilter Architecture & Data Model

## Overview

ChatFilter is a Telegram session management application built with Python, FastAPI, and Telethon. It handles multiple Telegram accounts, manages their authentication state, and provides a web UI for session management and chat filtering.

**Stack:** Python 3.11+ / FastAPI / Telethon / HTMX / SQLite

---

## Session Storage Architecture

### Directory Structure

Each session is stored in a dedicated directory with clearly separated concerns:

```
sessions/
  AccountName/
    .account_info.json      # PUBLIC metadata (phone, name, user_id)
    .credentials.enc        # ENCRYPTED secrets (api_id, api_hash, proxy_id)
    session.session         # Telethon auth cache (OPTIONAL)
    config.json             # LEGACY (migrated to .credentials.enc)
```

### Data Model Boundaries

#### 1. `.account_info.json` — PUBLIC METADATA
**Purpose:** Identify the account and display user information
**Encryption:** None (plaintext JSON)
**Can be read:** Immediately on session discovery
**Can be deleted:** Causes session to disappear from UI
**Can be recreated:** During account upload flow

**Fields:**
```json
{
  "user_id": 6405411035,
  "phone": "13803807159",
  "first_name": "A.",
  "last_name": "Shiva",
  "username": null,
  "is_premium": false,
  "chat_count": 0
}
```

**Why separate?**
- Metadata needs to be readable for session discovery
- User identifies accounts by phone/name in UI
- Can be displayed without decryption
- Aligns with Pydantic `AccountInfo` model

**Related code:**
- Model: `chatfilter.models.account.AccountInfo`
- Usage: `src/chatfilter/web/routers/sessions.py` (read on session discovery)

---

#### 2. `.credentials.enc` — ENCRYPTED SECRETS
**Purpose:** Store sensitive Telegram API credentials
**Encryption:** Fernet symmetric encryption (requires `.master.key`)
**Can be read:** Only with encryption key (protected via `SecureCredentialManager`)
**Can be deleted:** Requires re-entry of API credentials
**Can be recreated:** During account upload or credential edit flow

**Fields (before encryption):**
```json
{
  "api_id": 123456,
  "api_hash": "abcdef0123456789abcdef0123456789",
  "proxy_id": "proxy_name_or_null"
}
```

**Why encrypted?**
- API credentials are Telegram secrets (like passwords)
- Must not leak to logs, crash dumps, or process memory inspection
- Encryption key is managed by OS/system (not in repo)
- File permissions: 0600 (owner read/write only)

**Encryption layers:**
1. **OS Keyring** (preferred) - Native system credential storage
   - macOS: Keychain
   - Windows: Credential Locker
   - Linux: Secret Service (libsecret/gnome-keyring)

2. **Encrypted file** (fallback) - Fernet encryption
   - Master key in `.master.key` (0600 permissions)
   - Credentials in `.credentials.enc`

3. **Environment variables** (read-only) - For containerized deployments
   - Format: `CHATFILTER_API_ID_{SESSION_ID}` / `CHATFILTER_API_HASH_{SESSION_ID}`
   - Cannot store new credentials

**Related code:**
- Manager: `chatfilter.security.credentials.SecureCredentialManager`
- Usage: `src/chatfilter/telegram/client.py` (load on client initialization)
- Testing: `tests/test_security_credentials.py`

**Redaction rules:**
- API credentials are **never** logged in plaintext
- Log output shows `***REDACTED***` for sensitive fields
- Repr/str methods redact credentials for debugging

---

#### 3. `session.session` — TELETHON AUTH CACHE
**Purpose:** Cache Telethon session state (auth key, message history, etc.)
**Encryption:** Handled by Telethon library (SQLite database)
**Can be read:** By Telethon client after authentication
**Can be deleted:** Session becomes "disconnected", reauth required
**Can be recreated:** On successful reconnection/reauthentication

**Contains:**
- Telegram auth key (session authentication token)
- Message history metadata
- Telethon internal state

**Why optional?**
- Authentication is stateless - can be recreated anytime
- If deleted/corrupted, user triggers `send_code` flow → `verify-code` → reconnected
- Presence of this file == "cached auth" state
- Absence of this file == "disconnected" state (but account metadata remains)

**Key insight:** If only `.account_info.json` and `.credentials.enc` exist but not `session.session`:
- Session is still **discoverable** (has metadata + credentials)
- Session is **disconnected** (no cached auth)
- Connect button triggers standard `send_code` → `needs_code` flow

**Related code:**
- Telethon client: `src/chatfilter/telegram/client.py`
- Session manager: `src/chatfilter/telegram/session_manager.py`
- Status check: Presence of file determines "connected" vs "disconnected" state

---

## Separation of Concerns

### Why This Split?

| Concern | File | Reason |
|---------|------|--------|
| **Metadata** | `.account_info.json` | Must be readable for session discovery, user displays name/phone |
| **Credentials** | `.credentials.enc` | Sensitive - must be encrypted, access controlled |
| **Auth state** | `session.session` | Optional cache - can be recreated anytime |

### Data Flow

```
Session Discovery:
  ├─ Read .account_info.json → Display name, phone, user_id
  ├─ Check for session.session file → Determine connected/disconnected
  └─ Credentials accessed only when: client init, edit credentials flow

Connect Flow:
  ├─ Load credentials from .credentials.enc
  ├─ Create Telethon client with API credentials
  ├─ If session.session missing/invalid → send_code → needs_code
  └─ On successful auth → create/update session.session

Upload Flow:
  ├─ Receive .session file (Telethon cache) + JSON metadata
  ├─ Extract phone/name from JSON → save to .account_info.json
  ├─ Extract api_id/api_hash from session → save to .credentials.enc
  └─ Import session.session as-is

Edit Credentials Flow:
  ├─ Load current credentials from .credentials.enc
  ├─ User updates api_id/api_hash
  ├─ Save to .credentials.enc
  └─ No change to metadata or session.session
```

---

## File Ownership & Access

### `.account_info.json`
- **Owner:** Session discovery / UI rendering
- **Access:** Read on startup, write on upload/create
- **Permissions:** 0644 (world readable for now)
- **Visibility:** Public (can be exposed in UI)

### `.credentials.enc`
- **Owner:** `SecureCredentialManager`
- **Access:** Read on client init, write on credential store/update
- **Permissions:** 0600 (owner only)
- **Visibility:** Never logged, never displayed

### `session.session`
- **Owner:** Telethon client
- **Access:** Read/write by Telethon
- **Permissions:** 0600 (owner only)
- **Visibility:** Never logged, binary format

### `.master.key` (fallback encryption)
- **Owner:** Encryption system
- **Access:** Read only (protect like a password)
- **Permissions:** 0600 (owner only)
- **Visibility:** CRITICAL - protect in version control (.gitignore)

---

## Session States & File Presence

### State Machine

| State | Metadata | Credentials | Session.session | Meaning |
|-------|----------|-------------|-----------------|---------|
| **discoverable** | ✓ | ✓ | ✗ | Account exists, needs connection |
| **disconnected** | ✓ | ✓ | ✗ | Same as discoverable (ready to connect) |
| **connecting** | ✓ | ✓ | ✗ | In-flight connection attempt |
| **connected** | ✓ | ✓ | ✓ | Auth cached, client can use session |
| **needs_code** | ✓ | ✓ | ✗ | Waiting for SMS/email code |
| **needs_2fa** | ✓ | ✓ | ✗ | Waiting for 2FA password |
| **error** | ✓ | ✓ | ? | Connection failed |

**Key rule:** If metadata + credentials exist, session is discoverable, even without `session.session`.

---

## Migration Path: Old → New

### Before (Plaintext)
```
sessions/Shiva/
  config.json           # api_id, api_hash in plaintext ⚠️
  session.session       # Auth cache
```

### After (Secure)
```
sessions/Shiva/
  .account_info.json    # Metadata from config
  .credentials.enc      # api_id, api_hash (encrypted)
  session.session       # Auth cache (unchanged)
```

### Auto-Migration Process
1. On first session load, detect plaintext `config.json`
2. Extract api_id, api_hash, proxy_id
3. Store in `.credentials.enc` via `SecureCredentialManager`
4. Securely delete plaintext `config.json` (overwrite with zeros)
5. Create `.migrated` or `.secure_storage` marker file
6. Log migration completion

**Related code:** `chatfilter.security.credentials` migration logic

---

## Security Principles

### 1. Separation of Secrets
- Metadata is public (`.account_info.json`)
- Credentials are encrypted (`.credentials.enc`)
- Auth state is Telethon-managed (`session.session`)

### 2. Least Privilege
- Each component reads only what it needs
- Credentials accessed only by client initialization
- Metadata accessible to UI rendering

### 3. Defense in Depth
- Encryption at rest (Fernet)
- Access control via OS keyring or file permissions
- Redaction in logs and debug output

### 4. Secure Deletion
- Plaintext files overwritten before deletion
- Sensitive data cleared from memory
- No temporary plaintext copies

---

## Testing & Verification

### Account Info Tests
- Location: `tests/test_account_info.py`
- Validates: Pydantic model, limits, thresholds

### Credential Storage Tests
- Location: `tests/test_security_credentials.py`
- Validates: Encryption, storage backends, redaction

### Session Upload Tests
- Location: `tests/test_telegram_client.py`
- Validates: File parsing, credential extraction, account info creation

---

## Open Questions Resolved

### Q1: Shiftable between environments?
**A:** Yes. Encrypt with OS keyring on macOS/Linux/Windows, with encrypted file as fallback. Environment variables for containers.

### Q2: 2FA storage location?
**A:** Added `twoFA_encrypted` field to `.account_info.json` (future enhancement). Can be auto-filled during `verify-code` flow.

### Q3: Backward compatibility?
**A:** Auto-migrate plaintext `config.json` to `.credentials.enc` on first load. No user action required.

---

## Implementation Checklist

- [x] Clarify data model boundaries (this document)
- [ ] Update upload flow to parse JSON metadata → `.account_info.json`
- [ ] Ensure `SecureCredentialManager` handles all credential storage
- [ ] Update session discovery to read `.account_info.json` for display
- [ ] Verify session state machine reflects file presence
- [ ] Add auto-migration for legacy `config.json`
- [ ] Document in-code with comments
- [ ] Add integration tests for full upload → display cycle

---

**Created:** 2026-02-06
**Phase:** Architecture Definition
**Status:** In Progress
