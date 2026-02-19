# Security Implementation

## Credential Storage

ChatFilter implements secure storage for Telegram API credentials (api_id and api_hash) to prevent exposure of sensitive data.

### Storage Backends

The application uses a layered approach with multiple storage backends:

1. **OS Keyring (Preferred)** - Native system credential storage
   - macOS: Keychain
   - Windows: Credential Locker
   - Linux: Secret Service (libsecret/gnome-keyring)

2. **Encrypted File (Fallback)** - For systems without keyring support
   - Uses Fernet symmetric encryption
   - Master key stored in `.master.key` with 0600 permissions
   - Credentials stored in `.credentials.enc`

3. **Environment Variables (Read-only)** - For containerized deployments
   - Format: `CHATFILTER_API_ID_{SESSION_ID}` and `CHATFILTER_API_HASH_{SESSION_ID}`
   - Read-only backend, cannot store credentials

### Security Features

- **No Plaintext Storage**: Credentials are never stored in plaintext config files
- **Secure File Permissions**: All sensitive files use 0600 permissions (owner read/write only)
- **Log Redaction**: API credentials are redacted in logs, repr(), and str() output
- **Secure Deletion**: Plaintext files are overwritten with zeros before deletion
- **Auto-Migration**: Existing plaintext config.json files are automatically migrated to secure storage

### Migration from Plaintext

When upgrading from an earlier version that used plaintext config.json files:

1. On first use, credentials are automatically migrated to secure storage
2. The original plaintext config.json is securely deleted (overwritten then removed)
3. A `.migrated` or `.secure_storage` marker file is created to indicate completion

No user action is required - migration happens automatically on session load.

### Backend Selection

The credential manager selects backends in this order:

**For retrieval (reading)**:
1. Environment variables
2. OS Keyring (if available)
3. Encrypted file

**For storage (writing)**:
1. OS Keyring (if available)
2. Encrypted file

### Usage in Code

```python
from chatfilter.security import SecureCredentialManager

# Initialize manager
manager = SecureCredentialManager(storage_dir=Path("/path/to/sessions"))

# Store credentials
manager.store_credentials("session_id", api_id=12345, api_hash="secret")

# Retrieve credentials
api_id, api_hash = manager.retrieve_credentials("session_id")

# Delete credentials
manager.delete_credentials("session_id")

# Check if credentials exist
if manager.has_credentials("session_id"):
    print("Credentials found")
```

### TelegramClientLoader Integration

The `TelegramClientLoader` class has been updated to use secure storage by default:

```python
from pathlib import Path
from chatfilter.telegram.client import TelegramClientLoader

# Secure storage mode (default)
loader = TelegramClientLoader(
    session_path=Path("sessions/my_account/session.session"),
    use_secure_storage=True,  # This is the default
)

# Legacy mode with plaintext (not recommended)
loader = TelegramClientLoader(
    session_path=Path("my_account.session"),
    config_path=Path("config.json"),
    use_secure_storage=False,
)
```

### Verifying Security

To verify that credentials are not leaking:

1. **Check logs**: Credentials should appear as `***REDACTED***`
2. **Check filesystem**: No `config.json` files should exist in session directories
3. **Check keyring**: On macOS, use Keychain Access to view ChatFilter entries
4. **Check encrypted file**: If using fallback, verify `.credentials.enc` exists with 0600 permissions

### Testing

Run the security tests to verify credential storage:

```bash
# Test credential redaction
python3 -c "
from chatfilter.telegram.client import TelegramConfig
config = TelegramConfig(api_id=12345, api_hash='secret')
assert 'secret' not in repr(config)
print('✓ Redaction tests passed')
"

# Test credential storage
python3 -c "
from pathlib import Path
from chatfilter.security import SecureCredentialManager
import tempfile

with tempfile.TemporaryDirectory() as tmpdir:
    manager = SecureCredentialManager(Path(tmpdir))
    manager.store_credentials('test', 12345, 'secret')
    api_id, api_hash = manager.retrieve_credentials('test')
    assert api_id == 12345 and api_hash == 'secret'
    print('✓ Storage tests passed')
"
```

### Troubleshooting

**Keyring not available on Linux:**
- Install `gnome-keyring` or `kwallet`
- System will fall back to encrypted file storage automatically

**Permission denied errors:**
- Ensure the sessions directory has proper ownership
- Check that `.master.key` has 0600 permissions

**Credentials not found:**
- Check if migration completed (look for `.migrated` or `.secure_storage` marker)
- Verify credentials were uploaded through the web interface
- Check environment variables if running in a container

### Security Considerations

1. **Keyring Access**: OS keyring requires user authentication (password, Touch ID, etc.)
2. **Encrypted File**: Master key is stored on disk - protect the sessions directory
3. **Environment Variables**: Suitable for containers but credentials visible in process environment
4. **Memory**: Credentials are held in memory while the session is active
5. **Logs**: Credentials are automatically redacted, but custom logging may need review

### Dependencies

- `keyring>=25.0.0`: OS-native credential storage
- `cryptography>=41.0.0`: Fernet encryption for fallback storage

---

## Web API Security

ChatFilter runs as a **single-user web application** on localhost. All data belongs to the local user running the application.

### Authentication Model

**No user authentication system** - ChatFilter does not implement multi-user support or user accounts:
- No User model or ownership fields in data models
- All sessions, proxies, and data belong to the single application user
- Access control relies on localhost binding and CSRF protection

**Design rationale:**
- Desktop/local-first application - only accessible from the same machine
- User authenticates to the OS, not to ChatFilter
- Adding user authentication would create UX friction without security benefit

### Web Request Protection

All API endpoints are protected by:

1. **CSRF Protection** (`CSRFProtectionMiddleware`)
   - Prevents cross-site request forgery attacks
   - Requires valid CSRF token for all state-changing operations
   - Sufficient protection for same-origin, localhost-bound application

2. **Localhost Binding** (default: `127.0.0.1:5050`)
   - Web server only binds to loopback interface
   - Not accessible from network (unless explicitly configured)
   - Physical access to machine = authorized user

### API Endpoint Security

**Proxy retest endpoint** (`POST /api/proxies/{id}/retest`):
- ✅ CSRF-protected (requires valid token)
- ✅ Localhost-bound (not network-accessible by default)
- ❌ No rate limiting (resource exhaustion risk if abused)
- ❌ No ownership validation (N/A - single user)

**Security implications:**
- Same-origin access only (any browser tab can retest any proxy)
- Resource waste possible if endpoint is spammed
- Acceptable risk for single-user localhost application

**Mitigation:**
- CSRF protection prevents external abuse
- Localhost binding prevents network access
- Future: Add rate limiting (10 retest/minute per proxy_id) if abuse becomes an issue

### Security Headers

Applied via `SecurityHeadersMiddleware`:
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `Referrer-Policy: same-origin` - Limits referrer leakage

### Network Exposure Warning

⚠️ **Do NOT expose ChatFilter to the public internet** without additional authentication:
- No user login system exists
- CSRF protection alone is insufficient for internet-facing deployments
- If network access is required, use SSH tunneling or VPN instead

**For containerized/network deployments**, implement one of:
1. Reverse proxy with HTTP Basic Auth (nginx, Caddy)
2. VPN/WireGuard tunnel for remote access
3. SSH port forwarding (`ssh -L 5050:localhost:5050`)

### Future Enhancements

Potential security improvements (not currently planned):
- [ ] Rate limiting on proxy retest endpoint (10 req/min per proxy_id)
- [ ] Optional HTTP Basic Auth for network deployments
- [ ] API token authentication for programmatic access
- [ ] Session timeout and auto-logout after inactivity
