# Encryption Key Management

This document describes the encryption key management system for ChatFilter session files.

## Overview

The key management system provides secure storage and retrieval of encryption keys for protecting session files at rest. It supports multiple backends with automatic fallback:

1. **Environment Variables** (preferred for containers/CI)
2. **Password-Derived Keys** (for user-controlled encryption)
3. **OS Keychain** (for desktop applications)
4. **Machine-Derived Keys** (legacy/fallback)

## Quick Start

### Basic Usage with OS Keychain

```python
from chatfilter.storage import FileStorage, EncryptedStorage
from chatfilter.security import KeyManager

# Create key manager (auto-selects best backend)
key_manager = KeyManager.create()

# Use with encrypted storage
storage = EncryptedStorage(FileStorage(), key_manager=key_manager)

# Save encrypted
storage.save(path, "sensitive data")

# Load decrypted
data = storage.load(path)
```

### Using Environment Variables

Recommended for containerized deployments:

```bash
# Set encryption key in environment
export CHATFILTER_ENCRYPTION_KEY_0="<base64-encoded-fernet-key>"

# Application will automatically use it
python your_app.py
```

### Using Password-Derived Keys

For user-controlled encryption:

```bash
# Set password in environment
export CHATFILTER_ENCRYPTION_PASSWORD="your-secure-password"

# Or pass programmatically
```

```python
from chatfilter.security import KeyManager

km = KeyManager.create(backend_type="password", password="your-secure-password")
```

## Architecture

### Key Backends

#### 1. EnvironmentBackend

Reads keys from environment variables:
- `CHATFILTER_ENCRYPTION_KEY_0` - Key for key_id 0
- `CHATFILTER_ENCRYPTION_KEY_1` - Key for key_id 1
- etc.

**Pros:**
- Explicit configuration
- Works in containers and CI/CD
- No persistent storage required

**Cons:**
- Keys visible in process environment
- Requires manual key distribution

#### 2. PasswordBackend

Derives keys from a master password using PBKDF2-HMAC-SHA256:
- 600,000 iterations (OWASP recommended)
- Unique salt per key_id
- Deterministic key derivation

**Pros:**
- User-controlled security
- No key storage required
- Portable across machines

**Cons:**
- Password must be provided on each startup
- Forgotten password = data loss

#### 3. KeyringBackend

Stores keys in OS-specific secure storage:
- **macOS**: Keychain
- **Windows**: Credential Locker
- **Linux**: Secret Service (gnome-keyring/libsecret)

**Pros:**
- Secure OS-level encryption
- Persistent across restarts
- Integrated with system security

**Cons:**
- Requires keyring library support
- Platform-specific behavior

#### 4. MachineKeyBackend

Derives keys from machine-specific identifiers:
- Linux: `/etc/machine-id`
- Fallback: MAC address

**Pros:**
- No configuration required
- Automatic fallback

**Cons:**
- Keys tied to specific machine
- Cannot move encrypted files
- Less secure than other options

## Backend Selection

The `create()` method automatically selects backends in this priority order:

```python
KeyManager.create(backend_type="auto")
```

Selection order:
1. Environment variables (if `CHATFILTER_ENCRYPTION_KEY_*` exists)
2. Password from environment (if `CHATFILTER_ENCRYPTION_PASSWORD` exists)
3. OS Keyring (if available)
4. Machine-derived keys (fallback)

### Manual Backend Selection

```python
# Environment variables
km = KeyManager.create(backend_type="environment")

# Password-based
km = KeyManager.create(backend_type="password", password="secret")

# OS Keyring
km = KeyManager.create(backend_type="keyring")

# Machine-derived
km = KeyManager.create(backend_type="machine")
```

## Key Rotation

The system supports key rotation for enhanced security:

```python
from chatfilter.security import KeyManager

km = KeyManager.create()

# Rotate from key_id 0 to key_id 1
new_key = km.rotate_key(old_key_id=0, new_key_id=1)

# Re-encrypt files with new key
# (old key is kept for decrypting existing files)
```

**Important:** After rotating keys, you must re-encrypt all files with the new key. The old key is not automatically deleted to allow decryption of existing files.

## Migration from Machine-Derived Keys

If you have existing encrypted files using machine-derived keys, you can migrate to a more secure backend:

```python
from chatfilter.security import KeyManager, MachineKeyBackend
from chatfilter.storage import FileStorage, EncryptedStorage
from pathlib import Path

# Old setup with machine-derived key
old_backend = MachineKeyBackend()
old_key = old_backend.get_key(0)

# New setup with keyring
new_km = KeyManager.create(backend_type="keyring")
new_key = new_km.get_or_create_key(1)  # Use new key_id

# Re-encrypt files
old_storage = EncryptedStorage(FileStorage(), encryption_key=old_key, key_id=0)
new_storage = EncryptedStorage(FileStorage(), key_manager=new_km, key_id=1)

for file_path in Path("encrypted_files").glob("*.enc"):
    # Decrypt with old key
    data = old_storage.load(file_path)

    # Encrypt with new key
    new_storage.save(file_path, data)
```

## Security Considerations

### Key Storage Security

1. **Environment Variables**: Keys visible in process environment. Use for containers/CI only.
2. **Password-Derived**: Secure if password is strong and kept secret. Vulnerable to password compromise.
3. **OS Keyring**: Most secure option for desktop applications. Uses OS-level encryption.
4. **Machine-Derived**: Provides basic at-rest encryption but keys are deterministic.

### Best Practices

1. **Use OS Keyring for desktop applications** - Most secure and user-friendly
2. **Use password-derived for portable encryption** - When files need to move between machines
3. **Use environment variables for containers** - Generate keys during deployment
4. **Rotate keys periodically** - Enhanced security through key rotation
5. **Never commit keys to version control** - Use secrets management
6. **Use unique keys per deployment** - Don't share keys across environments

### Key Generation

Generate secure Fernet keys using Python's cryptography library:

```python
from cryptography.fernet import Fernet

# Generate new key
key = Fernet.generate_key()
print(key.decode('ascii'))  # Use this for CHATFILTER_ENCRYPTION_KEY_0
```

## API Reference

### KeyManager

```python
class KeyManager:
    @classmethod
    def create(
        cls,
        backend_type: str = "auto",
        password: Optional[str] = None,
    ) -> KeyManager

    def get_key(self, key_id: int = 0) -> Optional[bytes]
    def get_or_create_key(self, key_id: int = 0) -> bytes
    def set_key(self, key_id: int, key: bytes) -> None
    def delete_key(self, key_id: int) -> None
    def rotate_key(self, old_key_id: int, new_key_id: int) -> bytes
```

### Backend Types

- `"auto"` - Automatic backend selection
- `"environment"` - Environment variables
- `"password"` - Password-derived keys
- `"keyring"` - OS keychain
- `"machine"` - Machine-derived keys

## Troubleshooting

### "KeyManagerError: Password required"

The password backend requires a password. Set it via:
- Environment variable: `CHATFILTER_ENCRYPTION_PASSWORD=your-password`
- Or pass to `create()`: `KeyManager.create(backend_type="password", password="...")`

### "KeyNotFoundError: Unknown key_id"

The key for the specified key_id doesn't exist. Either:
- Use `get_or_create_key()` instead of `get_key()`
- Or create the key first: `km.set_key(key_id, Fernet.generate_key())`

### "Failed to retrieve key from keyring"

OS keyring is not available or has errors. Fallback options:
- Use password backend: `KeyManager.create(backend_type="password")`
- Use environment variables: Set `CHATFILTER_ENCRYPTION_KEY_0`
- Use machine backend: `KeyManager.create(backend_type="machine")`

### Keys don't persist across restarts

Check your backend:
- **Environment variables**: Need to be set each time
- **Password backend**: Password required each time
- **Keyring backend**: Should persist (check OS keyring is working)
- **Machine backend**: Always available (derived from machine ID)

## Examples

### Docker Deployment

```dockerfile
# Generate key during build
RUN python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > /tmp/key.txt

# Pass as environment variable
ENV CHATFILTER_ENCRYPTION_KEY_0=$(cat /tmp/key.txt)

# Clean up
RUN rm /tmp/key.txt
```

### Kubernetes Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: chatfilter-encryption-key
type: Opaque
data:
  key: "<base64-encoded-fernet-key>"
---
apiVersion: v1
kind: Pod
metadata:
  name: chatfilter
spec:
  containers:
  - name: chatfilter
    image: chatfilter:latest
    env:
    - name: CHATFILTER_ENCRYPTION_KEY_0
      valueFrom:
        secretKeyRef:
          name: chatfilter-encryption-key
          key: key
```

### Multi-User System

```python
from chatfilter.security import KeyManager

# Each user has their own password
user_password = input("Enter your encryption password: ")
km = KeyManager.create(backend_type="password", password=user_password)

# Files encrypted with user's password
storage = EncryptedStorage(FileStorage(), key_manager=km)
```
