"""Security module for ChatFilter.

Provides secure credential storage and encryption key management.
"""

from chatfilter.security.credentials import (
    CredentialNotFoundError,
    CredentialStorageError,
    SecureCredentialManager,
)
from chatfilter.security.key_manager import (
    EnvironmentBackend,
    KeyBackend,
    KeyManager,
    KeyManagerError,
    KeyNotFoundError,
    KeyringBackend,
    MachineKeyBackend,
    PasswordBackend,
)
from chatfilter.security.url_validator import (
    URLValidationError,
    get_allowed_domains,
    validate_url,
)

__all__ = [
    # Credentials
    "SecureCredentialManager",
    "CredentialStorageError",
    "CredentialNotFoundError",
    # Key Management
    "KeyManager",
    "KeyManagerError",
    "KeyNotFoundError",
    "KeyBackend",
    "KeyringBackend",
    "PasswordBackend",
    "EnvironmentBackend",
    "MachineKeyBackend",
    # URL Validation
    "URLValidationError",
    "validate_url",
    "get_allowed_domains",
]
