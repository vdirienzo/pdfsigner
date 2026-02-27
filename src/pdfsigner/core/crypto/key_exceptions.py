"""
key_exceptions.py - Exception classes for cryptographic key management.

Provides specific exception types for key-related error conditions.
"""


class KeyManagerError(Exception):
    """Base exception for KeyManager errors."""

    pass


class KeyNotFoundError(KeyManagerError):
    """Key not found in storage."""

    pass


class KeyRevokedError(KeyManagerError):
    """Attempted to use a revoked key."""

    pass


class KeyExpiredError(KeyManagerError):
    """Attempted to use an expired key."""

    pass
