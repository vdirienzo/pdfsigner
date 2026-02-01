"""
exceptions.py - Custom exceptions for PDFSigner

Author: Homero Thompson del Lago del Terror

Defines the exception hierarchy for error handling
throughout the digital signature system.
"""


class PDFSignerError(Exception):
    """Base exception for all PDFSigner errors."""

    pass


class TokenError(PDFSignerError):
    """Errors related to USB token/NSS."""

    pass


class TokenNotFoundError(TokenError):
    """USB token not detected or unavailable."""

    def __init__(self, message: str = "USB token not detected"):
        super().__init__(message)


class TokenAuthenticationError(TokenError):
    """Authentication error with token (incorrect PIN)."""

    def __init__(self, message: str = "Incorrect PIN or authentication failed"):
        super().__init__(message)


class CertificateError(PDFSignerError):
    """Errors related to certificates."""

    pass


class CertificateNotFoundError(CertificateError):
    """Signing certificate not found on token."""

    def __init__(self, message: str = "Valid signing certificate not found"):
        super().__init__(message)


class CertificateExpiredError(CertificateError):
    """Certificate expired."""

    def __init__(self, cert_name: str, expiry_date: str):
        super().__init__(f"Certificate '{cert_name}' expired on {expiry_date}")


class SigningError(PDFSignerError):
    """Errors during signing process."""

    pass


class PDFError(SigningError):
    """Errors related to PDF file."""

    pass


class PDFProtectedError(PDFError):
    """PDF is protected and cannot be signed."""

    def __init__(self, filename: str):
        super().__init__(f"File '{filename}' is protected against modifications")


class PDFCorruptedError(PDFError):
    """PDF corrupted or invalid."""

    def __init__(self, filename: str):
        super().__init__(f"File '{filename}' is corrupted or not a valid PDF")


class TimestampError(SigningError):
    """Errors with timestamp server (TSA)."""

    pass


class TSAConnectionError(TimestampError):
    """Cannot connect to TSA server."""

    def __init__(self, tsa_url: str):
        super().__init__(f"Cannot connect to timestamp server: {tsa_url}")


class TSAResponseError(TimestampError):
    """Invalid response from TSA server."""

    def __init__(self, message: str = "Invalid response from timestamp server"):
        super().__init__(message)


class ConfigurationError(PDFSignerError):
    """Configuration errors."""

    pass


class NSSConfigError(ConfigurationError):
    """Error in NSS configuration."""

    def __init__(self, nss_path: str):
        super().__init__(f"Invalid NSS database at: {nss_path}")


# --- Encryption Errors ---


class PDFEncryptionError(PDFSignerError):
    """Base error for encryption operations."""

    def __init__(self, message: str = "Encryption operation failed"):
        super().__init__(message)


class PasswordIncorrectError(PDFEncryptionError):
    """Incorrect password provided for decryption."""

    def __init__(self, filename: str = ""):
        msg = f"Incorrect password for '{filename}'" if filename else "Incorrect password"
        super().__init__(msg)


class HIPAAComplianceError(PDFEncryptionError):
    """PDF encryption does not meet HIPAA requirements."""

    def __init__(self, reason: str):
        super().__init__(f"HIPAA compliance error: {reason}")


# --- Session Errors ---


class SessionError(PDFSignerError):
    """Base error for session management."""

    pass


class SessionExpiredError(SessionError):
    """Session has expired and is no longer valid."""

    def __init__(self, session_id: str = ""):
        msg = f"Session {session_id} has expired" if session_id else "Session has expired"
        super().__init__(msg)


class MaxSessionsExceededError(SessionError):
    """User has exceeded maximum concurrent sessions."""

    def __init__(self, max_sessions: int):
        super().__init__(f"Maximum concurrent sessions ({max_sessions}) exceeded")


# --- Emergency Access Errors ---


class EmergencyAccessError(PDFSignerError):
    """Emergency access operation failed."""

    pass


# --- Authorization Errors ---


class PermissionDeniedError(PDFSignerError):
    """User lacks required permission for the requested operation."""

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message)
