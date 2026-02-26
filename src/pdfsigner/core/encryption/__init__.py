"""
Encryption module for PDFSigner.

Provides HIPAA-compliant PDF encryption with AES-256 support.
Supports both password-based and certificate-based encryption.

Usage:
    from pdfsigner.core.encryption import (
        PDFEncryptor,
        EncryptionConfig,
        EncryptionMethod,
        PDFPermissions,
    )

    # Encrypt with password
    config = EncryptionConfig(
        method=EncryptionMethod.PASSWORD,
        user_password="<user-password>",
        owner_password="<owner-password>",
    )

    encryptor = PDFEncryptor()
    result = encryptor.encrypt(Path("document.pdf"), config)
"""

from pdfsigner.core.encryption.credential_store import (
    EncryptionCredentialStore,
    get_encryption_credential_store,
)
from pdfsigner.core.encryption.encryption_config import (
    EncryptionConfig,
    EncryptionMethod,
    EncryptionResult,
    EncryptionStrength,
    PDFPermissions,
)
from pdfsigner.core.encryption.encryption_validator import (
    EncryptionInfo,
    EncryptionValidator,
)
from pdfsigner.core.encryption.password_handler import PasswordEncryptionHandler
from pdfsigner.core.encryption.pdf_encryptor import PDFEncryptor, get_pdf_encryptor

__all__ = [
    # Main classes
    "PDFEncryptor",
    "get_pdf_encryptor",
    # Configuration
    "EncryptionConfig",
    "EncryptionMethod",
    "EncryptionStrength",
    "EncryptionResult",
    "PDFPermissions",
    # Validation
    "EncryptionValidator",
    "EncryptionInfo",
    # Handlers
    "PasswordEncryptionHandler",
    # Credentials
    "EncryptionCredentialStore",
    "get_encryption_credential_store",
]
