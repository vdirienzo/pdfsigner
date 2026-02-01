"""
Users module for PDFSigner.

Provides user management and certificate binding for HIPAA compliance.
Implements unique user identification (§164.312(a)(2)(i)).

Usage:
    from pdfsigner.core.users import (
        User,
        UserRole,
        UserRepository,
        get_user_repository,
        CertificateBindingService,
        get_certificate_binding_service,
    )

    # Get or create user from certificate
    binding = get_certificate_binding_service()
    user = binding.get_or_create_user_for_certificate(
        serial="123ABC",
        issuer="CN=MyCA",
        common_name="John Doe",
    )
"""

from pdfsigner.core.users.api_key_repository import (
    APIKey,
    APIKeyRepository,
    get_api_key_repository,
)
from pdfsigner.core.users.cert_binding import (
    CertificateBindingService,
    get_certificate_binding_service,
)
from pdfsigner.core.users.user_model import (
    Department,
    User,
    UserRole,
    UserStatus,
)
from pdfsigner.core.users.user_repository import (
    UserRepository,
    get_user_repository,
)

__all__ = [
    # Models
    "User",
    "UserRole",
    "UserStatus",
    "Department",
    # Repository
    "UserRepository",
    "get_user_repository",
    # Certificate binding
    "CertificateBindingService",
    "get_certificate_binding_service",
    # API Keys
    "APIKey",
    "APIKeyRepository",
    "get_api_key_repository",
]
