"""
API route handlers.

This package contains FastAPI routers for:
- /auth - Authentication endpoints
- /certificates - Certificate management endpoints
- /sign - PDF signing endpoints
- /validate - PDF validation endpoints
- /phi - PHI scanning endpoints
- /users - User management endpoints
- /sessions - Session management endpoints
- /emergency - Emergency access endpoints
- /compliance - HIPAA compliance monitoring endpoints
- /evidence - SOC 2 evidence collection endpoints
- /retention - Data retention policy endpoints
- /gdpr - GDPR compliance (data portability, erasure) endpoints
- /tokens - Token management endpoints
- /templates - Signature template endpoints
- /mfa - Multi-factor authentication endpoints
- /backup - Backup and recovery endpoints
- /breach - Data breach notification endpoints (GDPR/HIPAA)
- /vulnerabilities - Vulnerability scanning endpoints
"""

from pdfsigner.api.routes.api_keys import router as api_keys_router
from pdfsigner.api.routes.auth import router as auth_router
from pdfsigner.api.routes.backup import router as backup_router
from pdfsigner.api.routes.breach import router as breach_router
from pdfsigner.api.routes.certificates import router as certificates_router
from pdfsigner.api.routes.compliance import router as compliance_router
from pdfsigner.api.routes.consent import router as consent_router
from pdfsigner.api.routes.emergency import router as emergency_router
from pdfsigner.api.routes.evidence import router as evidence_router
from pdfsigner.api.routes.gdpr import router as gdpr_router
from pdfsigner.api.routes.mfa import router as mfa_router
from pdfsigner.api.routes.phi import router as phi_router
from pdfsigner.api.routes.redact import router as redact_router
from pdfsigner.api.routes.retention import router as retention_router
from pdfsigner.api.routes.sessions import router as sessions_router
from pdfsigner.api.routes.sign import router as sign_router
from pdfsigner.api.routes.users import router as users_router
from pdfsigner.api.routes.validate import router as validate_router
from pdfsigner.api.routes.vulnerabilities import router as vulnerabilities_router

__all__ = [
    "api_keys_router",
    "auth_router",
    "backup_router",
    "breach_router",
    "certificates_router",
    "compliance_router",
    "consent_router",
    "emergency_router",
    "evidence_router",
    "gdpr_router",
    "mfa_router",
    "phi_router",
    "redact_router",
    "retention_router",
    "sessions_router",
    "sign_router",
    "users_router",
    "validate_router",
    "vulnerabilities_router",
]
