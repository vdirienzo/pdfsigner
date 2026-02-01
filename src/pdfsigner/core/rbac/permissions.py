"""
permissions.py - Permission definitions and role mappings

Defines granular permissions and maps them to user roles for RBAC.
HIPAA: §164.308(a)(4) - Information access management
"""

from enum import Enum

from pdfsigner.core.users.user_model import UserRole


class Permission(str, Enum):
    """
    Fine-grained permissions for system operations.

    Each permission represents a specific capability that can be
    granted to users through their assigned role.
    """

    # Document viewing and validation
    VIEW = "view"  # View documents
    VALIDATE = "validate"  # Validate signatures

    # Document operations
    SIGN = "sign"  # Sign documents
    ENCRYPT = "encrypt"  # Encrypt documents
    DECRYPT = "decrypt"  # Decrypt documents (restricted)
    EXPORT = "export"  # Export/download documents

    # Administrative operations
    ADMIN_USERS = "admin.users"  # Manage user accounts
    ADMIN_CONFIG = "admin.config"  # Modify system configuration

    # Audit and compliance
    AUDIT_VIEW = "audit.view"  # View audit logs

    # Emergency access
    EMERGENCY_ACCESS = "emergency.access"  # Emergency break-glass access


# Role to permissions mapping
ROLE_PERMISSIONS: dict[UserRole, set[Permission]] = {
    # Viewers can only view and validate documents
    UserRole.VIEWER: {
        Permission.VIEW,
        Permission.VALIDATE,
    },
    # Signers can view, validate, sign, and encrypt
    UserRole.SIGNER: {
        Permission.VIEW,
        Permission.SIGN,
        Permission.VALIDATE,
        Permission.ENCRYPT,
        Permission.EXPORT,
    },
    # Auditors can view documents and audit logs
    UserRole.AUDITOR: {
        Permission.VIEW,
        Permission.VALIDATE,
        Permission.AUDIT_VIEW,
    },
    # Admins have all permissions except emergency access
    UserRole.ADMIN: {
        Permission.VIEW,
        Permission.SIGN,
        Permission.VALIDATE,
        Permission.ENCRYPT,
        Permission.EXPORT,
        Permission.ADMIN_USERS,
        Permission.ADMIN_CONFIG,
        Permission.AUDIT_VIEW,
    },
    # Emergency role has limited but critical permissions
    UserRole.EMERGENCY: {
        Permission.VIEW,
        Permission.DECRYPT,
        Permission.EMERGENCY_ACCESS,
    },
}
