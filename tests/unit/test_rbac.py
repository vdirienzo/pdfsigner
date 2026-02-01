"""Tests for RBAC module."""

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from pdfsigner.core.rbac import (
    ROLE_PERMISSIONS,
    AuthorizationService,
    Permission,
    check_permission,
    get_authorization_service,
)
from pdfsigner.core.users import User, UserRole
from pdfsigner.exceptions import PermissionDeniedError

# Mark async tests with anyio
pytestmark = pytest.mark.anyio


class TestPermission:
    """Tests for Permission enum."""

    def test_all_permissions_defined(self):
        """Test all expected permissions exist."""
        assert Permission.VIEW.value == "view"
        assert Permission.SIGN.value == "sign"
        assert Permission.VALIDATE.value == "validate"
        assert Permission.ENCRYPT.value == "encrypt"
        assert Permission.DECRYPT.value == "decrypt"
        assert Permission.EXPORT.value == "export"
        assert Permission.ADMIN_USERS.value == "admin.users"
        assert Permission.ADMIN_CONFIG.value == "admin.config"
        assert Permission.AUDIT_VIEW.value == "audit.view"
        assert Permission.EMERGENCY_ACCESS.value == "emergency.access"

    def test_permission_count(self):
        """Test number of permissions."""
        assert len(Permission) == 10


class TestRolePermissions:
    """Tests for ROLE_PERMISSIONS mapping."""

    def test_viewer_permissions(self):
        """Test viewer role has limited permissions."""
        perms = ROLE_PERMISSIONS[UserRole.VIEWER]
        assert Permission.VIEW in perms
        assert Permission.VALIDATE in perms
        assert Permission.SIGN not in perms
        assert len(perms) == 2

    def test_signer_permissions(self):
        """Test signer role has document operation permissions."""
        perms = ROLE_PERMISSIONS[UserRole.SIGNER]
        assert Permission.VIEW in perms
        assert Permission.SIGN in perms
        assert Permission.VALIDATE in perms
        assert Permission.ENCRYPT in perms
        assert Permission.EXPORT in perms
        assert Permission.ADMIN_USERS not in perms
        assert len(perms) == 5

    def test_auditor_permissions(self):
        """Test auditor role has audit permissions."""
        perms = ROLE_PERMISSIONS[UserRole.AUDITOR]
        assert Permission.VIEW in perms
        assert Permission.VALIDATE in perms
        assert Permission.AUDIT_VIEW in perms
        assert Permission.SIGN not in perms
        assert len(perms) == 3

    def test_admin_permissions(self):
        """Test admin role has all permissions except emergency."""
        perms = ROLE_PERMISSIONS[UserRole.ADMIN]
        assert Permission.VIEW in perms
        assert Permission.SIGN in perms
        assert Permission.ADMIN_USERS in perms
        assert Permission.ADMIN_CONFIG in perms
        assert Permission.AUDIT_VIEW in perms
        assert Permission.EMERGENCY_ACCESS not in perms
        assert len(perms) == 8

    def test_emergency_permissions(self):
        """Test emergency role has critical permissions only."""
        perms = ROLE_PERMISSIONS[UserRole.EMERGENCY]
        assert Permission.VIEW in perms
        assert Permission.DECRYPT in perms
        assert Permission.EMERGENCY_ACCESS in perms
        assert Permission.SIGN not in perms
        assert len(perms) == 3

    def test_all_roles_mapped(self):
        """Test all user roles have permission mappings."""
        assert len(ROLE_PERMISSIONS) == 5
        for role in UserRole:
            assert role in ROLE_PERMISSIONS


class TestAuthorizationService:
    """Tests for AuthorizationService."""

    def test_initialization(self):
        """Test service initializes correctly."""
        service = AuthorizationService()
        assert service is not None

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_has_permission_with_healthcare_mode_disabled(self, mock_settings):
        """Test all permissions granted when healthcare_mode is False."""
        mock_settings.return_value.healthcare_mode = False
        service = AuthorizationService()

        user = User(username="test", role=UserRole.VIEWER)
        # Viewer normally can't sign, but with healthcare_mode=False they can
        assert service.has_permission(user, Permission.SIGN) is True
        assert service.has_permission(user, Permission.ADMIN_USERS) is True

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_has_permission_with_healthcare_mode_enabled(self, mock_settings):
        """Test permissions enforced when healthcare_mode is True."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        viewer = User(username="viewer", role=UserRole.VIEWER)
        signer = User(username="signer", role=UserRole.SIGNER)

        # Viewer can view but not sign
        assert service.has_permission(viewer, Permission.VIEW) is True
        assert service.has_permission(viewer, Permission.SIGN) is False

        # Signer can sign
        assert service.has_permission(signer, Permission.SIGN) is True

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_require_permissions_passes_when_granted(self, mock_settings):
        """Test require_permissions passes when user has permissions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        signer = User(username="signer", role=UserRole.SIGNER)
        # Should not raise
        service.require_permissions(signer, Permission.SIGN, Permission.VIEW)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_require_permissions_raises_when_denied(self, mock_settings):
        """Test require_permissions raises PermissionDeniedError when lacking permission."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        viewer = User(username="viewer", role=UserRole.VIEWER)
        with pytest.raises(PermissionDeniedError, match="lacks required permissions"):
            service.require_permissions(viewer, Permission.SIGN)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_require_permissions_with_healthcare_mode_disabled(self, mock_settings):
        """Test require_permissions allows all when healthcare_mode is False."""
        mock_settings.return_value.healthcare_mode = False
        service = AuthorizationService()

        viewer = User(username="viewer", role=UserRole.VIEWER)
        # Should not raise even though viewer lacks admin permission
        service.require_permissions(viewer, Permission.ADMIN_USERS)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_get_user_permissions(self, mock_settings):
        """Test get_user_permissions returns correct permission set."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        signer = User(username="signer", role=UserRole.SIGNER)
        perms = service.get_user_permissions(signer)

        assert Permission.SIGN in perms
        assert Permission.VIEW in perms
        assert Permission.ADMIN_USERS not in perms

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_get_user_permissions_with_healthcare_mode_disabled(self, mock_settings):
        """Test get_user_permissions returns all permissions when healthcare_mode is False."""
        mock_settings.return_value.healthcare_mode = False
        service = AuthorizationService()

        viewer = User(username="viewer", role=UserRole.VIEWER)
        perms = service.get_user_permissions(viewer)

        # Should return all permissions
        assert len(perms) == len(Permission)


class TestSingleton:
    """Tests for singleton pattern."""

    def test_get_authorization_service_returns_same_instance(self):
        """Test get_authorization_service returns singleton."""
        service1 = get_authorization_service()
        service2 = get_authorization_service()
        assert service1 is service2


class TestFastAPIDependencies:
    """Tests for FastAPI dependencies."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_check_permission_allows_when_granted(self, mock_settings):
        """Test check_permission allows request when permission granted."""
        mock_settings.return_value.healthcare_mode = True

        signer = User(username="signer", role=UserRole.SIGNER)
        dependency = check_permission(Permission.SIGN)

        # Should not raise
        await dependency(signer)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_check_permission_raises_403_when_denied(self, mock_settings):
        """Test check_permission raises HTTPException 403 when permission denied."""
        mock_settings.return_value.healthcare_mode = True

        viewer = User(username="viewer", role=UserRole.VIEWER)
        dependency = check_permission(Permission.SIGN)

        with pytest.raises(HTTPException) as exc_info:
            await dependency(viewer)

        assert exc_info.value.status_code == 403
        assert "Permission denied" in exc_info.value.detail
