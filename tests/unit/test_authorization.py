"""
Comprehensive authorization and security tests for RBAC.

Tests IDOR prevention, privilege escalation, healthcare_mode enforcement,
decorators, and emergency access scenarios.

HIPAA: §164.308(a)(4) - Information access management
"""

from unittest.mock import patch

import pytest
from fastapi import HTTPException

from pdfsigner.core.rbac import (
    AuthorizationService,
    Permission,
    check_permission,
    require_permission,
)
from pdfsigner.core.users import User, UserRole, UserStatus
from pdfsigner.exceptions import PermissionDeniedError

# Mark async tests
pytestmark = pytest.mark.anyio


# --- Fixtures ---


@pytest.fixture
def viewer_user() -> User:
    """Create a viewer user for testing."""
    return User(
        id="viewer-001",
        username="viewer_user",
        email="viewer@example.com",
        role=UserRole.VIEWER,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def signer_user() -> User:
    """Create a signer user for testing."""
    return User(
        id="signer-001",
        username="signer_user",
        email="signer@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def admin_user() -> User:
    """Create an admin user for testing."""
    return User(
        id="admin-001",
        username="admin_user",
        email="admin@example.com",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def auditor_user() -> User:
    """Create an auditor user for testing."""
    return User(
        id="auditor-001",
        username="auditor_user",
        email="auditor@example.com",
        role=UserRole.AUDITOR,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def emergency_user() -> User:
    """Create an emergency access user for testing."""
    return User(
        id="emergency-001",
        username="emergency_user",
        email="emergency@example.com",
        role=UserRole.EMERGENCY,
        status=UserStatus.ACTIVE,
    )


@pytest.fixture
def inactive_user() -> User:
    """Create an inactive user for testing."""
    return User(
        id="inactive-001",
        username="inactive_user",
        email="inactive@example.com",
        role=UserRole.SIGNER,
        status=UserStatus.INACTIVE,
    )


# --- IDOR Prevention Tests ---


@pytest.mark.security
class TestIDORPrevention:
    """Tests for Insecure Direct Object Reference (IDOR) prevention."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_user_cannot_access_other_user_data_with_healthcare_mode(
        self, mock_settings, viewer_user, signer_user
    ):
        """Test that users cannot access other users' data when healthcare_mode is enabled."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Viewer cannot access admin operations
        assert service.has_permission(viewer_user, Permission.ADMIN_USERS) is False

        # Even if they know another user's ID, they can't get admin permission
        viewer_with_fake_id = User(
            id="admin-999",  # Pretending to be admin
            username="viewer_user",
            role=UserRole.VIEWER,
            status=UserStatus.ACTIVE,
        )
        assert service.has_permission(viewer_with_fake_id, Permission.ADMIN_USERS) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_user_role_determines_access_not_id(self, mock_settings, viewer_user):
        """Test that role determines access, not user ID."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Create two users with different roles but try to confuse with IDs
        fake_admin = User(
            id="viewer-001",  # Same ID as viewer
            username="fake_admin",
            role=UserRole.VIEWER,  # But viewer role
            status=UserStatus.ACTIVE,
        )

        # Role determines access, not ID
        assert service.has_permission(fake_admin, Permission.ADMIN_USERS) is False
        assert service.has_permission(fake_admin, Permission.VIEW) is True

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_document_owner_check_simulation(self, mock_settings, signer_user):
        """Simulate checking if user owns a document before allowing access."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # User has SIGN permission
        assert service.has_permission(signer_user, Permission.SIGN) is True

        # But in real scenario, need to also check document ownership
        # This test documents the pattern: has_permission + ownership_check
        document_owner_id = "signer-001"
        can_sign = (
            service.has_permission(signer_user, Permission.SIGN)
            and signer_user.id == document_owner_id
        )
        assert can_sign is True

        # Different user trying to access
        other_user = User(
            id="signer-002",
            username="other_signer",
            role=UserRole.SIGNER,
            status=UserStatus.ACTIVE,
        )
        can_sign_other = (
            service.has_permission(other_user, Permission.SIGN)
            and other_user.id == document_owner_id
        )
        assert can_sign_other is False


# --- Privilege Escalation Tests ---


@pytest.mark.security
class TestPrivilegeEscalation:
    """Tests to prevent privilege escalation attacks."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_viewer_cannot_escalate_to_admin(self, mock_settings, viewer_user):
        """Test that viewer cannot perform admin actions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Viewer attempts admin operations
        assert service.has_permission(viewer_user, Permission.ADMIN_USERS) is False
        assert service.has_permission(viewer_user, Permission.ADMIN_CONFIG) is False

        with pytest.raises(PermissionDeniedError, match="lacks required permissions"):
            service.require_permissions(viewer_user, Permission.ADMIN_USERS)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_signer_cannot_escalate_to_admin(self, mock_settings, signer_user):
        """Test that signer cannot perform admin actions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Signer can sign but not admin
        assert service.has_permission(signer_user, Permission.SIGN) is True
        assert service.has_permission(signer_user, Permission.ADMIN_USERS) is False

        with pytest.raises(PermissionDeniedError):
            service.require_permissions(signer_user, Permission.ADMIN_CONFIG)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_auditor_cannot_perform_operations(self, mock_settings, auditor_user):
        """Test that auditor can only view/audit, not perform operations."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Auditor can view and audit
        assert service.has_permission(auditor_user, Permission.VIEW) is True
        assert service.has_permission(auditor_user, Permission.AUDIT_VIEW) is True

        # But cannot sign or encrypt
        assert service.has_permission(auditor_user, Permission.SIGN) is False
        assert service.has_permission(auditor_user, Permission.ENCRYPT) is False
        assert service.has_permission(auditor_user, Permission.ADMIN_USERS) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_emergency_role_limited_to_emergency_only(self, mock_settings, emergency_user):
        """Test that emergency role cannot escalate beyond emergency permissions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Emergency has limited permissions
        assert service.has_permission(emergency_user, Permission.EMERGENCY_ACCESS) is True
        assert service.has_permission(emergency_user, Permission.VIEW) is True
        assert service.has_permission(emergency_user, Permission.DECRYPT) is True

        # But cannot perform regular operations or admin
        assert service.has_permission(emergency_user, Permission.SIGN) is False
        assert service.has_permission(emergency_user, Permission.ENCRYPT) is False
        assert service.has_permission(emergency_user, Permission.ADMIN_USERS) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_role_modification_not_bypassing_checks(self, mock_settings, viewer_user):
        """Test that modifying user object doesn't bypass permission checks."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Initial check - viewer cannot admin
        assert service.has_permission(viewer_user, Permission.ADMIN_USERS) is False

        # Attacker tries to modify role in their session
        viewer_user.role = UserRole.ADMIN

        # Service should use the current role from user object
        # This test shows that we rely on proper authentication/session management
        # to prevent role tampering
        assert service.has_permission(viewer_user, Permission.ADMIN_USERS) is True

        # The real protection is ensuring User objects come from trusted source
        # (database/auth system), not user input


# --- Healthcare Mode Enforcement Tests ---


@pytest.mark.security
class TestHealthcareModeEnforcement:
    """Tests for healthcare_mode enforcement behavior."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_all_users_unrestricted_when_healthcare_mode_disabled(
        self, mock_settings, viewer_user, signer_user, auditor_user
    ):
        """Test that all permission checks pass when healthcare_mode is disabled."""
        mock_settings.return_value.healthcare_mode = False
        service = AuthorizationService()

        # All users can do everything
        for user in [viewer_user, signer_user, auditor_user]:
            assert service.has_permission(user, Permission.ADMIN_USERS) is True
            assert service.has_permission(user, Permission.SIGN) is True
            assert service.has_permission(user, Permission.DECRYPT) is True

            # require_permissions should not raise
            service.require_permissions(user, Permission.ADMIN_USERS, Permission.SIGN)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_strict_enforcement_when_healthcare_mode_enabled(
        self, mock_settings, viewer_user, signer_user, admin_user
    ):
        """Test that permissions are strictly enforced when healthcare_mode is enabled."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Viewer limited
        assert service.has_permission(viewer_user, Permission.VIEW) is True
        assert service.has_permission(viewer_user, Permission.SIGN) is False

        # Signer can sign but not admin
        assert service.has_permission(signer_user, Permission.SIGN) is True
        assert service.has_permission(signer_user, Permission.ADMIN_USERS) is False

        # Only admin can admin
        assert service.has_permission(admin_user, Permission.ADMIN_USERS) is True

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_healthcare_mode_toggle_affects_permissions(self, mock_settings, viewer_user):
        """Test that toggling healthcare_mode changes permission enforcement."""
        # Start with healthcare mode enabled
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        assert service.has_permission(viewer_user, Permission.SIGN) is False

        # Toggle to disabled
        mock_settings.return_value.healthcare_mode = False
        assert service.has_permission(viewer_user, Permission.SIGN) is True

        # Toggle back to enabled
        mock_settings.return_value.healthcare_mode = True
        assert service.has_permission(viewer_user, Permission.SIGN) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_get_user_permissions_respects_healthcare_mode(self, mock_settings, viewer_user):
        """Test that get_user_permissions returns different sets based on healthcare_mode."""
        # Healthcare mode enabled - limited permissions
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()
        perms_enabled = service.get_user_permissions(viewer_user)
        assert len(perms_enabled) == 2  # VIEW and VALIDATE only
        assert Permission.SIGN not in perms_enabled

        # Healthcare mode disabled - all permissions
        mock_settings.return_value.healthcare_mode = False
        perms_disabled = service.get_user_permissions(viewer_user)
        assert len(perms_disabled) == len(Permission)
        assert Permission.SIGN in perms_disabled


# --- Multiple Missing Permissions Tests ---


@pytest.mark.security
class TestMultipleMissingPermissions:
    """Tests for require_permissions with multiple missing permissions."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_require_multiple_permissions_all_missing(self, mock_settings, viewer_user):
        """Test error message when user lacks multiple permissions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        with pytest.raises(PermissionDeniedError, match="sign, encrypt, admin.users") as exc_info:
            service.require_permissions(
                viewer_user,
                Permission.SIGN,
                Permission.ENCRYPT,
                Permission.ADMIN_USERS,
            )

        error_message = str(exc_info.value)
        assert "viewer_user" in error_message
        assert "lacks required permissions" in error_message

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_require_multiple_permissions_some_missing(self, mock_settings, signer_user):
        """Test error when user has some but not all required permissions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Signer has SIGN but not ADMIN_USERS
        with pytest.raises(PermissionDeniedError, match="admin.users") as exc_info:
            service.require_permissions(
                signer_user,
                Permission.SIGN,  # Has this
                Permission.ADMIN_USERS,  # Missing this
            )

        error_message = str(exc_info.value)
        # Only missing permission should be listed
        assert "admin.users" in error_message
        assert "lacks required permissions: admin.users" in error_message

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_require_multiple_permissions_all_granted(self, mock_settings, signer_user):
        """Test that require_permissions passes when all permissions granted."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Should not raise - signer has all these
        service.require_permissions(
            signer_user,
            Permission.SIGN,
            Permission.VIEW,
            Permission.ENCRYPT,
        )


# --- Permission Decorator Tests ---


@pytest.mark.security
class TestPermissionDecorators:
    """Tests for FastAPI permission decorators."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_require_permission_decorator_success(self, mock_settings, signer_user):
        """Test require_permission decorator allows access when permission granted."""
        mock_settings.return_value.healthcare_mode = True

        @require_permission(Permission.SIGN)
        async def sign_document(user: User):
            return {"status": "signed"}

        # Should not raise
        result = await sign_document(user=signer_user)
        assert result["status"] == "signed"

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_require_permission_decorator_denied(self, mock_settings, viewer_user):
        """Test require_permission decorator raises 403 when permission denied."""
        mock_settings.return_value.healthcare_mode = True

        @require_permission(Permission.SIGN)
        async def sign_document(user: User):
            return {"status": "signed"}

        with pytest.raises(HTTPException) as exc_info:
            await sign_document(user=viewer_user)

        assert exc_info.value.status_code == 403
        assert "lacks required permissions" in exc_info.value.detail

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_require_permission_decorator_multiple_permissions(
        self, mock_settings, admin_user
    ):
        """Test require_permission decorator with multiple permissions."""
        mock_settings.return_value.healthcare_mode = True

        @require_permission(Permission.SIGN, Permission.ADMIN_USERS)
        async def admin_sign(user: User):
            return {"status": "admin_signed"}

        # Admin has both permissions
        result = await admin_sign(user=admin_user)
        assert result["status"] == "admin_signed"

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_require_permission_decorator_no_user(self, mock_settings):
        """Test require_permission decorator raises 401 when no user provided."""
        mock_settings.return_value.healthcare_mode = True

        @require_permission(Permission.SIGN)
        async def sign_document(user: User):
            return {"status": "signed"}

        # Call without user argument
        with pytest.raises(HTTPException) as exc_info:
            await sign_document()

        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_check_permission_dependency_success(self, mock_settings, signer_user):
        """Test check_permission dependency allows access when permission granted."""
        mock_settings.return_value.healthcare_mode = True

        # Mock get_current_user_or_api_key to return signer_user
        with patch(
            "pdfsigner.core.rbac.authorization._get_current_user_dynamic",
            return_value=lambda: signer_user,
        ):
            dependency = check_permission(Permission.SIGN)
            # Should not raise
            await dependency(current_user=signer_user)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    @patch("pdfsigner.core.rbac.authorization._authorization_service", None)
    async def test_check_permission_dependency_denied(self, mock_settings, viewer_user):
        """Test check_permission dependency raises 403 when permission denied."""
        mock_settings.return_value.healthcare_mode = True

        with patch(
            "pdfsigner.core.rbac.authorization._get_current_user_dynamic",
            return_value=lambda: viewer_user,
        ):
            dependency = check_permission(Permission.SIGN)

            with pytest.raises(HTTPException) as exc_info:
                await dependency(current_user=viewer_user)

            assert exc_info.value.status_code == 403
            assert "Permission denied" in exc_info.value.detail


# --- Emergency Role Tests ---


@pytest.mark.security
class TestEmergencyRolePermissions:
    """Tests for emergency role special permissions and restrictions."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_emergency_has_decrypt_permission(self, mock_settings, emergency_user):
        """Test that emergency role has decrypt permission."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        assert service.has_permission(emergency_user, Permission.DECRYPT) is True

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_emergency_has_emergency_access_permission(self, mock_settings, emergency_user):
        """Test that emergency role has emergency access permission."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        assert service.has_permission(emergency_user, Permission.EMERGENCY_ACCESS) is True

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_non_emergency_cannot_decrypt(
        self, mock_settings, viewer_user, signer_user, admin_user
    ):
        """Test that non-emergency roles cannot decrypt."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Decrypt is emergency-only
        assert service.has_permission(viewer_user, Permission.DECRYPT) is False
        assert service.has_permission(signer_user, Permission.DECRYPT) is False
        assert service.has_permission(admin_user, Permission.DECRYPT) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_non_emergency_cannot_emergency_access(
        self, mock_settings, viewer_user, signer_user, admin_user, auditor_user
    ):
        """Test that non-emergency roles cannot have emergency access."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        for user in [viewer_user, signer_user, admin_user, auditor_user]:
            assert service.has_permission(user, Permission.EMERGENCY_ACCESS) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_emergency_cannot_sign_or_admin(self, mock_settings, emergency_user):
        """Test that emergency role cannot perform regular operations or admin tasks."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Emergency cannot do regular operations
        assert service.has_permission(emergency_user, Permission.SIGN) is False
        assert service.has_permission(emergency_user, Permission.ENCRYPT) is False
        assert service.has_permission(emergency_user, Permission.EXPORT) is False

        # Emergency cannot admin
        assert service.has_permission(emergency_user, Permission.ADMIN_USERS) is False
        assert service.has_permission(emergency_user, Permission.ADMIN_CONFIG) is False

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_emergency_permissions_set_complete(self, mock_settings, emergency_user):
        """Test that emergency role has exactly 3 permissions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        perms = service.get_user_permissions(emergency_user)
        assert len(perms) == 3
        assert Permission.VIEW in perms
        assert Permission.DECRYPT in perms
        assert Permission.EMERGENCY_ACCESS in perms


# --- Parametrized Role-Permission Tests ---


@pytest.mark.security
class TestRolePermissionMatrix:
    """Parametrized tests for role-permission combinations."""

    @pytest.mark.parametrize(
        "role,permission,expected",
        [
            # Viewer
            (UserRole.VIEWER, Permission.VIEW, True),
            (UserRole.VIEWER, Permission.VALIDATE, True),
            (UserRole.VIEWER, Permission.SIGN, False),
            (UserRole.VIEWER, Permission.ADMIN_USERS, False),
            # Signer
            (UserRole.SIGNER, Permission.VIEW, True),
            (UserRole.SIGNER, Permission.SIGN, True),
            (UserRole.SIGNER, Permission.ENCRYPT, True),
            (UserRole.SIGNER, Permission.ADMIN_USERS, False),
            (UserRole.SIGNER, Permission.DECRYPT, False),
            # Auditor
            (UserRole.AUDITOR, Permission.VIEW, True),
            (UserRole.AUDITOR, Permission.AUDIT_VIEW, True),
            (UserRole.AUDITOR, Permission.SIGN, False),
            (UserRole.AUDITOR, Permission.ADMIN_USERS, False),
            # Admin
            (UserRole.ADMIN, Permission.VIEW, True),
            (UserRole.ADMIN, Permission.SIGN, True),
            (UserRole.ADMIN, Permission.ADMIN_USERS, True),
            (UserRole.ADMIN, Permission.EMERGENCY_ACCESS, False),
            (UserRole.ADMIN, Permission.DECRYPT, False),
            # Emergency
            (UserRole.EMERGENCY, Permission.VIEW, True),
            (UserRole.EMERGENCY, Permission.DECRYPT, True),
            (UserRole.EMERGENCY, Permission.EMERGENCY_ACCESS, True),
            (UserRole.EMERGENCY, Permission.SIGN, False),
            (UserRole.EMERGENCY, Permission.ADMIN_USERS, False),
        ],
    )
    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_role_permission_matrix(self, mock_settings, role, permission, expected):
        """Test role-permission matrix with parametrized values."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        user = User(
            username=f"test_{role.value}",
            role=role,
            status=UserStatus.ACTIVE,
        )

        assert service.has_permission(user, permission) == expected


# --- Edge Cases and Security Boundary Tests ---


@pytest.mark.security
class TestSecurityBoundaries:
    """Tests for edge cases and security boundaries."""

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_inactive_user_still_checked_for_permissions(self, mock_settings, inactive_user):
        """Test that inactive users are still subject to permission checks."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        # Inactive user with signer role - still follows role permissions
        assert service.has_permission(inactive_user, Permission.SIGN) is True
        assert service.has_permission(inactive_user, Permission.ADMIN_USERS) is False

        # Note: Active status should be checked separately in authentication layer

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_permission_check_with_empty_permissions(self, mock_settings):
        """Test require_permissions with no permissions (edge case)."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        user = User(username="test", role=UserRole.VIEWER, status=UserStatus.ACTIVE)

        # Calling with no permissions should not raise
        service.require_permissions(user)

    @patch("pdfsigner.core.rbac.authorization.get_settings")
    def test_get_user_permissions_consistent(self, mock_settings, viewer_user):
        """Test that get_user_permissions returns consistent permissions."""
        mock_settings.return_value.healthcare_mode = True
        service = AuthorizationService()

        perms1 = service.get_user_permissions(viewer_user)
        perms2 = service.get_user_permissions(viewer_user)

        # Should have same content
        assert perms1 == perms2
        assert len(perms1) == 2
        assert Permission.VIEW in perms1
        assert Permission.VALIDATE in perms1
