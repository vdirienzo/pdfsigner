"""
cert_binding.py - Certificate to user binding

Links X.509 certificates to user accounts for authentication.
HIPAA: §164.312(d) - Person or entity authentication
"""

from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.users.user_model import User, UserRole
from pdfsigner.core.users.user_repository import UserRepository, get_user_repository


class CertificateBindingService:
    """
    Service for binding certificates to users.

    Manages the relationship between X.509 certificates (from PKCS#11 tokens)
    and user accounts in the system.
    """

    def __init__(self, repository: UserRepository | None = None):
        """
        Initialize binding service.

        Args:
            repository: User repository instance
        """
        self._repository = repository

    @property
    def repository(self) -> UserRepository:
        """Lazy-load repository."""
        if self._repository is None:
            self._repository = get_user_repository()
        return self._repository

    def get_user_by_certificate(
        self,
        serial: str,
        issuer: str,
    ) -> User | None:
        """
        Get user associated with a certificate.

        Args:
            serial: Certificate serial number (hex)
            issuer: Certificate issuer DN

        Returns:
            User if found, None otherwise
        """
        return self.repository.get_user_by_certificate(serial, issuer)

    def bind_certificate_to_user(
        self,
        user_id: str,
        serial: str,
        issuer: str,
        common_name: str,
    ) -> User | None:
        """
        Bind a certificate to an existing user.

        Args:
            user_id: User ID to bind certificate to
            serial: Certificate serial number
            issuer: Certificate issuer DN
            common_name: Certificate common name

        Returns:
            Updated user, or None if user not found
        """
        user = self.repository.get_user_by_id(user_id)
        if not user:
            logger.warning(f"Cannot bind certificate: user {user_id} not found")
            return None

        # Check if certificate is already bound to another user
        existing = self.get_user_by_certificate(serial, issuer)
        if existing and existing.id != user_id:
            logger.warning(f"Certificate already bound to user {existing.username}")
            return None

        # Update user with certificate info
        user.certificate_serial = serial
        user.certificate_issuer = issuer
        user.certificate_cn = common_name
        user.updated_at = datetime.now(UTC)

        self.repository.update_user(user)
        logger.info(f"Bound certificate to user {user.username}")

        return user

    def unbind_certificate(self, user_id: str) -> bool:
        """
        Remove certificate binding from user.

        Args:
            user_id: User ID to unbind

        Returns:
            True if successful
        """
        user = self.repository.get_user_by_id(user_id)
        if not user:
            return False

        user.certificate_serial = None
        user.certificate_issuer = None
        user.certificate_cn = None
        user.updated_at = datetime.now(UTC)

        self.repository.update_user(user)
        logger.info(f"Unbound certificate from user {user.username}")

        return True

    def get_or_create_user_for_certificate(
        self,
        serial: str,
        issuer: str,
        common_name: str,
        email: str | None = None,
        auto_create: bool = True,
    ) -> User | None:
        """
        Get existing user for certificate, or create new one.

        This is the main entry point for certificate-based authentication.
        If no user exists and auto_create is True, creates a new user
        automatically.

        Args:
            serial: Certificate serial number
            issuer: Certificate issuer DN
            common_name: Certificate common name
            email: Optional email from certificate
            auto_create: Whether to create user if not exists

        Returns:
            User object (existing or newly created)
        """
        # Try to find existing user
        user = self.get_user_by_certificate(serial, issuer)
        if user:
            logger.debug(f"Found existing user for certificate: {user.username}")
            return user

        if not auto_create:
            logger.debug(f"No user found for certificate CN={common_name}, auto_create=False")
            return None

        # Create new user from certificate
        logger.info(f"Creating new user for certificate: {common_name}")

        # Generate username from CN
        base_username = common_name.lower().replace(" ", ".").replace(",", "")
        username = self._generate_unique_username(base_username)

        user = User(
            username=username,
            display_name=common_name,
            email=email or "",
            role=UserRole.SIGNER,  # Default role for certificate users
            certificate_serial=serial,
            certificate_issuer=issuer,
            certificate_cn=common_name,
        )

        try:
            created_user = self.repository.create_user(user)
            logger.info(
                f"Created user from certificate: {created_user.username} (id={created_user.id})"
            )
            return created_user
        except ValueError as e:
            logger.error(f"Failed to create user: {e}")
            return None

    def _generate_unique_username(self, base: str) -> str:
        """Generate unique username by adding suffix if needed."""
        username = base
        suffix = 0

        while self.repository.get_user_by_username(username) is not None:
            suffix += 1
            username = f"{base}{suffix}"

        return username

    def record_login_for_certificate(
        self,
        serial: str,
        issuer: str,
        success: bool,
    ) -> User | None:
        """
        Record login attempt for certificate user.

        Args:
            serial: Certificate serial
            issuer: Certificate issuer
            success: Whether login succeeded

        Returns:
            Updated user if found
        """
        user = self.get_user_by_certificate(serial, issuer)
        if not user:
            return None

        user.record_login(success)
        self.repository.update_user(user)

        return user


# Singleton
_binding_service: CertificateBindingService | None = None


def get_certificate_binding_service() -> CertificateBindingService:
    """Get singleton binding service."""
    global _binding_service
    if _binding_service is None:
        _binding_service = CertificateBindingService()
    return _binding_service
