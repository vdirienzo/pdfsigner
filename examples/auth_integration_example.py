"""
integration_example.py - Password policy integration examples

This module demonstrates how to integrate the password policy engine
with PDFSigner's user management and audit systems.

NOT FOR PRODUCTION - This is example code only.
"""

from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.audit import AuditEvent, AuditEventType, get_audit_logger
from pdfsigner.core.auth import PasswordPolicy, PasswordValidator, get_password_validator
from pdfsigner.core.users import User, UserRepository, get_user_repository


class PasswordService:
    """
    Example service integrating password validation with user management.

    This demonstrates how to:
    1. Validate passwords against policy
    2. Store password hashes
    3. Track password history
    4. Emit audit events
    5. Handle password expiration
    """

    def __init__(
        self,
        user_repo: UserRepository | None = None,
        validator: PasswordValidator | None = None,
    ):
        """
        Initialize password service.

        Args:
            user_repo: User repository (default: singleton)
            validator: Password validator (default: singleton)
        """
        self.user_repo = user_repo or get_user_repository()
        self.validator = validator or get_password_validator()
        self.audit_logger = get_audit_logger()

    def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        session_id: str | None = None,
    ) -> tuple[bool, list[str]]:
        """
        Change user password with validation and audit trail.

        Args:
            user_id: User ID
            old_password: Current password
            new_password: New password
            session_id: Session ID for audit trail

        Returns:
            Tuple of (success, errors)
        """
        errors = []

        # Get user
        user = self.user_repo.get_user_by_id(user_id)
        if not user:
            errors.append("User not found")
            return False, errors

        # Verify old password (placeholder - in production, verify against stored hash)
        # if not self.validator.verify_password(old_password, user.password_hash):
        #     errors.append("Current password is incorrect")
        #     self._log_password_change_failure(user, session_id, "invalid_old_password")
        #     return False, errors

        # Validate new password
        validation_result = self.validator.validate(new_password, user_id=user_id)
        if not validation_result.is_valid:
            self._log_password_change_failure(user, session_id, "policy_violation")
            return False, validation_result.errors

        # Hash new password
        password_hash = self.validator.hash_password(new_password)

        # Add to password history
        self.validator.history_repo.add_password(user_id, password_hash)

        # Update user record (in production, store password_hash)
        user.password_changed_at = datetime.now(UTC)
        self.user_repo.update_user(user)

        # Log success
        self._log_password_change_success(user, session_id)

        logger.info(f"Password changed successfully for user: {user.username}")
        return True, []

    def validate_password_strength(self, password: str) -> dict:
        """
        Validate password and return detailed feedback.

        Args:
            password: Password to validate

        Returns:
            Dictionary with validation results
        """
        result = self.validator.validate(password, user_id=None)

        return {
            "is_valid": result.is_valid,
            "strength_score": result.strength_score,
            "strength_label": self._get_strength_label(result.strength_score),
            "errors": result.errors,
            "suggestions": result.suggestions,
        }

    def check_password_expired(self, user: User) -> bool:
        """
        Check if user's password has expired.

        Args:
            user: User to check

        Returns:
            True if password is expired
        """
        if not user.password_changed_at:
            return True  # Never set, consider expired

        policy = self.validator.policy
        if policy.max_age_days == 0:
            return False  # Never expire

        age_days = (datetime.now(UTC) - user.password_changed_at).days
        return age_days >= policy.max_age_days

    def _get_strength_label(self, score: int) -> str:
        """Get human-readable strength label."""
        if score >= 80:
            return "Very Strong"
        elif score >= 70:
            return "Strong"
        elif score >= 50:
            return "Moderate"
        elif score >= 30:
            return "Weak"
        else:
            return "Very Weak"

    def _log_password_change_success(self, user: User, session_id: str | None) -> None:
        """Log successful password change to audit trail."""
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGE,
            status="SUCCESS",
            user_id=user.id,
            user_cn=user.display_name or user.username,
            session_id=session_id,
            details={
                "action": "password_change",
                "username": user.username,
            },
        )
        self.audit_logger.log_event(event)

    def _log_password_change_failure(self, user: User, session_id: str | None, reason: str) -> None:
        """Log failed password change attempt to audit trail."""
        event = AuditEvent(
            event_type=AuditEventType.CONFIG_CHANGE,
            status="FAILURE",
            user_id=user.id,
            user_cn=user.display_name or user.username,
            session_id=session_id,
            error_message=f"Password change failed: {reason}",
            details={
                "action": "password_change",
                "username": user.username,
                "failure_reason": reason,
            },
        )
        self.audit_logger.log_event(event)


# Example usage
def example_password_change():
    """Example: Change a user's password."""
    service = PasswordService()

    # Simulate password change
    success, errors = service.change_password(
        user_id="user-123",
        old_password="<old-password>",
        new_password="<new-password>",
        session_id="session-456",
    )

    if success:
        print("Password changed successfully")
    else:
        print("Password change failed:")
        for error in errors:
            print(f"  - {error}")


def example_password_validation():
    """Example: Validate password strength."""
    service = PasswordService()

    passwords = [
        "weak",
        "Password123",
        "MyStr0ng!P@ssword",
    ]

    for password in passwords:
        result = service.validate_password_strength(password)
        print(f"\nPassword: {password}")
        print(f"  Valid: {result['is_valid']}")
        print(f"  Strength: {result['strength_label']} ({result['strength_score']}/100)")
        if result["errors"]:
            print("  Errors:")
            for error in result["errors"]:
                print(f"    - {error}")


def example_custom_policy():
    """Example: Use custom password policy."""
    # Create custom policy for high-security environment
    custom_policy = PasswordPolicy(
        min_length=16,
        max_age_days=60,
        history_count=24,
        lockout_threshold=3,
        lockout_duration_minutes=60,
        min_unique_chars=12,
    )

    # Create validator with custom policy
    validator = PasswordValidator(policy=custom_policy)

    # Validate password
    result = validator.validate("MyCustomP@ssw0rd2024!")
    print(f"Valid: {result.is_valid}")
    print(f"Strength: {result.strength_score}/100")


if __name__ == "__main__":
    print("=== Password Change Example ===")
    example_password_change()

    print("\n=== Password Validation Example ===")
    example_password_validation()

    print("\n=== Custom Policy Example ===")
    example_custom_policy()
