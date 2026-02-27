"""
mfa_verification.py - MFA verification and secret retrieval

Handles TOTP code verification, backup code verification,
and encrypted secret retrieval.
"""

import base64
import sqlite3
from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEventType
from pdfsigner.core.audit.helpers import emit_audit_event
from pdfsigner.core.auth.mfa.backup_codes import BackupCodeManager
from pdfsigner.core.auth.mfa.totp_provider import TOTPProvider


class MFAVerificationService:
    """
    Handles MFA verification operations.

    Responsible for:
    - TOTP code verification
    - Backup code verification
    - MFA activation after enrollment
    - Encrypted secret retrieval
    """

    def __init__(
        self,
        totp_provider: TOTPProvider,
        backup_manager: BackupCodeManager,
        get_connection: "callable[[], sqlite3.Connection]",
        get_status: "callable",
    ) -> None:
        """
        Initialize verification service.

        Args:
            totp_provider: TOTP provider for code verification
            backup_manager: Backup code manager
            get_connection: Callable returning a new SQLite connection
            get_status: Callable to check current MFA status for a user
        """
        self._totp_provider = totp_provider
        self._backup_manager = backup_manager
        self._get_connection = get_connection
        self._get_status = get_status

    def verify_and_activate(self, user_id: str, code: str) -> bool:
        """
        Verify TOTP code and activate MFA.

        Args:
            user_id: User ID
            code: TOTP code to verify

        Returns:
            True if code is valid and MFA activated

        Raises:
            ValueError: If user has no pending enrollment
        """
        # Get secret
        secret = self.get_secret(user_id)
        if not secret:
            raise ValueError(f"No MFA enrollment found for user {user_id}")

        # Verify code
        if not self._totp_provider.verify_totp(secret, code):
            emit_audit_event(
                AuditEventType.MFA_VERIFICATION_FAILED,
                details={"reason": "invalid_code"},
                user_id=user_id,
                status="FAILURE",
            )
            logger.warning("MFA activation failed: invalid code")
            logger.debug(f"MFA activation failed for user {user_id}")
            return False

        # Enable MFA
        self._enable_mfa(user_id)

        # Emit audit event
        emit_audit_event(
            AuditEventType.MFA_VERIFIED,
            details={"action": "mfa_activated"},
            user_id=user_id,
            status="SUCCESS",
        )

        logger.info("MFA activated successfully")
        logger.debug(f"MFA activated for user {user_id}")
        return True

    def verify(self, user_id: str, code: str, is_backup: bool = False) -> bool:
        """
        Verify TOTP or backup code.

        Args:
            user_id: User ID
            code: TOTP code or backup code
            is_backup: Whether code is a backup code (default: False)

        Returns:
            True if code is valid
        """
        # Get status
        status = self._get_status(user_id)
        if not status.enabled:
            logger.warning("MFA verification attempted for non-enrolled user")
            logger.debug(f"MFA verification attempted for non-enrolled user {user_id}")
            return False

        # Verify backup code
        if is_backup:
            if self._backup_manager.verify_code(user_id, code):
                self._update_last_used(user_id)
                emit_audit_event(
                    AuditEventType.MFA_BACKUP_USED,
                    details={"remaining_codes": status.backup_codes_remaining - 1},
                    user_id=user_id,
                    status="SUCCESS",
                )
                logger.info("Backup code verified successfully")
                logger.debug(f"Backup code verified for user {user_id}")
                return True
            else:
                emit_audit_event(
                    AuditEventType.MFA_VERIFICATION_FAILED,
                    details={"reason": "invalid_backup_code"},
                    user_id=user_id,
                    status="FAILURE",
                )
                return False

        # Verify TOTP code
        secret = self.get_secret(user_id)
        if not secret:
            return False

        if self._totp_provider.verify_totp(secret, code):
            self._update_last_used(user_id)
            emit_audit_event(
                AuditEventType.MFA_VERIFIED,
                details={"action": "totp_verified"},
                user_id=user_id,
                status="SUCCESS",
            )
            return True
        else:
            emit_audit_event(
                AuditEventType.MFA_VERIFICATION_FAILED,
                details={"reason": "invalid_totp"},
                user_id=user_id,
                status="FAILURE",
            )
            return False

    def get_secret(self, user_id: str) -> str | None:
        """
        Retrieve and decrypt TOTP secret.

        Supports both AES-256-GCM encrypted secrets and legacy base64 encoded secrets.
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "SELECT encrypted_secret, key_id FROM mfa_secrets WHERE user_id = ?",
                (user_id,),
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            encoded_secret = row[0]
            key_id = row[1]

            # Handle legacy base64 encoding
            if key_id == "base64":
                logger.warning(
                    "MFA secret uses legacy base64 encoding. "
                    "Consider re-enrolling for AES-256-GCM encryption."
                )
                return base64.b64decode(encoded_secret).decode()

            # Decrypt with KeyManager
            try:
                from pdfsigner.core.crypto.key_manager import get_key_manager

                key_mgr = get_key_manager()
                encrypted_bytes = base64.b64decode(encoded_secret)
                decrypted = key_mgr.decrypt_data(key_id, encrypted_bytes)
                return decrypted.decode()

            except RuntimeError:
                logger.error("KeyManager not initialized but MFA secret requires decryption key")
                return None

        except Exception as e:
            logger.error("Failed to retrieve MFA secret")
            logger.debug(f"Failed to retrieve MFA secret for user {user_id}: {e}")
            return None

    def _enable_mfa(self, user_id: str) -> None:
        """Enable MFA for user."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE mfa_secrets
            SET enabled = 1, enrolled_at = ?
            WHERE user_id = ?
        """,
            (datetime.now(UTC).isoformat(), user_id),
        )
        conn.commit()
        conn.close()

    def _update_last_used(self, user_id: str) -> None:
        """Update last used timestamp."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE mfa_secrets SET last_used_at = ? WHERE user_id = ?",
            (datetime.now(UTC).isoformat(), user_id),
        )
        conn.commit()
        conn.close()


# Public exports
__all__ = ["MFAVerificationService"]
