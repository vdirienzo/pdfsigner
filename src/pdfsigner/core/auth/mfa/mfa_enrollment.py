"""
mfa_enrollment.py - MFA enrollment and secret storage

Handles TOTP enrollment, QR code generation, backup code provisioning,
and encrypted secret storage via KeyManager.
"""

import base64
import sqlite3
from datetime import UTC, datetime

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEventType
from pdfsigner.core.audit.helpers import emit_audit_event
from pdfsigner.core.auth.mfa.backup_codes import BackupCodeManager
from pdfsigner.core.auth.mfa.mfa_types import MFAEnrollment
from pdfsigner.core.auth.mfa.totp_provider import TOTPProvider


class MFAEnrollmentService:
    """
    Handles MFA enrollment operations.

    Responsible for:
    - TOTP secret generation and encrypted storage
    - QR code and provisioning URI generation
    - Backup code provisioning and regeneration
    """

    def __init__(
        self,
        totp_provider: TOTPProvider,
        backup_manager: BackupCodeManager,
        get_connection: "callable[[], sqlite3.Connection]",
        get_status: "callable",
    ) -> None:
        """
        Initialize enrollment service.

        Args:
            totp_provider: TOTP provider for secret/code generation
            backup_manager: Backup code manager
            get_connection: Callable returning a new SQLite connection
            get_status: Callable to check current MFA status for a user
        """
        self._totp_provider = totp_provider
        self._backup_manager = backup_manager
        self._get_connection = get_connection
        self._get_status = get_status

    def enroll(self, user_id: str, account_name: str | None = None) -> MFAEnrollment:
        """
        Start MFA enrollment for user.

        Generates TOTP secret, QR code, and backup codes.
        Does not enable MFA until verify_and_activate() is called.

        Args:
            user_id: User ID to enroll
            account_name: Account name for QR code (default: user_id)

        Returns:
            MFAEnrollment with secret, QR code, and backup codes

        Raises:
            ValueError: If user already has MFA enabled
        """
        # Check if already enrolled
        if self._get_status(user_id).enabled:
            raise ValueError(f"User {user_id} already has MFA enabled")

        # Generate TOTP secret
        secret = self._totp_provider.generate_secret()

        # Generate QR code
        account_name = account_name or user_id
        qr_bytes = self._totp_provider.generate_qr_code(secret, account_name)
        qr_base64 = base64.b64encode(qr_bytes).decode()

        # Generate provisioning URI
        provisioning_uri = self._totp_provider.get_provisioning_uri(secret, account_name)

        # Generate backup codes
        backup_codes = self._backup_manager.generate_codes(count=10)

        # Store encrypted secret (but keep enabled=0 until verified)
        self.store_secret(user_id, secret, enabled=False)

        # Store backup codes
        self._backup_manager.store_codes(user_id, backup_codes)

        # Emit audit event
        emit_audit_event(
            AuditEventType.MFA_ENROLLED,
            details={"action": "enrollment_started"},
            user_id=user_id,
            status="SUCCESS",
        )

        logger.info("MFA enrollment started")
        logger.debug(f"MFA enrollment started for user {user_id}")

        return MFAEnrollment(
            secret=secret,
            qr_code_base64=qr_base64,
            provisioning_uri=provisioning_uri,
            backup_codes=backup_codes,
        )

    def regenerate_backup_codes(self, user_id: str) -> list[str]:
        """
        Regenerate backup codes for user.

        Args:
            user_id: User ID

        Returns:
            List of new backup codes

        Raises:
            ValueError: If MFA not enabled for user
        """
        status = self._get_status(user_id)
        if not status.enabled:
            raise ValueError(f"MFA not enabled for user {user_id}")

        # Generate and store new codes
        backup_codes = self._backup_manager.generate_codes(count=10)
        self._backup_manager.store_codes(user_id, backup_codes)

        # Emit audit event
        emit_audit_event(
            AuditEventType.MFA_BACKUP_REGENERATED,
            details={"new_code_count": len(backup_codes)},
            user_id=user_id,
            status="SUCCESS",
        )

        logger.info("Backup codes regenerated")
        logger.debug(f"Backup codes regenerated for user {user_id}")
        return backup_codes

    def store_secret(self, user_id: str, secret: str, enabled: bool = False) -> None:
        """
        Store TOTP secret with AES-256-GCM encryption.

        Security: Uses KeyManager for proper encryption instead of base64 obfuscation.
        """
        try:
            # Try to use KeyManager for proper encryption
            try:
                from pdfsigner.core.crypto.key_manager import get_key_manager

                key_mgr = get_key_manager()
                mfa_key_id = key_mgr.get_or_create_mfa_key()

                # Encrypt the secret
                encrypted_bytes = key_mgr.encrypt_data(mfa_key_id, secret.encode())
                encoded_secret = base64.b64encode(encrypted_bytes).decode()
                key_id = mfa_key_id

                logger.debug("MFA secret encrypted with AES-256-GCM")

            except RuntimeError:
                raise RuntimeError(
                    "KeyManager not initialized. MFA enrollment requires KeyManager "
                    "for secure secret storage. Call init_key_manager() first."
                )

            # Store in database
            conn = self._get_connection()
            cursor = conn.cursor()

            enrolled_at = datetime.now(UTC).isoformat() if enabled else None

            cursor.execute(
                """
                INSERT OR REPLACE INTO mfa_secrets
                (user_id, encrypted_secret, key_id, enabled, enrolled_at, last_used_at)
                VALUES (?, ?, ?, ?, ?, NULL)
            """,
                (user_id, encoded_secret, key_id, int(enabled), enrolled_at),
            )
            conn.commit()
            conn.close()

        except Exception as e:
            logger.error("Failed to store MFA secret")
            logger.debug(f"Failed to store MFA secret for user {user_id}: {e}")
            raise


# Public exports
__all__ = ["MFAEnrollmentService"]
