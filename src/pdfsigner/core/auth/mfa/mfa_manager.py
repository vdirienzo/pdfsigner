"""
mfa_manager.py - Multi-Factor Authentication manager

Manages MFA enrollment, verification, and lifecycle.
Integrates TOTP provider, backup codes, and encrypted storage.
"""

import base64
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit import get_audit_logger
from pdfsigner.core.audit.audit_event import AuditEvent, AuditEventType
from pdfsigner.core.auth.mfa.backup_codes import BackupCodeManager
from pdfsigner.core.auth.mfa.totp_provider import TOTPProvider


@dataclass
class MFAEnrollment:
    """MFA enrollment data for user setup."""

    secret: str
    qr_code_base64: str
    provisioning_uri: str
    backup_codes: list[str]


@dataclass
class MFAStatus:
    """MFA status for a user."""

    enabled: bool
    enrolled_at: datetime | None
    last_used_at: datetime | None
    backup_codes_remaining: int


class MFAManager:
    """
    Multi-Factor Authentication manager.

    Features:
    - TOTP enrollment with QR code generation
    - TOTP verification with time window tolerance
    - Backup code generation and verification
    - Encrypted secret storage using KeyManager
    - Audit logging for all MFA operations
    - SQLite-based persistence
    """

    _instance: "MFAManager | None" = None
    _lock = threading.Lock()

    def __init__(self, db_path: Path) -> None:
        """
        Initialize MFA manager.

        Args:
            db_path: Path to SQLite database for MFA data
        """
        self.db_path = db_path
        self.totp_provider = TOTPProvider()

        # Create directory if needed
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self._init_database()

        # Initialize backup code manager
        self.backup_manager = BackupCodeManager(self._get_connection())

        logger.info("MFA manager initialized")

    @classmethod
    def get_instance(cls, db_path: Path | None = None) -> "MFAManager":
        """
        Get or create singleton instance.

        Args:
            db_path: Path to SQLite database (required on first call)

        Returns:
            MFAManager singleton instance

        Raises:
            ValueError: If db_path not provided on first call
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    if db_path is None:
                        db_path = Path.home() / ".config" / "pdfsigner" / "mfa.db"
                    cls._instance = cls(db_path)
        return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        return sqlite3.connect(self.db_path)

    def _init_database(self) -> None:
        """Initialize SQLite database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # MFA secrets table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_secrets (
                user_id TEXT PRIMARY KEY,
                encrypted_secret BLOB NOT NULL,
                key_id TEXT NOT NULL,
                enabled INTEGER DEFAULT 0,
                enrolled_at TEXT,
                last_used_at TEXT
            )
        """
        )

        # Backup codes table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS mfa_backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                salt TEXT NOT NULL DEFAULT '',
                used INTEGER DEFAULT 0,
                used_at TEXT,
                FOREIGN KEY (user_id) REFERENCES mfa_secrets(user_id)
            )
        """
        )

        # Migration: add salt column if missing (existing databases)
        try:
            cursor.execute("ALTER TABLE mfa_backup_codes ADD COLUMN salt TEXT NOT NULL DEFAULT ''")
        except Exception:
            pass  # Column already exists

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_user ON mfa_secrets(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_backup_user ON mfa_backup_codes(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_backup_used ON mfa_backup_codes(used)")

        conn.commit()
        conn.close()

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
        if self.get_status(user_id).enabled:
            raise ValueError(f"User {user_id} already has MFA enabled")

        # Generate TOTP secret
        secret = self.totp_provider.generate_secret()

        # Generate QR code
        account_name = account_name or user_id
        qr_bytes = self.totp_provider.generate_qr_code(secret, account_name)
        qr_base64 = base64.b64encode(qr_bytes).decode()

        # Generate provisioning URI
        provisioning_uri = self.totp_provider.get_provisioning_uri(secret, account_name)

        # Generate backup codes
        backup_codes = self.backup_manager.generate_codes(count=10)

        # Store encrypted secret (but keep enabled=0 until verified)
        self._store_secret(user_id, secret, enabled=False)

        # Store backup codes
        self.backup_manager.store_codes(user_id, backup_codes)

        # Emit audit event
        self._emit_audit_event(
            AuditEventType.MFA_ENROLLED,
            user_id,
            "SUCCESS",
            {"action": "enrollment_started"},
        )

        logger.info("MFA enrollment started")
        logger.debug(f"MFA enrollment started for user {user_id}")

        return MFAEnrollment(
            secret=secret,
            qr_code_base64=qr_base64,
            provisioning_uri=provisioning_uri,
            backup_codes=backup_codes,
        )

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
        secret = self._get_secret(user_id)
        if not secret:
            raise ValueError(f"No MFA enrollment found for user {user_id}")

        # Verify code
        if not self.totp_provider.verify_totp(secret, code):
            self._emit_audit_event(
                AuditEventType.MFA_VERIFICATION_FAILED,
                user_id,
                "FAILURE",
                {"reason": "invalid_code"},
            )
            logger.warning("MFA activation failed: invalid code")
            logger.debug(f"MFA activation failed for user {user_id}")
            return False

        # Enable MFA
        self._enable_mfa(user_id)

        # Emit audit event
        self._emit_audit_event(
            AuditEventType.MFA_VERIFIED,
            user_id,
            "SUCCESS",
            {"action": "mfa_activated"},
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
        status = self.get_status(user_id)
        if not status.enabled:
            logger.warning("MFA verification attempted for non-enrolled user")
            logger.debug(f"MFA verification attempted for non-enrolled user {user_id}")
            return False

        # Verify backup code
        if is_backup:
            if self.backup_manager.verify_code(user_id, code):
                self._update_last_used(user_id)
                self._emit_audit_event(
                    AuditEventType.MFA_BACKUP_USED,
                    user_id,
                    "SUCCESS",
                    {"remaining_codes": status.backup_codes_remaining - 1},
                )
                logger.info("Backup code verified successfully")
                logger.debug(f"Backup code verified for user {user_id}")
                return True
            else:
                self._emit_audit_event(
                    AuditEventType.MFA_VERIFICATION_FAILED,
                    user_id,
                    "FAILURE",
                    {"reason": "invalid_backup_code"},
                )
                return False

        # Verify TOTP code
        secret = self._get_secret(user_id)
        if not secret:
            return False

        if self.totp_provider.verify_totp(secret, code):
            self._update_last_used(user_id)
            self._emit_audit_event(
                AuditEventType.MFA_VERIFIED,
                user_id,
                "SUCCESS",
                {"action": "totp_verified"},
            )
            return True
        else:
            self._emit_audit_event(
                AuditEventType.MFA_VERIFICATION_FAILED,
                user_id,
                "FAILURE",
                {"reason": "invalid_totp"},
            )
            return False

    def disable(self, user_id: str, admin_id: str | None = None) -> bool:
        """
        Disable MFA for user.

        Args:
            user_id: User ID to disable MFA for
            admin_id: Optional admin ID (for audit trail)

        Returns:
            True if disabled successfully
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Delete MFA data
            cursor.execute("DELETE FROM mfa_secrets WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM mfa_backup_codes WHERE user_id = ?", (user_id,))
            conn.commit()

            # Emit audit event
            details = {"disabled_by": admin_id or user_id}
            self._emit_audit_event(AuditEventType.MFA_DISABLED, user_id, "SUCCESS", details)

            logger.info("MFA disabled successfully")
            logger.debug(
                f"MFA disabled for user {user_id}" + (f" by admin {admin_id}" if admin_id else "")
            )
            return True

        except Exception as e:
            logger.error("Failed to disable MFA")
            logger.debug(f"Failed to disable MFA for user {user_id}: {e}")
            conn.rollback()
            return False
        finally:
            conn.close()

    def get_status(self, user_id: str) -> MFAStatus:
        """
        Get MFA status for user.

        Args:
            user_id: User ID

        Returns:
            MFAStatus with enrollment and usage info
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT enabled, enrolled_at, last_used_at
                FROM mfa_secrets
                WHERE user_id = ?
            """,
                (user_id,),
            )
            row = cursor.fetchone()

            if not row:
                return MFAStatus(
                    enabled=False,
                    enrolled_at=None,
                    last_used_at=None,
                    backup_codes_remaining=0,
                )

            enabled = bool(row[0])
            enrolled_at = datetime.fromisoformat(row[1]) if row[1] else None
            last_used_at = datetime.fromisoformat(row[2]) if row[2] else None
            backup_codes_remaining = self.backup_manager.get_remaining_count(user_id)

            return MFAStatus(
                enabled=enabled,
                enrolled_at=enrolled_at,
                last_used_at=last_used_at,
                backup_codes_remaining=backup_codes_remaining,
            )

        finally:
            conn.close()

    def is_mfa_required(self, user_id: str, user_role: str | None = None) -> bool:
        """
        Check if MFA is required for user.

        Args:
            user_id: User ID
            user_role: User role (for role-based requirements)

        Returns:
            True if MFA is required and enabled
        """
        from pdfsigner.config.settings import get_settings

        settings = get_settings()

        # Check if MFA feature is enabled globally
        if not settings.mfa_enabled:
            return False

        # Check role-based requirements
        if user_role and user_role.upper() in [r.upper() for r in settings.mfa_required_for_roles]:
            status = self.get_status(user_id)
            return status.enabled

        return False

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
        status = self.get_status(user_id)
        if not status.enabled:
            raise ValueError(f"MFA not enabled for user {user_id}")

        # Generate and store new codes
        backup_codes = self.backup_manager.generate_codes(count=10)
        self.backup_manager.store_codes(user_id, backup_codes)

        # Emit audit event
        self._emit_audit_event(
            AuditEventType.MFA_BACKUP_REGENERATED,
            user_id,
            "SUCCESS",
            {"new_code_count": len(backup_codes)},
        )

        logger.info("Backup codes regenerated")
        logger.debug(f"Backup codes regenerated for user {user_id}")
        return backup_codes

    def _store_secret(self, user_id: str, secret: str, enabled: bool = False) -> None:
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

    def _get_secret(self, user_id: str) -> str | None:
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

    def _emit_audit_event(
        self, event_type: AuditEventType, user_id: str, status: str, details: dict
    ) -> None:
        """Emit audit event for MFA operation."""
        try:
            audit_logger = get_audit_logger()
            event = AuditEvent(
                event_type=event_type,
                status=status,
                user_id=user_id,
                details=details,
            )
            audit_logger.log_event(event)
        except Exception as e:
            logger.warning(f"Failed to emit audit event: {e}")


# Singleton accessor
def get_mfa_manager() -> MFAManager:
    """Get MFA manager singleton instance."""
    return MFAManager.get_instance()


# Public exports
__all__ = ["MFAManager", "MFAEnrollment", "MFAStatus", "get_mfa_manager"]
