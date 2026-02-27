"""
mfa_manager.py - Multi-Factor Authentication manager (orchestrator)

Orchestrates MFA enrollment, verification, and lifecycle by delegating
to specialized services: MFAEnrollmentService and MFAVerificationService.
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.audit.audit_event import AuditEventType
from pdfsigner.core.audit.helpers import emit_audit_event
from pdfsigner.core.auth.mfa.backup_codes import BackupCodeManager
from pdfsigner.core.auth.mfa.mfa_enrollment import MFAEnrollmentService
from pdfsigner.core.auth.mfa.mfa_types import MFAEnrollment, MFAStatus
from pdfsigner.core.auth.mfa.mfa_verification import MFAVerificationService
from pdfsigner.core.auth.mfa.totp_provider import TOTPProvider


class MFAManager:
    """
    Multi-Factor Authentication manager.

    Orchestrates MFA operations by delegating to:
    - MFAEnrollmentService: enrollment, secret storage, backup codes
    - MFAVerificationService: TOTP/backup code verification, activation
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

        # Initialize sub-services
        self._enrollment_service = MFAEnrollmentService(
            totp_provider=self.totp_provider,
            backup_manager=self.backup_manager,
            get_connection=self._get_connection,
            get_status=self.get_status,
        )
        self._verification_service = MFAVerificationService(
            totp_provider=self.totp_provider,
            backup_manager=self.backup_manager,
            get_connection=self._get_connection,
            get_status=self.get_status,
        )

        logger.info("MFA manager initialized")

    @classmethod
    def get_instance(cls, db_path: Path | None = None) -> "MFAManager":
        """
        Get or create singleton instance.

        Args:
            db_path: Path to SQLite database (required on first call)

        Returns:
            MFAManager singleton instance
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
        except Exception as e:
            logger.debug(f"ALTER TABLE mfa_backup_codes (column may already exist): {e}")

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_mfa_user ON mfa_secrets(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_backup_user ON mfa_backup_codes(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_backup_used ON mfa_backup_codes(used)")

        conn.commit()
        conn.close()

    # --- Enrollment (delegated) ---

    def enroll(self, user_id: str, account_name: str | None = None) -> MFAEnrollment:
        """
        Start MFA enrollment for user.

        Generates TOTP secret, QR code, and backup codes.
        Does not enable MFA until verify_and_activate() is called.
        """
        return self._enrollment_service.enroll(user_id, account_name)

    def regenerate_backup_codes(self, user_id: str) -> list[str]:
        """Regenerate backup codes for user."""
        return self._enrollment_service.regenerate_backup_codes(user_id)

    # --- Verification (delegated) ---

    def verify_and_activate(self, user_id: str, code: str) -> bool:
        """Verify TOTP code and activate MFA."""
        return self._verification_service.verify_and_activate(user_id, code)

    def verify(self, user_id: str, code: str, is_backup: bool = False) -> bool:
        """Verify TOTP or backup code."""
        return self._verification_service.verify(user_id, code, is_backup)

    # --- Status & lifecycle (kept in orchestrator) ---

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
            emit_audit_event(
                AuditEventType.MFA_DISABLED,
                details=details,
                user_id=user_id,
                status="SUCCESS",
            )

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

    # --- Internal helpers exposed for backward compatibility ---

    def _store_secret(self, user_id: str, secret: str, enabled: bool = False) -> None:
        """Store TOTP secret (delegates to enrollment service)."""
        self._enrollment_service.store_secret(user_id, secret, enabled)

    def _get_secret(self, user_id: str) -> str | None:
        """Retrieve and decrypt TOTP secret (delegates to verification service)."""
        return self._verification_service.get_secret(user_id)

    def _enable_mfa(self, user_id: str) -> None:
        """Enable MFA for user (delegates to verification service)."""
        self._verification_service._enable_mfa(user_id)

    def _update_last_used(self, user_id: str) -> None:
        """Update last used timestamp (delegates to verification service)."""
        self._verification_service._update_last_used(user_id)


# Singleton accessor
def get_mfa_manager() -> MFAManager:
    """Get MFA manager singleton instance."""
    return MFAManager.get_instance()


# Public exports
__all__ = ["MFAManager", "MFAEnrollment", "MFAStatus", "get_mfa_manager"]
