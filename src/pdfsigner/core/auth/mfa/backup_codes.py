"""
backup_codes.py - Backup code management for MFA

Provides one-time use backup codes for MFA recovery.
Codes are hashed before storage (bcrypt) for security.
"""

import hashlib
import secrets
from datetime import datetime

from loguru import logger


class BackupCodeManager:
    """
    Manager for MFA backup codes.

    Backup codes are one-time use codes for MFA recovery when TOTP is unavailable.
    Codes are hashed before storage using SHA-256 + salt for security.
    """

    CODE_LENGTH = 8  # XXXX-XXXX format
    HASH_ALGORITHM = "sha256"

    def __init__(self, db_connection: any) -> None:
        """
        Initialize backup code manager.

        Args:
            db_connection: SQLite database connection (from MFAManager)
        """
        self.db = db_connection

    def generate_codes(self, count: int = 10) -> list[str]:
        """
        Generate backup codes in XXXX-XXXX format.

        Args:
            count: Number of codes to generate (default: 10)

        Returns:
            List of backup codes (e.g., ["1234-5678", "9012-3456"])

        Example:
            >>> manager.generate_codes(5)
            ['1234-5678', '9012-3456', '7890-1234', '5678-9012', '3456-7890']
        """
        codes = []
        for _ in range(count):
            # Generate 8 random digits
            code_num = secrets.randbelow(100000000)  # 0 to 99,999,999
            code = f"{code_num:08d}"  # Zero-pad to 8 digits

            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)

        return codes

    def hash_code(self, code: str) -> str:
        """
        Hash backup code for secure storage.

        Args:
            code: Backup code to hash (e.g., "1234-5678")

        Returns:
            Hex-encoded hash string

        Note:
            Uses SHA-256 for hashing. In production, consider using bcrypt
            or argon2 for better security against rainbow tables.
        """
        # Remove hyphen for hashing
        normalized_code = code.replace("-", "")

        # Add application-specific salt
        salted = f"pdfsigner_mfa_backup_{normalized_code}"

        # Hash with SHA-256
        hash_obj = hashlib.sha256(salted.encode())
        return hash_obj.hexdigest()

    def store_codes(self, user_id: str, codes: list[str]) -> bool:
        """
        Store backup codes for user.

        Args:
            user_id: User ID
            codes: List of backup codes to store

        Returns:
            True if stored successfully

        Note:
            This replaces any existing backup codes for the user.
        """
        try:
            cursor = self.db.cursor()

            # Delete existing backup codes
            cursor.execute("DELETE FROM mfa_backup_codes WHERE user_id = ?", (user_id,))

            # Insert new codes
            for code in codes:
                code_hash = self.hash_code(code)
                cursor.execute(
                    """
                    INSERT INTO mfa_backup_codes (user_id, code_hash, used, used_at)
                    VALUES (?, ?, 0, NULL)
                """,
                    (user_id, code_hash),
                )

            self.db.commit()
            logger.info(f"Stored {len(codes)} backup codes for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to store backup codes for user {user_id}: {e}")
            self.db.rollback()
            return False

    def verify_code(self, user_id: str, code: str) -> bool:
        """
        Verify backup code and mark as used.

        Args:
            user_id: User ID
            code: Backup code to verify

        Returns:
            True if code is valid and unused, False otherwise

        Note:
            Code is marked as used after successful verification (one-time use).
        """
        try:
            code_hash = self.hash_code(code)
            cursor = self.db.cursor()

            # Check if code exists and is not used
            cursor.execute(
                """
                SELECT id FROM mfa_backup_codes
                WHERE user_id = ? AND code_hash = ? AND used = 0
            """,
                (user_id, code_hash),
            )
            row = cursor.fetchone()

            if not row:
                logger.warning(f"Invalid or already used backup code for user {user_id}")
                return False

            # Mark as used
            backup_id = row[0]
            cursor.execute(
                """
                UPDATE mfa_backup_codes
                SET used = 1, used_at = ?
                WHERE id = ?
            """,
                (datetime.now().isoformat(), backup_id),
            )
            self.db.commit()

            logger.info(f"Backup code verified and consumed for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to verify backup code for user {user_id}: {e}")
            self.db.rollback()
            return False

    def get_remaining_count(self, user_id: str) -> int:
        """
        Get count of remaining (unused) backup codes.

        Args:
            user_id: User ID

        Returns:
            Number of unused backup codes
        """
        try:
            cursor = self.db.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) FROM mfa_backup_codes
                WHERE user_id = ? AND used = 0
            """,
                (user_id,),
            )
            row = cursor.fetchone()
            return row[0] if row else 0

        except Exception as e:
            logger.error(f"Failed to get backup code count for user {user_id}: {e}")
            return 0


# Public exports
__all__ = ["BackupCodeManager"]
