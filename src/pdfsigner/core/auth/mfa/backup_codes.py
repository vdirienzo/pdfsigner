"""
backup_codes.py - Backup code management for MFA

Provides one-time use backup codes for MFA recovery.
Codes are hashed before storage (PBKDF2) for security.
"""

import hashlib
import hmac
import secrets
import sqlite3
from datetime import UTC, datetime

from loguru import logger


class BackupCodeManager:
    """
    Manager for MFA backup codes.

    Backup codes are one-time use codes for MFA recovery when TOTP is unavailable.
    Codes are hashed before storage using PBKDF2-HMAC-SHA256 + random salt for security.
    """

    CODE_LENGTH = 8  # XXXX-XXXX format

    def __init__(self, db_connection: sqlite3.Connection) -> None:
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

    def hash_code(self, code: str, salt: bytes | None = None) -> tuple[str, str]:
        """
        Hash backup code with random salt using PBKDF2.

        Args:
            code: Backup code to hash (e.g., "1234-5678")
            salt: Optional salt (generated if None)

        Returns:
            Tuple of (hex-encoded hash, hex-encoded salt)
        """
        normalized_code = code.replace("-", "")

        if salt is None:
            salt = secrets.token_bytes(16)

        # Use PBKDF2 with 600k iterations (NIST 2023 recommendation)
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256",
            normalized_code.encode(),
            salt,
            iterations=600_000,
        )
        return hash_bytes.hex(), salt.hex()

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

            # Insert new codes with per-code salt
            for code in codes:
                code_hash, salt = self.hash_code(code)
                cursor.execute(
                    """
                    INSERT INTO mfa_backup_codes (user_id, code_hash, salt, used, used_at)
                    VALUES (?, ?, ?, 0, NULL)
                """,
                    (user_id, code_hash, salt),
                )

            self.db.commit()
            logger.info(f"Stored {len(codes)} backup codes")
            logger.debug(f"Stored backup codes for user {user_id}")
            return True

        except Exception as e:
            logger.error("Failed to store backup codes")
            logger.debug(f"Failed to store backup codes for user {user_id}: {e}")
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
            cursor = self.db.cursor()

            # Get all unused codes with their salts
            cursor.execute(
                """
                SELECT id, code_hash, salt FROM mfa_backup_codes
                WHERE user_id = ? AND used = 0
            """,
                (user_id,),
            )
            rows = cursor.fetchall()

            if not rows:
                logger.warning("No unused backup codes available")
                logger.debug(f"No unused backup codes for user {user_id}")
                return False

            # Check each code (timing-safe comparison)
            normalized_code = code.replace("-", "")
            for row in rows:
                backup_id, stored_hash, stored_salt = row
                salt = bytes.fromhex(stored_salt)
                computed_hash = hashlib.pbkdf2_hmac(
                    "sha256",
                    normalized_code.encode(),
                    salt,
                    iterations=600_000,
                ).hex()

                if hmac.compare_digest(computed_hash, stored_hash):
                    # Mark as used
                    cursor.execute(
                        """
                        UPDATE mfa_backup_codes
                        SET used = 1, used_at = ?
                        WHERE id = ?
                    """,
                        (datetime.now(UTC).isoformat(), backup_id),
                    )
                    self.db.commit()
                    logger.info("Backup code verified and consumed")
                    logger.debug(f"Backup code consumed for user {user_id}")
                    return True

            logger.warning("Invalid backup code attempted")
            logger.debug(f"Invalid backup code for user {user_id}")
            return False

        except Exception as e:
            logger.error("Failed to verify backup code")
            logger.debug(f"Failed to verify backup code for user {user_id}: {e}")
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
            logger.error("Failed to get backup code count")
            logger.debug(f"Failed to get backup code count for user {user_id}: {e}")
            return 0


# Public exports
__all__ = ["BackupCodeManager"]
