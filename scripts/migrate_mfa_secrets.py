#!/usr/bin/env python3
"""
migrate_mfa_secrets.py - Migrate MFA secrets from base64 to AES-256-GCM encryption

Usage:
    uv run python scripts/migrate_mfa_secrets.py --master-password <password>
    uv run python scripts/migrate_mfa_secrets.py --dry-run

Security: Migrates legacy base64-encoded MFA secrets to proper AES-256-GCM encryption.
"""

import argparse
import base64
import sqlite3
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


from pdfsigner.core.crypto.key_manager import init_key_manager


def get_mfa_db_path() -> Path:
    """Get path to MFA database."""
    config_dir = Path.home() / ".config" / "pdfsigner"
    return config_dir / "mfa.db"


def get_key_db_path() -> Path:
    """Get path to key manager database."""
    config_dir = Path.home() / ".config" / "pdfsigner"
    return config_dir / "keys.db"


def migrate_secrets(master_password: str, dry_run: bool = False) -> tuple[int, int]:
    """
    Migrate MFA secrets from base64 to AES-256-GCM.

    Args:
        master_password: Master password for KeyManager
        dry_run: If True, only report what would be migrated

    Returns:
        Tuple of (migrated_count, error_count)
    """
    mfa_db = get_mfa_db_path()
    if not mfa_db.exists():
        print("No MFA database found. Nothing to migrate.")
        return 0, 0

    # Initialize KeyManager
    key_db = get_key_db_path()
    key_mgr = init_key_manager(key_db, master_password)
    mfa_key_id = key_mgr.get_or_create_mfa_key()

    print(f"MFA encryption key ID: {mfa_key_id}")

    # Connect to MFA database
    conn = sqlite3.connect(mfa_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Find secrets using base64 encoding
    cursor.execute("SELECT user_id, encrypted_secret FROM mfa_secrets WHERE key_id = 'base64'")
    rows = cursor.fetchall()

    if not rows:
        print("No secrets using legacy base64 encoding found.")
        conn.close()
        return 0, 0

    print(f"Found {len(rows)} secrets to migrate")

    migrated = 0
    errors = 0

    for row in rows:
        user_id = row["user_id"]
        encoded_secret = row["encrypted_secret"]

        try:
            # Decode base64
            secret = base64.b64decode(encoded_secret).decode()

            if dry_run:
                print(f"  [DRY-RUN] Would migrate secret for user: {user_id}")
                migrated += 1
                continue

            # Encrypt with KeyManager
            encrypted_bytes = key_mgr.encrypt_data(mfa_key_id, secret.encode())
            new_encoded = base64.b64encode(encrypted_bytes).decode()

            # Update database
            cursor.execute(
                "UPDATE mfa_secrets SET encrypted_secret = ?, key_id = ? WHERE user_id = ?",
                (new_encoded, mfa_key_id, user_id),
            )

            print(f"  Migrated secret for user: {user_id}")
            migrated += 1

        except Exception as e:
            print(f"  ERROR migrating secret for user {user_id}: {e}")
            errors += 1

    if not dry_run:
        conn.commit()

    conn.close()

    return migrated, errors


def main():
    parser = argparse.ArgumentParser(
        description="Migrate MFA secrets from base64 to AES-256-GCM encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--master-password",
        help="Master password for KeyManager encryption",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without making changes",
    )

    args = parser.parse_args()

    if not args.dry_run and not args.master_password:
        parser.error("--master-password is required unless using --dry-run")

    master_password = args.master_password or "dry-run-placeholder"

    print("MFA Secret Migration Tool")
    print("=" * 50)

    if args.dry_run:
        print("Mode: DRY RUN (no changes will be made)")
    else:
        print("Mode: LIVE MIGRATION")

    print()

    migrated, errors = migrate_secrets(master_password, dry_run=args.dry_run)

    print()
    print("=" * 50)
    print(f"Migrated: {migrated}")
    print(f"Errors: {errors}")

    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
