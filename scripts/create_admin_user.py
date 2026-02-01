#!/usr/bin/env python3
"""
create_admin_user.py - Create admin user for PDFSigner API

Usage:
    uv run python scripts/create_admin_user.py --username admin --password <password>
    uv run python scripts/create_admin_user.py --username admin --generate-password

Security: NIST IA-5 compliant password handling with Argon2 hashing.
"""

import argparse
import secrets
import string
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pdfsigner.core.auth.password_validator import get_password_validator
from pdfsigner.core.users.user_model import User, UserRole, UserStatus
from pdfsigner.core.users.user_repository import get_user_repository


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    # Ensure at least one of each required character type
    password = (
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%^&*")
        + password[4:]
    )
    return password


def create_admin_user(
    username: str,
    password: str,
    email: str | None = None,
    display_name: str | None = None,
) -> tuple[User, str]:
    """
    Create an admin user with password.

    Args:
        username: Admin username
        password: Plain text password
        email: Optional email address
        display_name: Optional display name

    Returns:
        Tuple of (created User, password hash)

    Raises:
        ValueError: If password doesn't meet policy or username exists
    """
    user_repo = get_user_repository()
    password_validator = get_password_validator()

    # Check if username already exists
    existing = user_repo.get_user_by_username(username)
    if existing:
        raise ValueError(f"User '{username}' already exists")

    # Validate password against policy
    result = password_validator.validate(password)
    if not result.is_valid:
        raise ValueError(f"Password does not meet policy: {', '.join(result.errors)}")

    # Hash password
    password_hash = password_validator.hash_password(password)

    # Create user
    user = User(
        username=username,
        display_name=display_name or username.title(),
        email=email or f"{username}@localhost",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
    )

    # Save user and credentials
    created_user = user_repo.create_user(user)
    user_repo.set_password(created_user.id, password_hash)

    return created_user, password_hash


def main():
    parser = argparse.ArgumentParser(
        description="Create admin user for PDFSigner API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --username admin --password MySecureP@ss123
  %(prog)s --username admin --generate-password
  %(prog)s --username admin --password MySecureP@ss123 --email admin@company.com
        """,
    )
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--password", help="Password (min 12 chars, mixed case, digits, special)")
    parser.add_argument(
        "--generate-password", action="store_true", help="Generate a secure random password"
    )
    parser.add_argument("--email", help="Email address (optional)")
    parser.add_argument("--display-name", help="Display name (optional)")

    args = parser.parse_args()

    # Get or generate password
    if args.generate_password:
        password = generate_secure_password()
        print(f"Generated password: {password}")
    elif args.password:
        password = args.password
    else:
        parser.error("Either --password or --generate-password is required")

    try:
        user, _ = create_admin_user(
            username=args.username,
            password=password,
            email=args.email,
            display_name=args.display_name,
        )
        print("\nAdmin user created successfully!")
        print(f"  Username: {user.username}")
        print(f"  ID: {user.id}")
        print(f"  Role: {user.role.value}")
        print(f"  Email: {user.email}")
        print("\nUse these credentials to login to the API.")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
