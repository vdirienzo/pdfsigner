"""
user_repository.py - User persistence with SQLite

Provides CRUD operations for user management.
HIPAA: §164.312(a)(2)(i) - Unique user identification
"""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from loguru import logger

from pdfsigner.core.users.user_model import Department, User, UserRole, UserStatus


class UserRepository:
    """
    SQLite-based user repository.

    Stores users and departments with full CRUD operations.
    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None):
        """
        Initialize repository.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/users.db
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / "users.db"

        self.db_path = db_path
        self._init_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with automatic cleanup."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS departments (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    code TEXT,
                    description TEXT,
                    parent_id TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (parent_id) REFERENCES departments(id)
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    display_name TEXT,
                    email TEXT,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    department_id TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    password_changed_at TEXT,
                    certificate_serial TEXT,
                    certificate_issuer TEXT,
                    certificate_cn TEXT,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (department_id) REFERENCES departments(id)
                );

                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_users_certificate ON users(certificate_serial, certificate_issuer);
                CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

                -- Credentials table for password authentication (NIST IA-5)
                CREATE TABLE IF NOT EXISTS credentials (
                    user_id TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)

    # --- User CRUD ---

    def create_user(self, user: User) -> User:
        """
        Create new user.

        Args:
            user: User to create

        Returns:
            Created user with ID

        Raises:
            ValueError: If username already exists
        """
        with self._get_connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users (
                        id, username, display_name, email, role, department_id,
                        status, created_at, updated_at, last_login_at,
                        failed_login_attempts, locked_until, password_changed_at,
                        certificate_serial, certificate_issuer, certificate_cn, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user.id,
                        user.username,
                        user.display_name,
                        user.email,
                        user.role.value,
                        user.department_id,
                        user.status.value,
                        user.created_at.isoformat(),
                        user.updated_at.isoformat(),
                        user.last_login_at.isoformat() if user.last_login_at else None,
                        user.failed_login_attempts,
                        user.locked_until.isoformat() if user.locked_until else None,
                        user.password_changed_at.isoformat() if user.password_changed_at else None,
                        user.certificate_serial,
                        user.certificate_issuer,
                        user.certificate_cn,
                        json.dumps(user.metadata),
                    ),
                )
                logger.info(f"Created user: {user.username} (id={user.id})")
                return user
            except sqlite3.IntegrityError as e:
                if "UNIQUE constraint" in str(e):
                    raise ValueError(f"Username '{user.username}' already exists") from e
                raise

    def get_user_by_id(self, user_id: str) -> User | None:
        """Get user by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> User | None:
        """Get user by username."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return self._row_to_user(row) if row else None

    def get_user_by_certificate(self, serial: str, issuer: str) -> User | None:
        """
        Get user by certificate serial and issuer.

        Used to find user when they authenticate with PKCS#11 token.
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE certificate_serial = ? AND certificate_issuer = ?",
                (serial, issuer),
            ).fetchone()
            return self._row_to_user(row) if row else None

    def update_user(self, user: User) -> User:
        """Update existing user."""
        user.updated_at = datetime.now()

        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE users SET
                    username = ?, display_name = ?, email = ?, role = ?,
                    department_id = ?, status = ?, updated_at = ?,
                    last_login_at = ?, failed_login_attempts = ?,
                    locked_until = ?, password_changed_at = ?,
                    certificate_serial = ?, certificate_issuer = ?,
                    certificate_cn = ?, metadata = ?
                WHERE id = ?
                """,
                (
                    user.username,
                    user.display_name,
                    user.email,
                    user.role.value,
                    user.department_id,
                    user.status.value,
                    user.updated_at.isoformat(),
                    user.last_login_at.isoformat() if user.last_login_at else None,
                    user.failed_login_attempts,
                    user.locked_until.isoformat() if user.locked_until else None,
                    user.password_changed_at.isoformat() if user.password_changed_at else None,
                    user.certificate_serial,
                    user.certificate_issuer,
                    user.certificate_cn,
                    json.dumps(user.metadata),
                    user.id,
                ),
            )

        logger.debug(f"Updated user: {user.username}")
        return user

    def delete_user(self, user_id: str) -> bool:
        """Delete user (hard delete)."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            deleted = cursor.rowcount > 0

        if deleted:
            logger.info(f"Deleted user: {user_id}")
        return deleted

    def deactivate_user(self, user_id: str) -> bool:
        """Deactivate user (soft delete)."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE users SET status = ?, updated_at = ? WHERE id = ?",
                (UserStatus.INACTIVE.value, datetime.now().isoformat(), user_id),
            )
            return cursor.rowcount > 0

    def list_users(
        self,
        status: UserStatus | None = None,
        role: UserRole | None = None,
        department_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[User]:
        """
        List users with optional filters.

        Args:
            status: Filter by status
            role: Filter by role
            department_id: Filter by department
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching users
        """
        query = "SELECT * FROM users WHERE 1=1"
        params: list = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if role:
            query += " AND role = ?"
            params.append(role.value)

        if department_id:
            query += " AND department_id = ?"
            params.append(department_id)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_user(row) for row in rows]

    def count_users(self, status: UserStatus | None = None) -> int:
        """Count users with optional status filter."""
        query = "SELECT COUNT(*) FROM users"
        params: list = []

        if status:
            query += " WHERE status = ?"
            params.append(status.value)

        with self._get_connection() as conn:
            return conn.execute(query, params).fetchone()[0]

    # --- Department CRUD ---

    def create_department(self, department: Department) -> Department:
        """Create new department."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO departments (id, name, code, description, parent_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    department.id,
                    department.name,
                    department.code,
                    department.description,
                    department.parent_id,
                    department.created_at.isoformat(),
                ),
            )
        logger.info(f"Created department: {department.name}")
        return department

    def get_department_by_id(self, dept_id: str) -> Department | None:
        """Get department by ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM departments WHERE id = ?", (dept_id,)).fetchone()
            return self._row_to_department(row) if row else None

    def list_departments(self) -> list[Department]:
        """List all departments."""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM departments ORDER BY name").fetchall()
            return [self._row_to_department(row) for row in rows]

    # --- Credentials CRUD (NIST IA-5) ---

    def set_password(self, user_id: str, password_hash: str) -> bool:
        """
        Set password hash for user.

        Args:
            user_id: User ID
            password_hash: Argon2 hash of password

        Returns:
            True if password was set, False if user not found
        """
        with self._get_connection() as conn:
            # Verify user exists
            user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                return False

            now = datetime.now().isoformat()
            # Insert or update credentials
            conn.execute(
                """
                INSERT INTO credentials (user_id, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    updated_at = excluded.updated_at
                """,
                (user_id, password_hash, now, now),
            )
            # Update password_changed_at on user
            conn.execute(
                "UPDATE users SET password_changed_at = ?, updated_at = ? WHERE id = ?",
                (now, now, user_id),
            )
            logger.debug(f"Set password for user: {user_id}")
            return True

    def get_password_hash(self, user_id: str) -> str | None:
        """
        Get password hash for user.

        Args:
            user_id: User ID

        Returns:
            Password hash or None if not found
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT password_hash FROM credentials WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            return row["password_hash"] if row else None

    def has_password(self, user_id: str) -> bool:
        """Check if user has a password set."""
        return self.get_password_hash(user_id) is not None

    def count_admins(self) -> int:
        """Count active admin users."""
        with self._get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = ? AND status = ?",
                (UserRole.ADMIN.value, UserStatus.ACTIVE.value),
            ).fetchone()[0]

    # --- Helpers ---

    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert database row to User object."""
        data = dict(row)
        data["metadata"] = json.loads(data.get("metadata") or "{}")
        return User.from_dict(data)

    def _row_to_department(self, row: sqlite3.Row) -> Department:
        """Convert database row to Department object."""
        return Department.from_dict(dict(row))


# Singleton instance
_user_repository: UserRepository | None = None


def get_user_repository() -> UserRepository:
    """Get singleton user repository."""
    global _user_repository
    if _user_repository is None:
        _user_repository = UserRepository()
    return _user_repository
