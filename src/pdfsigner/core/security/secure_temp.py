"""
secure_temp.py - Secure temporary file handling

Author: Homero Thompson del Lago del Terror

Provides secure temporary file and directory management with HIPAA-compliant
deletion (DoD 5220.22-M standard) for device and media controls per
§164.310(d)(1).
"""

import os
import secrets
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from loguru import logger


@dataclass
class TempFileInfo:
    """Metadata about a secure temp file."""

    path: Path
    created_at: datetime = field(default_factory=datetime.now)
    size_bytes: int = 0
    secure_deleted: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "path": str(self.path),
            "created_at": self.created_at.isoformat(),
            "size_bytes": self.size_bytes,
            "secure_deleted": self.secure_deleted,
        }


class SecureTempFile:
    """
    Context manager for secure temporary files.

    Features:
    - Random filename generation (cryptographically secure)
    - Secure deletion (overwrite before delete per DoD 5220.22-M)
    - Audit logging of file operations
    - Automatic cleanup on exit/exception
    - Restricted permissions (600)

    Usage:
        with SecureTempFile(suffix=".pdf") as temp_path:
            # Write to temp_path
            temp_path.write_bytes(data)
        # File is securely deleted here

    HIPAA Compliance:
    - §164.310(d)(1) - Device and media controls
    - §164.310(d)(2)(i) - Disposal
    """

    OVERWRITE_PASSES = 3  # DoD 5220.22-M standard

    def __init__(
        self,
        suffix: str = "",
        prefix: str = "pdfsigner_",
        dir: Path | None = None,
        delete: bool = True,
    ):
        """
        Initialize secure temp file.

        Args:
            suffix: File suffix (e.g., ".pdf")
            prefix: File prefix (default: "pdfsigner_")
            dir: Directory for temp file (default: secure temp dir)
            delete: Whether to delete file on exit (default: True)
        """
        self._suffix = suffix
        self._prefix = prefix
        self._dir = dir or self._get_secure_temp_dir()
        self._delete = delete
        self._path: Path | None = None
        self._info: TempFileInfo | None = None

    def __enter__(self) -> Path:
        """Create and return secure temp file path."""
        # Create secure random filename
        random_part = secrets.token_hex(16)
        filename = f"{self._prefix}{random_part}{self._suffix}"
        self._path = self._dir / filename

        # Create empty file with restricted permissions (600)
        self._path.touch(mode=0o600)

        self._info = TempFileInfo(path=self._path)
        logger.debug(f"Created secure temp file: {self._path.name}")

        return self._path

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Securely delete temp file on exit."""
        if self._delete and self._path and self._path.exists():
            self._secure_delete(self._path)
            if self._info:
                self._info.secure_deleted = True
            logger.debug(f"Securely deleted temp file: {self._path.name}")

    def _secure_delete(self, path: Path) -> None:
        """
        Securely delete file by overwriting with random data.

        Follows DoD 5220.22-M standard (3 passes):
        - Pass 1: Overwrite with zeros
        - Pass 2: Overwrite with ones
        - Pass 3: Overwrite with random data

        Args:
            path: Path to file to delete
        """
        if not path.exists():
            return

        try:
            file_size = path.stat().st_size

            if file_size > 0:
                with open(path, "r+b") as f:
                    for pass_num in range(self.OVERWRITE_PASSES):
                        f.seek(0)
                        # Pass 1: zeros, Pass 2: ones, Pass 3: random
                        if pass_num == 0:
                            data = b"\x00" * file_size
                        elif pass_num == 1:
                            data = b"\xff" * file_size
                        else:
                            data = secrets.token_bytes(file_size)
                        f.write(data)
                        f.flush()
                        os.fsync(f.fileno())

            # Finally delete
            path.unlink()
        except Exception as e:
            logger.error(f"Failed to securely delete {path}: {e}")
            # Still try to delete normally
            try:
                path.unlink()
            except Exception:
                pass

    def _get_secure_temp_dir(self) -> Path:
        """
        Get or create secure temp directory.

        Prefers XDG_RUNTIME_DIR (RAM-based, user-private) if available,
        otherwise falls back to system temp dir with restricted permissions.

        Returns:
            Path to secure temp directory
        """
        # Use XDG runtime dir if available (RAM-based, user-private)
        xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
        if xdg_runtime:
            temp_dir = Path(xdg_runtime) / "pdfsigner"
        else:
            temp_dir = Path(tempfile.gettempdir()) / "pdfsigner"

        temp_dir.mkdir(parents=True, exist_ok=True)
        # Ensure directory has restricted permissions (700)
        temp_dir.chmod(0o700)

        return temp_dir


@contextmanager
def secure_temp_file(
    suffix: str = "",
    prefix: str = "pdfsigner_",
) -> Generator[Path, None, None]:
    """
    Functional interface for SecureTempFile.

    Args:
        suffix: File suffix (e.g., ".pdf")
        prefix: File prefix (default: "pdfsigner_")

    Yields:
        Path to secure temp file

    Example:
        with secure_temp_file(suffix=".pdf") as temp_path:
            temp_path.write_bytes(pdf_data)
    """
    with SecureTempFile(suffix=suffix, prefix=prefix) as path:
        yield path


class SecureTempDirectory:
    """
    Context manager for secure temporary directories.

    All files inside are securely deleted on exit.

    Usage:
        with SecureTempDirectory() as temp_dir:
            # Create files in temp_dir
            (temp_dir / "file.txt").write_text("data")
        # Directory and all contents are securely deleted here
    """

    def __init__(self, prefix: str = "pdfsigner_"):
        """
        Initialize secure temp directory.

        Args:
            prefix: Directory name prefix (default: "pdfsigner_")
        """
        self._prefix = prefix
        self._path: Path | None = None

    def __enter__(self) -> Path:
        """Create and return secure temp directory path."""
        random_part = secrets.token_hex(8)
        base_dir = Path(tempfile.gettempdir()) / "pdfsigner"
        base_dir.mkdir(parents=True, exist_ok=True)

        self._path = base_dir / f"{self._prefix}{random_part}"
        self._path.mkdir(mode=0o700)

        logger.debug(f"Created secure temp directory: {self._path.name}")
        return self._path

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Securely delete directory and all contents on exit."""
        if self._path and self._path.exists():
            self._secure_delete_directory(self._path)
            logger.debug(f"Securely deleted temp directory: {self._path.name}")

    def _secure_delete_directory(self, dir_path: Path) -> None:
        """
        Recursively secure-delete all files then remove directory.

        Args:
            dir_path: Path to directory to delete
        """
        secure_file = SecureTempFile()

        # Recursively delete all files
        for item in dir_path.rglob("*"):
            if item.is_file():
                secure_file._secure_delete(item)

        # Remove empty directories (bottom-up)
        for item in sorted(dir_path.rglob("*"), reverse=True):
            if item.is_dir():
                try:
                    item.rmdir()
                except OSError as e:
                    logger.warning(f"Failed to remove directory {item}: {e}")

        # Remove the top-level directory
        try:
            dir_path.rmdir()
        except OSError as e:
            logger.warning(f"Failed to remove directory {dir_path}: {e}")


@contextmanager
def secure_temp_directory(
    prefix: str = "pdfsigner_",
) -> Generator[Path, None, None]:
    """
    Functional interface for SecureTempDirectory.

    Args:
        prefix: Directory name prefix (default: "pdfsigner_")

    Yields:
        Path to secure temp directory

    Example:
        with secure_temp_directory() as temp_dir:
            (temp_dir / "file.txt").write_text("data")
    """
    with SecureTempDirectory(prefix=prefix) as path:
        yield path
