"""
base_repository.py - Base SQLite repository with shared connection boilerplate

Provides common __init__ and _get_connection() for all SQLite-backed repositories.
"""

import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


class BaseSQLiteRepository(ABC):
    """
    Base class for SQLite-backed repositories.

    Provides:
    - Default db_path under ~/.config/pdfsigner/
    - Context-managed connection with commit/rollback/close
    - Abstract _init_schema() for subclass table creation

    Thread-safe with connection-per-operation pattern.
    """

    def __init__(self, db_path: Path | None = None, default_db_name: str = "data.db"):
        """
        Initialize repository.

        Args:
            db_path: Path to SQLite database. Default: ~/.config/pdfsigner/{default_db_name}
            default_db_name: Default database filename when db_path is None
        """
        if db_path is None:
            config_dir = Path.home() / ".config" / "pdfsigner"
            config_dir.mkdir(parents=True, exist_ok=True)
            db_path = config_dir / default_db_name

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

    @abstractmethod
    def _init_schema(self) -> None:
        """Initialize database schema. Subclasses must implement."""
