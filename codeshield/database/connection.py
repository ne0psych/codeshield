"""
CodeShield Database Connection Manager
Thread-safe SQLite connection pool with WAL mode.
"""

import sqlite3
import threading
import logging
from pathlib import Path
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("codeshield.database")


class DatabaseManager:
    """Thread-safe SQLite database manager with per-thread connections."""

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, timeout=30.0)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def get_connection(self):
        conn = self._get_connection()
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise

    @contextmanager
    def transaction(self):
        conn = self._get_connection()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def execute(self, sql: str, params: tuple = ()):
        return self._get_connection().execute(sql, params)

    def executemany(self, sql: str, params_list: list):
        return self._get_connection().executemany(sql, params_list)

    def fetchone(self, sql: str, params: tuple = ()):
        return self.execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()):
        return self.execute(sql, params).fetchall()

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


_db_manager: Optional[DatabaseManager] = None


def init_db(db_path: str) -> DatabaseManager:
    global _db_manager
    _db_manager = DatabaseManager(db_path)
    logger.info("Database initialized at %s", db_path)
    return _db_manager


def get_db() -> DatabaseManager:
    if _db_manager is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _db_manager
