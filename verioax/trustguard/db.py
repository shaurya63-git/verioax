"""Database access shared by the accounts store (accounts, activity log, feedback) and the scan history.

Two engines, one code path:

* **SQLite** (default): one file per store in the data directory - nothing to install, right for one machine. Every
  thread gets its own connection; WAL journalling lets readers work while a writer commits, and a busy timeout makes a
  second writer wait for the first instead of failing. Transactions are short (one statement or one small unit).
* **PostgreSQL** (set ``VERIOAX_DATABASE_URL=postgresql://user:password@host:5432/verioax``): one shared database for
  several API workers, Streamlit servers or hosts, through a bounded connection pool (psycopg 3). Use it as soon as more
  than one process serves the same users: separate SQLite files would give every instance its own accounts and history.

SQL is written once with ``?`` placeholders; the PostgreSQL adapter rewrites them. Schema changes go through
``Database.migrate``: numbered steps recorded per component in a ``schema_migrations`` table, each applied once, in
order, inside a transaction. Before an existing SQLite database is migrated, a copy is written next to it.
"""
from __future__ import annotations

import atexit
import os
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class DatabaseError(RuntimeError):
    """The database could not be reached or a statement failed."""


class IntegrityError(DatabaseError):
    """A uniqueness or check constraint was violated (e.g. a username that already exists)."""


# observability hook: called with the exception type name whenever a statement fails (see trustguard.metrics)
on_error: Callable[[str], None] | None = None


@dataclass(frozen=True)
class Step:
    version: int
    description: str
    apply: Callable[[Conn], None]


class Conn:
    """A uniform wrapper over one DB-API connection inside a transaction."""

    def __init__(self, raw: Any, dialect: str):
        self.raw, self.dialect = raw, dialect

    def _sql(self, sql: str) -> str:
        if self.dialect == "postgres":
            return sql.replace("%", "%%").replace("?", "%s")
        return sql

    def execute(self, sql: str, params: tuple | list = ()) -> Any:
        try:
            cur = self.raw.execute(self._sql(sql), tuple(params))
        except Exception as exc:                        # map driver errors to ours, never echo SQL parameters
            raise _wrap(exc) from None
        return cur

    def query(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        cur = self.execute(sql, params)
        rows = cur.fetchall()
        if self.dialect == "sqlite":
            return [dict(r) for r in rows]
        return list(rows)

    def one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: tuple | list = ()) -> Any:
        row = self.one(sql, params)
        return next(iter(row.values())) if row else None

    def insert(self, sql: str, params: tuple | list = (), pk: str = "id") -> int:
        if self.dialect == "postgres":
            row = self.one(sql + f" RETURNING {pk}", params)
            return int(row[pk]) if row else 0
        return int(self.execute(sql, params).lastrowid or 0)

    def rowcount(self, sql: str, params: tuple | list = ()) -> int:
        return int(self.execute(sql, params).rowcount or 0)

    def columns(self, table: str) -> set[str]:
        if self.dialect == "postgres":
            return {r["column_name"] for r in self.query("SELECT column_name FROM information_schema.columns WHERE table_name = ?", (table,))}
        return {r["name"] for r in self.query(f"PRAGMA table_info({table})")}

    def tables(self) -> set[str]:
        if self.dialect == "postgres":
            return {r["table_name"] for r in self.query("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()")}
        return {r["name"] for r in self.query("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _wrap(exc: Exception) -> DatabaseError:
    name = type(exc).__name__
    if on_error is not None:
        try:
            on_error(name)
        except Exception:
            pass
    if isinstance(exc, sqlite3.IntegrityError) or name in ("UniqueViolation", "IntegrityError", "CheckViolation", "NotNullViolation"):
        return IntegrityError(name)
    if isinstance(exc, DatabaseError):
        return exc
    return DatabaseError(f"database error ({name})")


def _redact_url(url: str) -> str:
    return re.sub(r"//[^@/]*@", "//***@", url)


class Database:
    """A SQLite file or a PostgreSQL database. Thread-safe; cheap to share."""

    def __init__(self, target: str | Path, *, pool_size: int = 10, timeout_s: float = 10.0):
        t = str(target)
        self.timeout_s = timeout_s
        if t.startswith(("postgresql://", "postgres://")):
            self.dialect = "postgres"
            self.label = _redact_url(t)
            try:
                from psycopg.rows import dict_row
                from psycopg_pool import ConnectionPool
            except ImportError as exc:                  # pragma: no cover - depends on the installed extras
                raise DatabaseError("PostgreSQL support needs the 'postgres' extra: pip install 'psycopg[binary]' psycopg-pool") from exc
            self._pool = ConnectionPool(t, min_size=1, max_size=max(1, pool_size), timeout=timeout_s, open=True,
                                        kwargs={"row_factory": dict_row, "autocommit": False})
            self.path = None
        else:
            self.dialect = "sqlite"
            path = Path(t.removeprefix("sqlite:///"))
            path.parent.mkdir(parents=True, exist_ok=True)
            self.path = path
            self.label = str(path)
            self._local = threading.local()
            self._all: list[sqlite3.Connection] = []
            self._all_lock = threading.Lock()
            with self.tx() as c:                        # WAL is a property of the file: set it once
                c.execute("PRAGMA journal_mode=WAL")

    # ------------------------------------------------------------------ connections
    def _sqlite(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), timeout=self.timeout_s, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout = {int(self.timeout_s * 1000)}")
            conn.execute("PRAGMA synchronous = NORMAL")
            self._local.conn = conn
            with self._all_lock:
                self._all.append(conn)
        return conn

    @contextmanager
    def tx(self) -> Iterator[Conn]:
        """One short transaction: committed when the block ends, rolled back on any error."""
        if self.dialect == "postgres":
            try:
                ctx = self._pool.connection()
                raw = ctx.__enter__()
            except Exception as exc:
                raise _wrap(exc) from None
            try:
                yield Conn(raw, "postgres")
                raw.commit()
            except BaseException:
                raw.rollback()
                raise
            finally:
                ctx.__exit__(None, None, None)
            return
        raw = self._sqlite()
        try:
            yield Conn(raw, "sqlite")
            raw.commit()
        except BaseException:
            raw.rollback()
            raise

    # ------------------------------------------------------------------ one-statement helpers (each its own transaction)
    def query(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self.tx() as c:
            return c.query(sql, params)

    def one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        with self.tx() as c:
            return c.one(sql, params)

    def scalar(self, sql: str, params: tuple | list = ()) -> Any:
        with self.tx() as c:
            return c.scalar(sql, params)

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        with self.tx() as c:
            return c.rowcount(sql, params)

    def insert(self, sql: str, params: tuple | list = (), pk: str = "id") -> int:
        with self.tx() as c:
            return c.insert(sql, params, pk)

    # ------------------------------------------------------------------ schema
    def id_column(self) -> str:
        return "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY" if self.dialect == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"

    def migrate(self, component: str, steps: list[Step]) -> list[int]:
        """Apply the steps of ``component`` that haven't been applied yet. Returns the versions applied now."""
        with self.tx() as c:
            c.execute("CREATE TABLE IF NOT EXISTS schema_migrations (component TEXT NOT NULL, version INTEGER NOT NULL, "
                      "description TEXT, applied_at TEXT NOT NULL, PRIMARY KEY (component, version))")
            done = {r["version"] for r in c.query("SELECT version FROM schema_migrations WHERE component = ?", (component,))}
            had_data = bool(c.tables() - {"schema_migrations", "sqlite_sequence"})
        pending = [s for s in sorted(steps, key=lambda s: s.version) if s.version not in done]
        if pending and had_data and self.dialect == "sqlite":
            self.backup(self._backup_path(component, pending))
        applied = []
        for step in pending:
            with self.tx() as c:
                step.apply(c)
                c.execute("INSERT INTO schema_migrations (component, version, description, applied_at) VALUES (?, ?, ?, ?)",
                          (component, step.version, step.description, datetime.now(timezone.utc).isoformat(timespec="seconds")))
            applied.append(step.version)
        return applied

    def schema_version(self, component: str) -> int:
        try:
            return int(self.scalar("SELECT MAX(version) AS v FROM schema_migrations WHERE component = ?", (component,)) or 0)
        except DatabaseError:
            return 0

    # ------------------------------------------------------------------ maintenance
    def _backup_path(self, component: str, pending: list[Step]) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return self.path.with_name(f"{self.path.name}.pre-{component}-v{pending[0].version}-{stamp}.bak")

    def backup(self, dest: Path | str) -> Path:
        """Consistent copy of a SQLite database (online backup API: safe while the app is running)."""
        if self.dialect != "sqlite":
            raise DatabaseError("Use pg_dump to back up a PostgreSQL database.")
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        src = sqlite3.connect(str(self.path), timeout=self.timeout_s)
        try:
            out = sqlite3.connect(str(dest))
            try:
                src.backup(out)
            finally:
                out.close()
        finally:
            src.close()
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        return dest

    def ping(self) -> float:
        """Round-trip time of a trivial query, in milliseconds (health checks)."""
        t = time.perf_counter()
        self.scalar("SELECT 1 AS ok")
        return round((time.perf_counter() - t) * 1000, 2)

    def close(self) -> None:
        if self.dialect == "postgres":
            self._pool.close()
            return
        with self._all_lock:
            for conn in self._all:
                try:
                    conn.close()
                except Exception:
                    pass
            self._all.clear()
        self._local = threading.local()


# ---------------------------------------------------------------------------------------------- shared instances
_SHARED: dict[str, Database] = {}
_SHARED_LOCK = threading.Lock()


def open_database(settings, sqlite_name: str) -> Database:
    """The configured shared PostgreSQL database, or the SQLite file ``data_dir/sqlite_name``. Instances are reused."""
    url = settings.database_url.get_secret_value() if getattr(settings, "database_url", None) else None
    key = url or str(Path(settings.data_dir) / sqlite_name)
    with _SHARED_LOCK:
        db = _SHARED.get(key)
        if db is None:
            db = Database(key, pool_size=getattr(settings, "database_pool_size", 10))
            _SHARED[key] = db
        return db


@atexit.register
def close_all() -> None:
    """Close the shared databases (their pools' worker threads) when the process ends."""
    with _SHARED_LOCK:
        dbs = list(_SHARED.values())
        _SHARED.clear()
    for db in dbs:
        try:
            db.close()
        except Exception:
            pass
