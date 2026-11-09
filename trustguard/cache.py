"""Small SQLite TTL cache for network lookups (RDAP, TLS, threat intelligence, feeds).

Caching keeps the number of calls to free-tier APIs low and makes repeated scans of the same link deterministic within
the cache window. Values are JSON; keys are namespaced ("rdap:example.com").
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class TTLCache:
    def __init__(self, path: Path | str | None):
        self._lock = threading.Lock()
        self._mem: dict[str, tuple[float, Any]] = {}
        self._db: sqlite3.Connection | None = None
        if path is not None:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(p), check_same_thread=False)
            self._db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, expires REAL, value TEXT)")
            self._db.commit()

    def get(self, key: str) -> Any | None:
        now = time.time()
        with self._lock:
            if key in self._mem:
                exp, val = self._mem[key]
                if exp > now:
                    return val
                del self._mem[key]
            if self._db is None:
                return None
            row = self._db.execute("SELECT expires, value FROM cache WHERE key = ?", (key,)).fetchone()
            if not row:
                return None
            if row[0] <= now:
                self._db.execute("DELETE FROM cache WHERE key = ?", (key,))
                self._db.commit()
                return None
            val = json.loads(row[1])
            self._mem[key] = (row[0], val)
            return val

    def set(self, key: str, value: Any, ttl_s: float) -> None:
        exp = time.time() + ttl_s
        with self._lock:
            self._mem[key] = (exp, value)
            if self._db is not None:
                self._db.execute("INSERT OR REPLACE INTO cache (key, expires, value) VALUES (?, ?, ?)", (key, exp, json.dumps(value, default=str)))
                self._db.commit()

    def clear(self, prefix: str = "") -> int:
        with self._lock:
            n = 0
            for k in [k for k in self._mem if k.startswith(prefix)]:
                del self._mem[k]
            if self._db is not None:
                n = self._db.execute("DELETE FROM cache WHERE key LIKE ?", (prefix + "%",)).rowcount
                self._db.commit()
            return n

    def stats(self) -> dict[str, int]:
        with self._lock:
            if self._db is None:
                return {"entries": len(self._mem)}
            n = self._db.execute("SELECT COUNT(*) FROM cache WHERE expires > ?", (time.time(),)).fetchone()[0]
            return {"entries": int(n)}
