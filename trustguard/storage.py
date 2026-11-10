"""Scan history (SQLite).

Only the audit-safe ``ScanResult`` is stored: redacted text, findings with placeholders and hashes, defanged links.
The original message and the placeholder -> value map are never written to disk. Retention is enforced on every save.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .schemas import RiskLevel, ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    input_type TEXT NOT NULL,
    mode TEXT NOT NULL,
    source_name TEXT,
    overall_risk TEXT NOT NULL,
    risk_basis TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence REAL NOT NULL,
    pii_count INTEGER NOT NULL,
    scam_count INTEGER NOT NULL,
    url_count INTEGER NOT NULL,
    suspicious_urls INTEGER NOT NULL,
    categories TEXT NOT NULL,
    pii_types TEXT NOT NULL,
    verdict TEXT NOT NULL,
    status TEXT NOT NULL,
    demo INTEGER NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL,
    owner_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
"""
_COLS = ("scan_id, created_at, input_type, mode, source_name, overall_risk, risk_basis, risk_score, confidence, pii_count, scam_count, "
         "url_count, suspicious_urls, categories, pii_types, verdict, status, demo, result_json, owner_id")


class ScanStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(_SCHEMA)
        # databases created before accounts existed: add the owner column (existing scans stay unowned)
        if "owner_id" not in {r[1] for r in self._db.execute("PRAGMA table_info(scans)")}:
            self._db.execute("ALTER TABLE scans ADD COLUMN owner_id INTEGER")
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id)")
        self._db.commit()

    @staticmethod
    def _owner_sql(owner_id: int | None) -> tuple[str, tuple]:
        return (" AND owner_id = ?", (owner_id,)) if owner_id is not None else ("", ())

    # ------------------------------------------------------------------ write
    def save(self, r: ScanResult, retention_days: int | None = None, owner_id: int | None = None) -> None:
        sf = r.scam_findings
        cats = sorted({f.category.value for f in sf if f.severity.value != "info"})
        susp_urls = sum(u.final_assessment in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL) for u in r.urls)
        status = r.pii.status if r.pii else "n/a"
        row = (r.scan_id, r.created_at.isoformat(), r.input_type.value, r.mode.value, r.source_name, r.overall_risk.value, r.risk_basis,
               r.risk_score, r.model_confidence, len(r.pii_findings), sum(f.severity.value != "info" for f in sf), len(r.urls), susp_urls,
               json.dumps(cats), json.dumps(sorted(r.pii.by_type) if r.pii else []), r.verdict_title, status, int(r.processing.demo),
               r.model_dump_json(), owner_id)
        with self._lock:
            self._db.execute(f"INSERT OR REPLACE INTO scans ({_COLS}) VALUES ({','.join('?' * 20)})", row)
            self._db.commit()
        if retention_days:
            self.purge_older_than(retention_days)

    def delete(self, scan_id: str, owner_id: int | None = None) -> bool:
        extra, args = self._owner_sql(owner_id)
        with self._lock:
            n = self._db.execute("DELETE FROM scans WHERE scan_id = ?" + extra, (scan_id, *args)).rowcount
            self._db.commit()
        return n > 0

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            n = self._db.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,)).rowcount
            self._db.commit()
        return n

    def clear(self, demo_only: bool = False, owner_id: int | None = None) -> int:
        extra, args = self._owner_sql(owner_id)
        with self._lock:
            n = self._db.execute("DELETE FROM scans WHERE 1=1" + (" AND demo = 1" if demo_only else "") + extra, args).rowcount
            self._db.commit()
        return n

    # ------------------------------------------------------------------ read
    def get(self, scan_id: str, owner_id: int | None = None) -> ScanResult | None:
        extra, args = self._owner_sql(owner_id)
        with self._lock:
            row = self._db.execute("SELECT result_json FROM scans WHERE scan_id = ?" + extra, (scan_id, *args)).fetchone()
        return ScanResult.model_validate_json(row["result_json"]) if row else None

    def list(self, *, limit: int = 500, risk: list[str] | None = None, input_type: list[str] | None = None,
             category: str | None = None, since: datetime | None = None, until: datetime | None = None,
             search: str | None = None, owner_id: int | None = None) -> list[dict[str, Any]]:
        sql = ("SELECT scan_id, created_at, input_type, mode, source_name, overall_risk, risk_basis, risk_score, confidence, pii_count, "
               "scam_count, url_count, suspicious_urls, categories, pii_types, verdict, status, demo FROM scans WHERE 1=1")
        args: list[Any] = []
        if risk:
            sql += f" AND overall_risk IN ({','.join('?' * len(risk))})"
            args += risk
        if input_type:
            sql += f" AND input_type IN ({','.join('?' * len(input_type))})"
            args += input_type
        if category:
            sql += " AND categories LIKE ?"
            args.append(f'%"{category}"%')
        if since:
            sql += " AND created_at >= ?"
            args.append(since.isoformat())
        if until:
            sql += " AND created_at <= ?"
            args.append(until.isoformat())
        if search:
            sql += " AND (scan_id LIKE ? OR verdict LIKE ? OR source_name LIKE ?)"
            args += [f"%{search}%"] * 3
        if owner_id is not None:
            sql += " AND owner_id = ?"
            args.append(owner_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["categories"] = json.loads(d["categories"])
            d["pii_types"] = json.loads(d["pii_types"])
            d["demo"] = bool(d["demo"])
            out.append(d)
        return out

    def results(self, limit: int = 500, owner_id: int | None = None) -> list[ScanResult]:
        extra, args = self._owner_sql(owner_id)
        with self._lock:
            rows = self._db.execute("SELECT result_json FROM scans WHERE 1=1" + extra + " ORDER BY created_at DESC LIMIT ?",
                                    (*args, limit)).fetchall()
        return [ScanResult.model_validate_json(r["result_json"]) for r in rows]

    def count(self, owner_id: int | None = None) -> int:
        extra, args = self._owner_sql(owner_id)
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) FROM scans WHERE 1=1" + extra, args).fetchone()[0])
