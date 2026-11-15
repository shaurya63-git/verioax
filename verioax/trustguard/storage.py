"""Scan history (SQLite file, or the shared PostgreSQL database - see ``trustguard.db``).

Only the audit-safe ``ScanResult`` is stored: redacted text, findings with placeholders and hashes, defanged links.
The original message and the placeholder -> value map are never written to disk. Retention is enforced on every save.

A scan can carry an *idempotency key* (the API's ``Idempotency-Key`` header): a retried request with the same key from
the same account gets the stored result back instead of a second scan.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .db import Conn, Database, Step
from .schemas import RiskLevel, ScanResult

_COLS = ("scan_id", "created_at", "input_type", "mode", "source_name", "overall_risk", "risk_basis", "risk_score", "confidence", "pii_count",
         "scam_count", "url_count", "suspicious_urls", "categories", "pii_types", "verdict", "status", "demo", "result_json", "owner_id",
         "scam_type", "idem_key")
_LIST_COLS = ("scan_id, created_at, input_type, mode, source_name, overall_risk, risk_basis, risk_score, confidence, pii_count, scam_count, "
              "url_count, suspicious_urls, categories, pii_types, verdict, status, demo, scam_type")


def _v1_baseline(c: Conn) -> None:
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input_type TEXT NOT NULL, mode TEXT NOT NULL, source_name TEXT,
        overall_risk TEXT NOT NULL, risk_basis TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence REAL NOT NULL, pii_count INTEGER NOT NULL,
        scam_count INTEGER NOT NULL, url_count INTEGER NOT NULL, suspicious_urls INTEGER NOT NULL, categories TEXT NOT NULL, pii_types TEXT NOT NULL,
        verdict TEXT NOT NULL, status TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0, result_json TEXT NOT NULL, owner_id INTEGER)""")
    if "owner_id" not in c.columns("scans"):                    # databases created before accounts existed (scans stay unowned)
        c.execute("ALTER TABLE scans ADD COLUMN owner_id INTEGER")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner ON scans(owner_id)")


def _v2_type_and_idempotency(c: Conn) -> None:
    have = c.columns("scans")
    for col in ("scam_type", "idem_key"):
        if col not in have:
            c.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_scans_idem ON scans(owner_id, idem_key) WHERE idem_key IS NOT NULL")
    c.execute("CREATE INDEX IF NOT EXISTS idx_scans_owner_created ON scans(owner_id, created_at)")


MIGRATIONS = [Step(1, "scans table", _v1_baseline), Step(2, "scam type; idempotency key", _v2_type_and_idempotency)]


class ScanStore:
    def __init__(self, path: Path | str | Database):
        self.db = path if isinstance(path, Database) else Database(path)
        self.path = self.db.path
        self.db.migrate("scans", MIGRATIONS)

    @staticmethod
    def _owner_sql(owner_id: int | None) -> tuple[str, tuple]:
        return (" AND owner_id = ?", (owner_id,)) if owner_id is not None else ("", ())

    # ------------------------------------------------------------------ write
    def save(self, r: ScanResult, retention_days: int | None = None, owner_id: int | None = None, idem_key: str | None = None) -> None:
        sf = r.scam_findings
        cats = sorted({f.category.value for f in sf if f.severity.value != "info"})
        susp_urls = sum(u.final_assessment in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL) for u in r.urls)
        status = r.pii.status if r.pii else "n/a"
        row = (r.scan_id, r.created_at.isoformat(), r.input_type.value, r.mode.value, r.source_name, r.overall_risk.value, r.risk_basis,
               r.risk_score, r.model_confidence, len(r.pii_findings), sum(f.severity.value != "info" for f in sf), len(r.urls), susp_urls,
               json.dumps(cats), json.dumps(sorted(r.pii.by_type) if r.pii else []), r.verdict_title, status, int(r.processing.demo),
               r.model_dump_json(), owner_id, r.scam_type, idem_key)
        update = ", ".join(f"{c} = excluded.{c}" for c in _COLS if c not in ("scan_id", "idem_key"))
        with self.db.tx() as c:
            c.execute(f"INSERT INTO scans ({', '.join(_COLS)}) VALUES ({','.join('?' * len(_COLS))}) "
                      f"ON CONFLICT (scan_id) DO UPDATE SET {update}", row)
        if retention_days:
            self.purge_older_than(retention_days)

    def delete(self, scan_id: str, owner_id: int | None = None) -> bool:
        extra, args = self._owner_sql(owner_id)
        return self.db.execute("DELETE FROM scans WHERE scan_id = ?" + extra, (scan_id, *args)) > 0

    def purge_older_than(self, days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return self.db.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))

    def clear(self, demo_only: bool = False, owner_id: int | None = None) -> int:
        extra, args = self._owner_sql(owner_id)
        return self.db.execute("DELETE FROM scans WHERE 1=1" + (" AND demo = 1" if demo_only else "") + extra, args)

    # ------------------------------------------------------------------ read
    def get(self, scan_id: str, owner_id: int | None = None) -> ScanResult | None:
        extra, args = self._owner_sql(owner_id)
        row = self.db.one("SELECT result_json FROM scans WHERE scan_id = ?" + extra, (scan_id, *args))
        return ScanResult.model_validate_json(row["result_json"]) if row else None

    def by_idempotency_key(self, owner_id: int | None, idem_key: str, max_age_s: int = 24 * 3600) -> ScanResult | None:
        """The scan an earlier request with the same key (and owner) produced, if it is recent enough."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age_s)).isoformat()
        owner_sql = "owner_id = ?" if owner_id is not None else "owner_id IS NULL"
        args = (owner_id, idem_key, cutoff) if owner_id is not None else (idem_key, cutoff)
        row = self.db.one(f"SELECT result_json FROM scans WHERE {owner_sql} AND idem_key = ? AND created_at >= ?", args)
        return ScanResult.model_validate_json(row["result_json"]) if row else None

    def list(self, *, limit: int = 500, risk: list[str] | None = None, input_type: list[str] | None = None,
             category: str | None = None, since: datetime | None = None, until: datetime | None = None,
             search: str | None = None, owner_id: int | None = None) -> list[dict[str, Any]]:
        sql = f"SELECT {_LIST_COLS} FROM scans WHERE 1=1"
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
            sql += " AND (lower(scan_id) LIKE lower(?) OR lower(verdict) LIKE lower(?) OR lower(source_name) LIKE lower(?))"
            args += [f"%{search}%"] * 3
        if owner_id is not None:
            sql += " AND owner_id = ?"
            args.append(owner_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(limit)
        out = []
        for d in self.db.query(sql, args):
            d["categories"] = json.loads(d["categories"])
            d["pii_types"] = json.loads(d["pii_types"])
            d["demo"] = bool(d["demo"])
            out.append(d)
        return out

    def results(self, limit: int = 500, owner_id: int | None = None) -> list[ScanResult]:
        extra, args = self._owner_sql(owner_id)
        rows = self.db.query("SELECT result_json FROM scans WHERE 1=1" + extra + " ORDER BY created_at DESC LIMIT ?", (*args, limit))
        return [ScanResult.model_validate_json(r["result_json"]) for r in rows]

    def count(self, owner_id: int | None = None) -> int:
        extra, args = self._owner_sql(owner_id)
        return int(self.db.scalar("SELECT COUNT(*) AS n FROM scans WHERE 1=1" + extra, args) or 0)
