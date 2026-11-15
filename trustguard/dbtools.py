"""Database maintenance: ``python -m trustguard.dbtools <command>``.

    check              which database is in use, schema versions, row counts
    backup             consistent copies of the SQLite databases (accounts and history) into data_dir/backups
    prune-activity     back up, then delete activity entries of retired event types (page views, sign-outs, failed attempts ...)
    copy-to-postgres   copy accounts, activity, feedback, scan history and preferences from the SQLite files into PostgreSQL

Nothing here deletes data without writing a backup first. PostgreSQL databases are backed up with ``pg_dump``.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .accounts import ACTIVITY_EVENTS, AccountStore
from .config import Settings, get_settings
from .db import Database, DatabaseError, open_database
from .storage import ScanStore

_TABLES = {"users": "id", "activity": "id", "feedback": "id", "scans": "scan_id"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def check(settings: Settings) -> int:
    for name in ("accounts.sqlite", "history.sqlite"):
        db = open_database(settings, name)
        print(f"{name.split('.')[0]}: {db.dialect} - {db.label}")
        try:
            print(f"  ping {db.ping()} ms; schema accounts v{db.schema_version('accounts')}, scans v{db.schema_version('scans')}")
            with db.tx() as c:
                for table in sorted(c.tables() & set(_TABLES)):
                    print(f"  {table}: {c.scalar(f'SELECT COUNT(*) AS n FROM {table}')} row(s)")
        except DatabaseError as exc:
            print(f"  not reachable: {exc}")
            return 1
        if db.dialect == "postgres":
            break                                   # one shared database holds both
    return 0


def backup(settings: Settings, out: Path | None = None) -> list[Path]:
    out = out or Path(settings.data_dir) / "backups"
    made = []
    for name in ("accounts.sqlite", "history.sqlite"):
        db = open_database(settings, name)
        if db.dialect != "sqlite":
            print("PostgreSQL is configured: back it up with  pg_dump --format=custom \"$VERIOAX_DATABASE_URL\" > verioax.dump")
            return made
        if db.path and db.path.exists():
            made.append(db.backup(out / f"{db.path.stem}-{_stamp()}.sqlite"))
    for p in made:
        print(f"backup written: {p}")
    return made


def prune_activity(settings: Settings) -> int:
    store = AccountStore(open_database(settings, "accounts.sqlite"))
    n = store.legacy_activity_count()
    if not n:
        print("No retired activity entries - nothing to do.")
        return 0
    if store.db.dialect == "sqlite":
        print(f"backup written: {store.db.backup(Path(settings.data_dir) / 'backups' / f'accounts-before-prune-{_stamp()}.sqlite')}")
    removed = store.prune_legacy_activity()
    print(f"Removed {removed} entr{'y' if removed == 1 else 'ies'} that are no longer part of the activity log "
          f"(kept: {', '.join(ACTIVITY_EVENTS)}).")
    return 0


def copy_to_postgres(settings: Settings, target_url: str, data_dir: Path | None = None, force: bool = False) -> dict[str, int]:
    """Copy the SQLite databases of ``data_dir`` into the PostgreSQL database at ``target_url`` (ids preserved)."""
    src_dir = Path(data_dir or settings.data_dir)
    target = Database(target_url)
    AccountStore(target)                             # creates the schema (migrations) in the target
    ScanStore(target)
    with target.tx() as c:
        existing = int(c.scalar("SELECT COUNT(*) AS n FROM users") or 0) + int(c.scalar("SELECT COUNT(*) AS n FROM scans") or 0)
    if existing and not force:
        raise SystemExit("The target database already contains accounts or scans; refusing to mix data (use --force to append).")
    copied: dict[str, int] = {}
    sources = {"accounts.sqlite": ("users", "activity", "feedback"), "history.sqlite": ("scans",)}
    for fname, tables in sources.items():
        path = src_dir / fname
        if not path.exists():
            continue
        src = Database(path)
        AccountStore(src) if fname == "accounts.sqlite" else ScanStore(src)      # bring the source up to the current schema
        for table in tables:
            with src.tx() as s, target.tx() as t:
                cols = sorted(s.columns(table) & t.columns(table))
                rows = s.query(f"SELECT {', '.join(cols)} FROM {table}")
                for row in rows:
                    t.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({','.join('?' * len(cols))}) ON CONFLICT DO NOTHING",
                              [row[c] for c in cols])
                copied[table] = len(rows)
                if _TABLES[table] == "id" and rows:
                    t.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), (SELECT MAX(id) FROM {table}))")
        src.close()
    prefs = src_dir / "preferences.json"
    if prefs.exists():
        target.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT)")
        target.execute("INSERT INTO app_settings (key, value, updated_at) VALUES ('preferences', ?, ?) ON CONFLICT (key) DO NOTHING",
                       (prefs.read_text(encoding="utf-8"), datetime.now(timezone.utc).isoformat(timespec="seconds")))
        copied["preferences"] = 1
    target.close()
    return copied


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m trustguard.dbtools", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    b = sub.add_parser("backup")
    b.add_argument("--out", type=Path)
    sub.add_parser("prune-activity")
    cp = sub.add_parser("copy-to-postgres")
    cp.add_argument("--to", required=True, help="postgresql://user:password@host:5432/dbname")
    cp.add_argument("--data-dir", type=Path, help="folder with accounts.sqlite and history.sqlite (default: TRUSTGUARD_DATA_DIR)")
    cp.add_argument("--force", action="store_true", help="append even if the target already has data")
    args = ap.parse_args(argv)
    settings = get_settings()
    if args.cmd == "check":
        return check(settings)
    if args.cmd == "backup":
        backup(settings, args.out)
        return 0
    if args.cmd == "prune-activity":
        return prune_activity(settings)
    plain = settings.model_copy(update={"database_url": None})        # read from the SQLite files, whatever .env says
    print(f"copied: {copy_to_postgres(plain, args.to, args.data_dir, args.force)}")
    print("Now set VERIOAX_DATABASE_URL to the new database (and VERIOAX_SECRET_KEY to the same value on every server).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
