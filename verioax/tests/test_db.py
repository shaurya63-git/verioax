"""Database layer: concurrent use of SQLite, and the same stores on PostgreSQL.

The PostgreSQL tests run when VERIOAX_TEST_POSTGRES_URL points at a disposable database, e.g.
    VERIOAX_TEST_POSTGRES_URL=postgresql://postgres@127.0.0.1:5432/verioax_test pytest tests/test_db.py
(CI starts one as a service container). Otherwise they are skipped."""
import os
import threading
import uuid

import pytest

from trustguard.accounts import AccountError, AccountStore
from trustguard.db import Database, IntegrityError
from trustguard.storage import ScanStore

PG_URL = os.environ.get("VERIOAX_TEST_POSTGRES_URL")
PIN = "424242"


def test_sqlite_handles_concurrent_writers_without_losing_rows(tmp_path):
    db = Database(tmp_path / "c.sqlite")
    db.execute("CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, worker INTEGER, n INTEGER)")
    errors = []

    def work(w):
        try:
            for n in range(50):
                db.insert("INSERT INTO t (worker, n) VALUES (?, ?)", (w, n))
        except Exception as exc:                        # pragma: no cover - the assertion below reports it
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(w,)) for w in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and db.scalar("SELECT COUNT(*) AS n FROM t") == 600


def test_concurrent_scan_saves_and_activity_writes(tmp_path, engine):
    store = AccountStore(tmp_path / "accounts.sqlite", moderator_pin=PIN)
    u = store.create_user("ravi", "ravi@example.com", "correct horse 42", "consumer")
    results = [engine.scan_message(f"Pay your pending e-challan {i} now: https://echallan-pay.vip/{i}", owner_id=u.id).result for i in range(4)]

    def work(r):
        for _ in range(5):
            engine.store.save(r, owner_id=u.id)
            store.record_scan(u, scan_id=r.scan_id, input_type="message", verdict=r.overall_risk.value)

    threads = [threading.Thread(target=work, args=(r,)) for r in results for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert engine.store.count(owner_id=u.id) == 4
    assert len([e for e in store.activity() if e["event"] == "scan"]) == 4


def test_integrity_errors_are_mapped(tmp_path):
    db = Database(tmp_path / "i.sqlite")
    db.execute("CREATE TABLE u (name TEXT UNIQUE)")
    db.execute("INSERT INTO u (name) VALUES (?)", ("a",))
    with pytest.raises(IntegrityError):
        db.execute("INSERT INTO u (name) VALUES (?)", ("a",))


# ----------------------------------------------------------------------------------------------- PostgreSQL
pg = pytest.mark.skipif(not PG_URL, reason="set VERIOAX_TEST_POSTGRES_URL to run the PostgreSQL tests")


@pytest.fixture
def pg_db():
    db = Database(PG_URL)
    with db.tx() as c:                                   # a clean schema for every test
        c.execute("DROP SCHEMA IF EXISTS public CASCADE")
        c.execute("CREATE SCHEMA public")
    yield db
    db.close()


@pg
def test_accounts_on_postgres(pg_db):
    store = AccountStore(pg_db, moderator_pin=PIN)
    u = store.create_user("Ravi", "ravi@example.com", "correct horse 42", "consumer")
    with pytest.raises(AccountError, match="taken"):
        store.create_user("RAVI", "other@example.com", "correct horse 42", "consumer")   # case-insensitive, like SQLite
    store.create_user("mod1", "mod1@example.com", "moderate this 7", "moderator", pin=PIN)
    assert store.authenticate("ravi@EXAMPLE.com", "correct horse 42", "consumer").login_count == 1
    with pytest.raises(AccountError):
        store.authenticate("ravi", "wrong one 12", "consumer")
    assert store.find("ravi").failed_attempts == 1 and not [r for r in store.activity() if r["event"] != "login"]
    for _ in range(2):
        store.record_scan(u, scan_id="VX-20261115-ABCDEF", input_type="url", verdict="HIGH")
    store.add_feedback(u, "feedback", "Hello there", "Just checking the feedback flow works.")
    assert sorted(r["event"] for r in store.activity()) == ["feedback", "login", "scan"]
    tr = store.traffic(days=3)
    assert tr["users"] == 2 and sum(d["scans"] for d in tr["series"].values()) == 1


@pg
def test_scan_history_on_postgres(pg_db, engine):
    st = ScanStore(pg_db)
    r = engine.scan_message("Your e-challan of Rs 500 is pending, pay now: https://parivahan-gov.in/pay", owner_id=7).result
    st.save(r, owner_id=7, idem_key="abc")
    st.save(r, owner_id=7, idem_key="abc")                          # upsert, not a duplicate
    assert st.count() == 1 and st.get(r.scan_id, owner_id=7).scan_id == r.scan_id and st.get(r.scan_id, owner_id=8) is None
    assert st.list(search="CHALLAN", owner_id=7)[0]["scam_type"] == r.scam_type
    assert st.by_idempotency_key(7, "abc").scan_id == r.scan_id and st.by_idempotency_key(8, "abc") is None
    assert st.delete(r.scan_id, owner_id=7) and st.count() == 0


@pg
def test_copy_sqlite_data_to_postgres(pg_db, tmp_path, settings, engine):
    from trustguard.dbtools import copy_to_postgres
    src = tmp_path / "src"
    a = AccountStore(src / "accounts.sqlite", moderator_pin=PIN)
    u = a.create_user("ravi", "ravi@example.com", "correct horse 42", "consumer")
    a.authenticate("ravi", "correct horse 42", "consumer")
    h = ScanStore(src / "history.sqlite")
    h.save(engine.scan_message("Mom, I reached Pune safely.").result, owner_id=u.id)
    pg_db.close()
    copied = copy_to_postgres(settings, PG_URL, data_dir=src)
    assert copied["users"] == 1 and copied["scans"] == 1 and copied["activity"] == 1
    dest = AccountStore(Database(PG_URL), moderator_pin=PIN)
    assert dest.authenticate("ravi", "correct horse 42", "consumer").id == u.id     # same id, same password hash
    new = dest.create_user(f"n{uuid.uuid4().hex[:6]}", f"{uuid.uuid4().hex[:6]}@example.com", "correct horse 42", "consumer")
    assert new.id > u.id                                             # sequences continue after the copied ids
