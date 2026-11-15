import sqlite3

import pytest

from trustguard.accounts import (
    GENERIC_LOGIN_ERROR,
    MAX_FAILED,
    SIGNUP_PIN_MAX_FAILURES,
    AccountError,
    AccountStore,
    hash_password,
    password_problems,
    verify_password,
)
from trustguard.storage import ScanStore

PIN = "424242"          # test PIN; the real one lives in .env, never in the code


def store_epoch():
    from datetime import datetime, timezone
    return datetime(2000, 1, 1, tzinfo=timezone.utc)


def redact(text: str) -> str:
    from trustguard.pii import analyze_pii
    return analyze_pii(text)[1].redacted_text


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path / "accounts.sqlite", moderator_pin=PIN, redact=redact)


def consumer(store, name="ravi", email="ravi@example.com", pw="correct horse 42"):
    return store.create_user(name, email, pw, "consumer", confirm=pw)


def moderator(store, name="mod1", email="mod1@example.com", pw="moderate this 7"):
    return store.create_user(name, email, pw, "moderator", pin=PIN, confirm=pw)


# ----------------------------------------------------------------------------------------------- passwords
def test_password_hash_is_salted_scrypt_and_verifies():
    a, b = hash_password("correct horse 42"), hash_password("correct horse 42")
    assert a != b and a.startswith("scrypt$16384$8$5$")
    assert verify_password("correct horse 42", a) and not verify_password("correct horse 43", a)
    assert not verify_password("x", "not-a-hash")


@pytest.mark.parametrize("pw,expect", [("short1", "8 characters"), ("password123", "too common"), ("aaaaaaaaaa", "too common"),
                                       ("ravi-is-great", "username")])
def test_password_policy(pw, expect):
    assert any(expect in p for p in password_problems(pw, "ravi", "ravi@example.com"))


# ----------------------------------------------------------------------------------------------- sign-up
def test_consumer_signup_and_uniqueness(store):
    u = consumer(store)
    assert u.role == "consumer" and u.status == "active" and u.email == "ravi@example.com"
    with pytest.raises(AccountError, match="username is already taken"):
        consumer(store, name="RAVI", email="other@example.com")
    with pytest.raises(AccountError, match="email already exists"):
        consumer(store, name="ravi2", email="Ravi@Example.com")
    with pytest.raises(AccountError, match="don't match"):
        store.create_user("neha", "neha@example.com", "long enough 12", "consumer", confirm="different 12")


def test_moderator_signup_needs_the_right_pin(store):
    with pytest.raises(AccountError, match="PIN is incorrect"):
        store.create_user("mod1", "mod1@example.com", "moderate this 7", "moderator", pin="000000")
    assert store.count("moderator") == 0
    assert store.activity() == []                                   # a wrong PIN is not an activity entry ...
    assert store._security_count("signup_pin_failed", store_epoch()) == 1   # ... it is an internal security counter
    m = moderator(store)
    assert m.is_moderator


def test_moderator_signup_is_disabled_without_a_configured_pin(tmp_path):
    s = AccountStore(tmp_path / "a.sqlite", moderator_pin=None)
    with pytest.raises(AccountError, match="VERIOAX_MODERATOR_PIN"):
        s.create_user("mod1", "mod1@example.com", "moderate this 7", "moderator", pin="135790")
    assert not AccountStore(tmp_path / "b.sqlite", moderator_pin="12345").pin_configured     # must be exactly 6 digits


def test_repeated_wrong_signup_pins_pause_moderator_signup(store):
    for i in range(SIGNUP_PIN_MAX_FAILURES):
        with pytest.raises(AccountError, match="PIN is incorrect"):
            store.create_user(f"mod{i}", f"mod{i}@example.com", "moderate this 7", "moderator", pin=f"{i:06d}")
    with pytest.raises(AccountError, match="paused"):
        moderator(store)                                     # even the right PIN waits: guessing 10^6 PINs becomes impractical


# ----------------------------------------------------------------------------------------------- sign-in
def test_login_by_username_or_email(store):
    consumer(store)
    assert store.authenticate("ravi", "correct horse 42", "consumer").login_count == 1
    assert store.authenticate("RAVI@example.com", "correct horse 42", "consumer").login_count == 2


def test_errors_do_not_reveal_whether_an_account_exists(store):
    consumer(store)
    with pytest.raises(AccountError) as unknown:
        store.authenticate("nobody", "whatever 123", "consumer")
    with pytest.raises(AccountError) as wrong:
        store.authenticate("ravi", "wrong password 1", "consumer")
    assert str(unknown.value) == str(wrong.value) == GENERIC_LOGIN_ERROR


def test_lockout_after_repeated_failures(store):
    consumer(store)
    for _ in range(MAX_FAILED - 1):
        with pytest.raises(AccountError, match="Incorrect"):
            store.authenticate("ravi", "wrong password 1", "consumer")
    with pytest.raises(AccountError, match="locked"):
        store.authenticate("ravi", "wrong password 1", "consumer")
    with pytest.raises(AccountError, match="locked"):               # even the right password is refused while locked
        store.authenticate("ravi", "correct horse 42", "consumer")
    assert store.find("ravi").account_state() == "locked"


def test_roles_and_the_moderator_pin_at_sign_in(store):
    consumer(store)
    moderator(store)
    with pytest.raises(AccountError, match="consumer account"):
        store.authenticate("ravi", "correct horse 42", "moderator", pin=PIN)
    with pytest.raises(AccountError, match="moderator account"):
        store.authenticate("mod1", "moderate this 7", "consumer")
    with pytest.raises(AccountError, match="PIN is incorrect"):
        store.authenticate("mod1", "moderate this 7", "moderator", pin="111111")
    assert store.find("mod1").failed_attempts == 1
    assert store.authenticate("mod1", "moderate this 7", "moderator", pin=PIN).is_moderator


def test_suspended_accounts_cannot_sign_in_and_only_moderators_can_suspend(store):
    u, m = consumer(store), moderator(store)
    with pytest.raises(AccountError, match="moderators"):
        store.set_status(u, m.id, "suspended")
    with pytest.raises(AccountError, match="own account"):
        store.set_status(m, m.id, "suspended")
    store.set_status(m, u.id, "suspended")
    with pytest.raises(AccountError, match="suspended"):
        store.authenticate("ravi", "correct horse 42", "consumer")
    store.set_status(m, u.id, "active")
    assert store.authenticate("ravi", "correct horse 42", "consumer")


def test_change_password(store):
    u = consumer(store)
    with pytest.raises(AccountError, match="current password"):
        store.change_password(u, "nope nope 1", "brand new pass 9", "brand new pass 9")
    store.change_password(u, "correct horse 42", "brand new pass 9", "brand new pass 9")
    assert store.authenticate("ravi", "brand new pass 9", "consumer")


# ----------------------------------------------------------------------------------------------- feedback and traffic
def test_feedback_is_redacted_and_moderated(store):
    u, m = consumer(store), moderator(store)
    fid = store.add_feedback(u, "wrong_result", "Missed a scam",
                             "My uncle Ravi Kumar got this on 9876543210 and it was rated low.", scan_id="VX-20261110-ABC123")
    fb = store.feedback()[0]
    assert fb["id"] == fid and "9876543210" not in fb["message"] and "[PHONE_" in fb["message"] and fb["scan_id"] == "VX-20261110-ABC123"
    with pytest.raises(AccountError, match="moderators"):
        store.update_feedback(u, fid, status="resolved")
    store.update_feedback(m, fid, status="resolved", reply="Thanks - fixed in the next rule update.")
    fb = store.feedback(user_id=u.id)[0]
    assert fb["status"] == "resolved" and fb["replied_by"] == "mod1"
    assert store.feedback_counts()["resolved"] == 1
    with pytest.raises(AccountError, match="subject"):
        store.add_feedback(u, "feedback", "x", "long enough message here")


def test_traffic_and_account_overview(store):
    u = consumer(store)
    moderator(store)
    store.authenticate("ravi", "correct horse 42", "consumer")
    store.record_scan(u, scan_id="VX-20261110-AAAAAA", input_type="message", verdict="HIGH")
    store.add_feedback(u, "feedback", "Works well", "The link report explained everything clearly.")
    tr = store.traffic(days=7)
    today = max(tr["series"])
    assert tr["users"] == 2 and tr["consumers"] == 1 and tr["moderators"] == 1 and tr["new_this_week"] == 2
    assert tr["series"][today] == {"logins": 1, "scans": 1, "feedback": 1, "active_users": 1}
    row = next(r for r in store.list_users() if r["username"] == "ravi")
    assert row["scans"] == 1 and row["feedback"] == 1 and row["state"] in ("online", "active")


# ----------------------------------------------------------------------------------------------- per-account scan history
def test_scan_history_is_per_account(engine):
    a = engine.scan_message("Your e-challan of Rs 500 is pending, pay now: https://parivahan-gov.in/pay", owner_id=1).result
    b = engine.scan_message("Mom, I reached Pune safely.", owner_id=2).result
    st = engine.store
    assert [r["scan_id"] for r in st.list(owner_id=1)] == [a.scan_id]
    assert st.get(b.scan_id, owner_id=1) is None and st.get(b.scan_id, owner_id=2) is not None
    assert not st.delete(b.scan_id, owner_id=1) and st.count() == 2
    assert {r.scan_id for r in st.results(owner_id=None)} == {a.scan_id, b.scan_id}


def test_old_history_database_gains_an_owner_column(tmp_path):
    path = tmp_path / "history.sqlite"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, input_type TEXT NOT NULL, mode TEXT NOT NULL, "
               "source_name TEXT, overall_risk TEXT NOT NULL, risk_basis TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence REAL NOT NULL, "
               "pii_count INTEGER NOT NULL, scam_count INTEGER NOT NULL, url_count INTEGER NOT NULL, suspicious_urls INTEGER NOT NULL, "
               "categories TEXT NOT NULL, pii_types TEXT NOT NULL, verdict TEXT NOT NULL, status TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0, "
               "result_json TEXT NOT NULL)")
    db.commit()
    db.close()
    ScanStore(path)
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(scans)")}
    assert "owner_id" in cols


def test_signing_out_ends_online_status(store):
    u = consumer(store)
    u = store.authenticate("ravi", "correct horse 42", "consumer")
    assert store.get(u.id).online()
    store.signed_out(u)
    assert not store.get(u.id).online() and store.get(u.id).account_state() == "active"
    store.authenticate("ravi", "correct horse 42", "consumer")
    assert store.get(u.id).online()


# ----------------------------------------------------------------------------------------------- the moderators' activity log
def events(store):
    return [r["event"] for r in store.activity(limit=1000)]


def test_activity_log_holds_only_logins_scans_and_feedback(store):
    u, m = consumer(store), moderator(store)
    assert events(store) == []                                       # creating accounts is not activity
    store.authenticate("ravi", "correct horse 42", "consumer")
    assert events(store) == ["login"]                                # one successful sign-in -> exactly one entry
    with pytest.raises(AccountError):
        store.authenticate("ravi", "wrong password 1", "consumer")    # failed sign-in -> nothing
    with pytest.raises(AccountError):
        store.authenticate("nobody", "whatever 123", "consumer")
    with pytest.raises(AccountError):
        store.authenticate("mod1", "moderate this 7", "moderator", pin="000000")   # wrong PIN -> nothing
    store.signed_out(u)                                              # sign-out -> nothing
    store.touch(u)
    store.change_password(u, "correct horse 42", "brand new pass 9", "brand new pass 9")
    store.set_status(m, u.id, "suspended")                           # moderator actions -> nothing
    store.set_status(m, u.id, "active")
    store.unlock(m, u.id)
    assert events(store) == ["login"]
    assert store.record_scan(u, scan_id="VX-20261115-ABCDEF", input_type="url", verdict="HIGH")
    fid = store.add_feedback(u, "complaint", "Rated wrongly", "This link was rated high but it is my bank's real site.")
    store.update_feedback(m, fid, status="resolved", reply="Thanks, we'll look at it.")   # reply -> nothing
    assert sorted(events(store)) == ["feedback", "login", "scan"]
    with pytest.raises(ValueError):
        store._record("page", u)                                     # no other event type can be written at all


def test_a_scan_is_logged_once_however_often_it_is_reported(store):
    u = consumer(store)
    for _ in range(3):                                               # reruns, repeated callbacks, retried requests
        store.record_scan(u, scan_id="VX-20261115-0A1B2C", input_type="message", verdict="CRITICAL")
    assert events(store) == ["scan"]
    row = store.activity()[0]
    assert (row["kind"], row["verdict"], row["ref"]) == ("message", "CRITICAL", "VX-20261115-0A1B2C")


def test_one_feedback_submission_is_one_entry(store):
    u = consumer(store)
    fid = store.add_feedback(u, "wrong_result", "Missed a scam", "A fake casino bonus post was rated low.")
    rows = store.activity()
    assert [r["event"] for r in rows] == ["feedback"] and rows[0]["kind"] == "wrong_result" and rows[0]["ref"] == f"FB-{fid:06d}"


def test_activity_entries_never_hold_message_contents(engine, store):
    u = consumer(store)
    secret = "Ravi Kumar 9876543210 nyxwin.com bonus code ZZTOP"
    r = engine.scan_message(f"Hi {secret}, claim your prize at nyxwin.com", owner_id=u.id).result
    store.record_scan(u, scan_id=r.scan_id, input_type=r.input_type.value, verdict=r.overall_risk.value)
    store.add_feedback(u, "feedback", "About my scan", f"The message said {secret}.", scan_id=r.scan_id)
    dump = repr(store.activity()) + repr(store.db.query("SELECT * FROM activity"))
    for token in ("Ravi", "9876543210", "nyxwin", "ZZTOP", "claim your prize"):
        assert token not in dump


def test_lockout_still_works_without_activity_entries(store):
    consumer(store)
    for _ in range(MAX_FAILED - 1):
        with pytest.raises(AccountError, match="Incorrect"):
            store.authenticate("ravi", "wrong password 1", "consumer")
    with pytest.raises(AccountError, match="locked"):
        store.authenticate("ravi", "wrong password 1", "consumer")
    assert store.find("ravi").locked() and events(store) == []


def test_older_databases_keep_their_history_but_hide_retired_events(tmp_path):
    path = tmp_path / "accounts.sqlite"
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            role TEXT NOT NULL, password_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, last_login_at TEXT,
            last_seen_at TEXT, failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, login_count INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE activity (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, user_id INTEGER, username TEXT, role TEXT, event TEXT NOT NULL,
            detail TEXT, session TEXT, client TEXT);
        CREATE TABLE feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, user_id INTEGER NOT NULL, username TEXT NOT NULL,
            kind TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, scan_id TEXT, status TEXT NOT NULL DEFAULT 'new', reply TEXT,
            replied_by TEXT, updated_at TEXT);
        INSERT INTO activity (at, user_id, username, role, event, detail) VALUES ('2026-11-10T10:00:00+00:00', 1, 'ravi', 'consumer', 'login', '');
        INSERT INTO activity (at, user_id, username, role, event, detail) VALUES ('2026-11-10T10:00:05+00:00', 1, 'ravi', 'consumer', 'page', 'Dashboard');
        INSERT INTO activity (at, user_id, username, role, event, detail) VALUES ('2026-11-10T10:01:00+00:00', 1, 'ravi', 'consumer', 'login_failed', '');
    """)
    db.commit()
    db.close()
    store = AccountStore(path, moderator_pin=PIN)
    assert [r["event"] for r in store.activity()] == ["login"]       # retired events are no longer shown ...
    assert store.legacy_activity_count() == 2                        # ... but nothing was deleted by the upgrade
    backups = list(tmp_path.glob("accounts.sqlite.pre-accounts-v1-*.bak"))
    assert len(backups) == 1                                         # and a copy was taken before migrating
    assert {"kind", "verdict", "ref"} <= store.db.query("SELECT * FROM activity LIMIT 1")[0].keys()
    assert store.prune_legacy_activity() == 2 and store.legacy_activity_count() == 0
