"""Accounts for the web app: consumers and moderators, sign-in with lockout, an activity log and consumer feedback (SQLite).

Security choices (docs/architecture.md, "Accounts"):

* Passwords are hashed with scrypt (N=2^14, r=8, p=5 - OWASP's minimum for scrypt) and a random 16-byte salt. Only the
  hash is stored.
* The moderator PIN comes from the ``VERIOAX_MODERATOR_PIN`` setting (``.env`` or the host's secrets). It is never written
  to the database or the code: the repository is public, so a PIN in the code would be readable by everyone. It is
  compared in constant time.
* Five wrong passwords or PINs in a row lock an account for 15 minutes. Wrong PINs at moderator *sign-up* are also limited
  installation-wide, because sign-up isn't tied to an existing account.
* Sign-in errors don't reveal whether a username exists, and a dummy hash is checked when it doesn't, so response time
  doesn't reveal it either.
* Feedback text passes through the PII redactor before it is stored. The activity log records what happened (sign-in,
  scan type and verdict, feedback sent), never message contents.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from functools import cache
from pathlib import Path
from typing import Any

ROLES = ("consumer", "moderator")
FEEDBACK_KINDS = {"feedback": "General feedback", "complaint": "Complaint", "wrong_result": "Wrong or missed result",
                  "bug": "Something isn't working"}
FEEDBACK_STATUSES = {"new": "New", "in_review": "In review", "resolved": "Resolved"}
MAX_FAILED = 5
LOCK_MINUTES = 15
SIGNUP_PIN_WINDOW_MIN = 15
SIGNUP_PIN_MAX_FAILURES = 10
ONLINE_MINUTES = 5
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 5}
USERNAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,29}$")
EMAIL_RX = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$")
GENERIC_LOGIN_ERROR = "Incorrect username, email or password."
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "12345678", "123456789", "1234567890", "11111111", "00000000", "87654321",
    "qwerty123", "qwertyuiop", "1q2w3e4r", "abc12345", "abcd1234", "iloveyou", "welcome1", "welcome123", "admin123", "letmein1",
    "india123", "india@123", "sunshine1", "princess1", "football1", "monkey123", "dragon123", "superman1", "verioax123", "trustguard",
}


class AccountError(Exception):
    """A user-facing problem: invalid input, wrong credentials, a locked or suspended account."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# ---------------------------------------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, key = stored.split("$")
        if algo != "scrypt":
            return False
        salt_b, key_b = base64.b64decode(salt), base64.b64decode(key)
        calc = hashlib.scrypt(password.encode("utf-8"), salt=salt_b, n=int(n), r=int(r), p=int(p), dklen=len(key_b))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(calc, key_b)


@cache
def _dummy_hash() -> str:
    return hash_password(secrets.token_urlsafe(16))


def password_problems(password: str, username: str = "", email: str = "") -> list[str]:
    out = []
    if len(password) < 8:
        out.append("Use at least 8 characters.")
    if len(password) > 128:
        out.append("Use at most 128 characters.")
    low = password.lower()
    if low in COMMON_PASSWORDS or len(set(password)) < 4:
        out.append("This password is too common or too simple. Choose something less predictable.")
    if username and len(username) >= 3 and username.lower() in low:
        out.append("Don't include your username in the password.")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 4 and local in low:
        out.append("Don't include your email address in the password.")
    return out


# ---------------------------------------------------------------------------------------------------------- records
@dataclass
class User:
    id: int
    username: str
    email: str
    role: str
    status: str
    created_at: str
    last_login_at: str | None
    last_seen_at: str | None
    failed_attempts: int
    locked_until: str | None
    login_count: int
    signed_out_at: str | None = None

    @property
    def is_moderator(self) -> bool:
        return self.role == "moderator"

    def locked(self, now: datetime | None = None) -> bool:
        lu = _parse(self.locked_until)
        return bool(lu and lu > (now or _now()))

    def online(self, now: datetime | None = None) -> bool:
        ls, out = _parse(self.last_seen_at), _parse(self.signed_out_at)
        return bool(ls and (now or _now()) - ls < timedelta(minutes=ONLINE_MINUTES) and not (out and out >= ls))

    def account_state(self) -> str:
        """What a moderator sees: suspended > locked > online > active."""
        if self.status == "suspended":
            return "suspended"
        if self.locked():
            return "locked"
        return "online" if self.online() else "active"


_USER_COLS = [f.name for f in fields(User)]
_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role TEXT NOT NULL CHECK (role IN ('consumer', 'moderator')),
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    last_seen_at TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    login_count INTEGER NOT NULL DEFAULT 0,
    signed_out_at TEXT
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    user_id INTEGER,
    username TEXT,
    role TEXT,
    event TEXT NOT NULL,
    detail TEXT,
    session TEXT,
    client TEXT
);
CREATE INDEX IF NOT EXISTS ix_activity_at ON activity(at);
CREATE INDEX IF NOT EXISTS ix_activity_user ON activity(user_id);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    scan_id TEXT,
    status TEXT NOT NULL DEFAULT 'new',
    reply TEXT,
    replied_by TEXT,
    updated_at TEXT
);
"""
EVENT_LABELS = {"signup": "Created account", "login": "Signed in", "logout": "Signed out", "login_failed": "Failed sign-in",
                "pin_failed": "Wrong moderator PIN", "locked": "Account locked", "login_blocked": "Blocked sign-in", "page": "Opened page",
                "scan": "Ran a scan", "feedback": "Sent feedback", "status_change": "Changed account status", "unlock": "Unlocked account",
                "password_change": "Changed password", "feedback_update": "Updated feedback", "session_expired": "Session expired"}


class AccountStore:
    def __init__(self, path: Path | str, moderator_pin: str | None = None, redact: Callable[[str], str] | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._pin = (moderator_pin or "").strip()
        self._redact = redact
        self._lock = threading.Lock()
        self._seen: dict[int, datetime] = {}
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        if "signed_out_at" not in {r[1] for r in self._db.execute("PRAGMA table_info(users)")}:
            self._db.execute("ALTER TABLE users ADD COLUMN signed_out_at TEXT")
        self._db.commit()

    # ------------------------------------------------------------------ helpers
    @property
    def pin_configured(self) -> bool:
        return re.fullmatch(r"\d{6}", self._pin) is not None

    def _pin_ok(self, pin: str | None) -> bool:
        return self.pin_configured and hmac.compare_digest((pin or "").strip().encode(), self._pin.encode())

    def _q(self, sql: str, args: tuple = (), one: bool = False):
        with self._lock:
            cur = self._db.execute(sql, args)
            return cur.fetchone() if one else cur.fetchall()

    def _x(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, args)
            self._db.commit()
            return cur.lastrowid or cur.rowcount

    def _user(self, row) -> User | None:
        return User(**{k: row[k] for k in _USER_COLS}) if row else None

    def get(self, user_id: int) -> User | None:
        return self._user(self._q("SELECT * FROM users WHERE id = ?", (user_id,), one=True))

    def find(self, identifier: str) -> User | None:
        ident = (identifier or "").strip()
        return self._user(self._q("SELECT * FROM users WHERE username = ? OR email = ?", (ident, ident.lower()), one=True))

    def count(self, role: str | None = None) -> int:
        if role:
            return int(self._q("SELECT COUNT(*) FROM users WHERE role = ?", (role,), one=True)[0])
        return int(self._q("SELECT COUNT(*) FROM users", one=True)[0])

    # ------------------------------------------------------------------ activity log
    def log(self, event: str, *, user: User | None = None, username: str | None = None, role: str | None = None, detail: str = "",
            session: str | None = None, client: str | None = None) -> None:
        self._x("INSERT INTO activity (at, user_id, username, role, event, detail, session, client) VALUES (?,?,?,?,?,?,?,?)",
                (_iso(_now()), user.id if user else None, (user.username if user else username or "")[:60], user.role if user else role,
                 event, (detail or "")[:300], session, (client or "")[:80]))

    def activity(self, *, limit: int = 500, user_id: int | None = None, events: list[str] | None = None,
                 since: datetime | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM activity WHERE 1=1", []
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        if events:
            sql += f" AND event IN ({','.join('?' * len(events))})"
            args += events
        if since:
            sql += " AND at >= ?"
            args.append(_iso(since))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self._q(sql, tuple(args))]

    def purge_activity(self, older_than_days: int = 180) -> int:
        return self._x("DELETE FROM activity WHERE at < ?", (_iso(_now() - timedelta(days=older_than_days)),))

    def signed_out(self, user: User) -> None:
        """The account left on purpose (or its session expired): it no longer counts as online."""
        self._seen.pop(user.id, None)
        self._x("UPDATE users SET signed_out_at = ? WHERE id = ?", (_iso(_now()), user.id))

    def touch(self, user: User) -> None:
        """Record that the user is active (at most one write a minute)."""
        now = _now()
        last = self._seen.get(user.id)
        if last and now - last < timedelta(seconds=60):
            return
        self._seen[user.id] = now
        self._x("UPDATE users SET last_seen_at = ? WHERE id = ?", (_iso(now), user.id))

    # ------------------------------------------------------------------ sign-up / sign-in
    def signup_problems(self, username: str, email: str, password: str, confirm: str | None = None) -> list[str]:
        out = []
        if not USERNAME_RX.fullmatch(username or ""):
            out.append("Usernames are 3-30 characters: letters, numbers, dots, dashes or underscores, starting with a letter or number.")
        if not EMAIL_RX.fullmatch(email or ""):
            out.append("Enter a valid email address.")
        out += password_problems(password or "", username, email)
        if confirm is not None and confirm != password:
            out.append("The two passwords don't match.")
        return out

    def _signup_pin_paused(self) -> bool:
        since = _now() - timedelta(minutes=SIGNUP_PIN_WINDOW_MIN)
        row = self._q("SELECT COUNT(*) FROM activity WHERE event = 'pin_failed' AND detail = 'moderator sign-up' AND at >= ?",
                      (_iso(since),), one=True)
        return int(row[0]) >= SIGNUP_PIN_MAX_FAILURES

    def create_user(self, username: str, email: str, password: str, role: str, *, pin: str | None = None, confirm: str | None = None,
                    session: str | None = None, client: str | None = None) -> User:
        username, email = (username or "").strip(), (email or "").strip().lower()
        if role not in ROLES:
            raise AccountError("Choose Consumer or Moderator.")
        problems = self.signup_problems(username, email, password, confirm)
        if problems:
            raise AccountError(" ".join(problems))
        if role == "moderator":
            if not self.pin_configured:
                raise AccountError("Moderator accounts aren't enabled on this server yet: the administrator has to set VERIOAX_MODERATOR_PIN.")
            if self._signup_pin_paused():
                raise AccountError(f"Moderator sign-up is paused for {SIGNUP_PIN_WINDOW_MIN} minutes after repeated wrong PINs.")
            if not self._pin_ok(pin):
                self.log("pin_failed", username=username, role="moderator", detail="moderator sign-up", session=session, client=client)
                raise AccountError("The moderator security PIN is incorrect.")
        if self.find(username):
            raise AccountError("That username is already taken.")
        if self._q("SELECT 1 FROM users WHERE email = ?", (email,), one=True):
            raise AccountError("An account with this email already exists. Sign in instead.")
        try:
            uid = self._x("INSERT INTO users (username, email, role, password_hash, created_at) VALUES (?,?,?,?,?)",
                          (username, email, role, hash_password(password), _iso(_now())))
        except sqlite3.IntegrityError:
            raise AccountError("That username or email is already registered.") from None
        user = self.get(uid)
        self.log("signup", user=user, detail=f"{role} account", session=session, client=client)
        return user

    def authenticate(self, identifier: str, password: str, role: str, *, pin: str | None = None, session: str | None = None,
                     client: str | None = None) -> User:
        user = self.find(identifier)
        if user is None:
            verify_password(password or "", _dummy_hash())             # same work as a real check: no timing difference
            self.log("login_failed", username=(identifier or "")[:60], detail="unknown account", session=session, client=client)
            raise AccountError(GENERIC_LOGIN_ERROR)
        if user.locked():
            mins = max(1, int((_parse(user.locked_until) - _now()).total_seconds() // 60) + 1)
            self.log("login_blocked", user=user, detail="locked", session=session, client=client)
            raise AccountError(f"Too many failed attempts. This account is locked for {mins} more minute{'s' if mins != 1 else ''}.")
        if not verify_password(password or "", self._q("SELECT password_hash FROM users WHERE id = ?", (user.id,), one=True)[0]):
            self._fail(user, "login_failed", "wrong password", session, client)
            raise AccountError(GENERIC_LOGIN_ERROR)
        # the password is right: from here on, messages may be specific
        if user.status == "suspended":
            self.log("login_blocked", user=user, detail="suspended", session=session, client=client)
            raise AccountError("This account has been suspended. Send a message to the moderators if you think this is a mistake.")
        if user.role != role:
            raise AccountError("This is a moderator account. Choose Moderator and enter your security PIN." if user.is_moderator
                               else "This is a consumer account. Choose Consumer to sign in.")
        if user.is_moderator:
            if not self.pin_configured:
                raise AccountError("Moderator sign-in isn't enabled on this server: the administrator has to set VERIOAX_MODERATOR_PIN.")
            if not self._pin_ok(pin):
                self._fail(user, "pin_failed", "moderator sign-in", session, client)
                raise AccountError("The moderator security PIN is incorrect.")
        now = _iso(_now())
        self._x("UPDATE users SET failed_attempts = 0, locked_until = NULL, signed_out_at = NULL, last_login_at = ?, last_seen_at = ?, "
                "login_count = login_count + 1 WHERE id = ?", (now, now, user.id))
        user = self.get(user.id)
        self.log("login", user=user, session=session, client=client)
        return user

    def _fail(self, user: User, event: str, detail: str, session, client) -> None:
        n = user.failed_attempts + 1
        locked = n >= MAX_FAILED
        self._x("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (n, _iso(_now() + timedelta(minutes=LOCK_MINUTES)) if locked else None, user.id))
        self.log(event, user=user, detail=detail, session=session, client=client)
        if locked:
            self.log("locked", user=user, detail=f"{n} failed attempts", session=session, client=client)
            raise AccountError(f"Too many failed attempts. This account is locked for {LOCK_MINUTES} minutes.")

    def change_password(self, user: User, current: str, new: str, confirm: str) -> None:
        stored = self._q("SELECT password_hash FROM users WHERE id = ?", (user.id,), one=True)[0]
        if not verify_password(current or "", stored):
            raise AccountError("Your current password is incorrect.")
        problems = password_problems(new or "", user.username, user.email) + (["The two passwords don't match."] if new != confirm else [])
        if problems:
            raise AccountError(" ".join(problems))
        self._x("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new), user.id))
        self.log("password_change", user=user)

    # ------------------------------------------------------------------ moderation
    def _require_moderator(self, actor: User) -> None:
        fresh = self.get(actor.id)
        if fresh is None or not fresh.is_moderator or fresh.status != "active":
            raise AccountError("Only active moderators can do this.")

    def list_users(self) -> list[dict[str, Any]]:
        users = [self._user(r) for r in self._q("SELECT * FROM users ORDER BY created_at")]
        counts = {(r["user_id"], r["event"]): r["n"] for r in
                  self._q("SELECT user_id, event, COUNT(*) AS n FROM activity WHERE event IN ('scan', 'feedback', 'login') GROUP BY user_id, event")}
        out = []
        for u in users:
            d = {k: getattr(u, k) for k in _USER_COLS}
            d.update(state=u.account_state(), scans=counts.get((u.id, "scan"), 0), feedback=counts.get((u.id, "feedback"), 0))
            out.append(d)
        return out

    def set_status(self, actor: User, user_id: int, status: str) -> None:
        self._require_moderator(actor)
        if status not in ("active", "suspended"):
            raise AccountError("Unknown status.")
        if user_id == actor.id:
            raise AccountError("You can't change the status of your own account.")
        target = self.get(user_id)
        if target is None:
            raise AccountError("That account no longer exists.")
        self._x("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
        self.log("status_change", user=actor, detail=f"{target.username}: {target.status} -> {status}")

    def unlock(self, actor: User, user_id: int) -> None:
        self._require_moderator(actor)
        target = self.get(user_id)
        if target is None:
            raise AccountError("That account no longer exists.")
        self._x("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        self.log("unlock", user=actor, detail=target.username)

    def traffic(self, days: int = 14) -> dict[str, Any]:
        now = _now()
        start = (now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        rows = self._q("SELECT substr(at, 1, 10) AS day, event, COUNT(*) AS n, COUNT(DISTINCT user_id) AS users FROM activity "
                       "WHERE at >= ? GROUP BY day, event", (_iso(start),))
        active = self._q("SELECT substr(at, 1, 10) AS day, COUNT(DISTINCT user_id) AS users FROM activity "
                         "WHERE at >= ? AND user_id IS NOT NULL GROUP BY day", (_iso(start),))
        series = {(start + timedelta(days=i)).date().isoformat(): {"signups": 0, "logins": 0, "scans": 0, "feedback": 0, "page_views": 0,
                                                                  "failed_sign_ins": 0, "active_users": 0} for i in range(days)}
        name = {"signup": "signups", "login": "logins", "scan": "scans", "feedback": "feedback", "page": "page_views",
                "login_failed": "failed_sign_ins", "pin_failed": "failed_sign_ins"}
        for r in rows:
            if r["day"] in series and r["event"] in name:
                series[r["day"]][name[r["event"]]] += r["n"]
        for r in active:
            if r["day"] in series:
                series[r["day"]]["active_users"] = r["users"]
        users = [self._user(r) for r in self._q("SELECT * FROM users")]
        week = now - timedelta(days=7)
        return {
            "series": series,
            "users": len(users),
            "consumers": sum(u.role == "consumer" for u in users),
            "moderators": sum(u.role == "moderator" for u in users),
            "online": sum(u.online(now) and u.status == "active" for u in users),
            "active_today": series[now.date().isoformat()]["active_users"] if now.date().isoformat() in series else 0,
            "new_this_week": sum((_parse(u.created_at) or now) >= week for u in users),
            "suspended": sum(u.status == "suspended" for u in users),
            "locked": sum(u.locked(now) for u in users),
        }

    # ------------------------------------------------------------------ feedback
    def add_feedback(self, user: User, kind: str, subject: str, message: str, scan_id: str | None = None, *, session: str | None = None,
                     client: str | None = None) -> int:
        subject, message = (subject or "").strip(), (message or "").strip()
        if kind not in FEEDBACK_KINDS:
            raise AccountError("Choose what kind of feedback this is.")
        if not 3 <= len(subject) <= 120:
            raise AccountError("Give your feedback a short subject (3-120 characters).")
        if not 10 <= len(message) <= 4000:
            raise AccountError("Write a few words of detail (10-4,000 characters).")
        if scan_id and not re.fullmatch(r"(?:VX|TG)-\d{8}-[0-9A-F]{6}", scan_id):
            scan_id = None
        if self._redact:
            subject, message = self._redact(subject), self._redact(message)
        fid = self._x("INSERT INTO feedback (created_at, user_id, username, kind, subject, message, scan_id) VALUES (?,?,?,?,?,?,?)",
                      (_iso(_now()), user.id, user.username, kind, subject, message, scan_id))
        self.log("feedback", user=user, detail=f"#{fid} {FEEDBACK_KINDS[kind].lower()}" + (f" about {scan_id}" if scan_id else ""),
                 session=session, client=client)
        return fid

    def feedback(self, *, user_id: int | None = None, status: list[str] | None = None, limit: int = 500) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM feedback WHERE 1=1", []
        if user_id is not None:
            sql += " AND user_id = ?"
            args.append(user_id)
        if status:
            sql += f" AND status IN ({','.join('?' * len(status))})"
            args += status
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self._q(sql, tuple(args))]

    def feedback_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in FEEDBACK_STATUSES}
        for r in self._q("SELECT status, COUNT(*) AS n FROM feedback GROUP BY status"):
            counts[r["status"]] = r["n"]
        return counts

    def update_feedback(self, actor: User, feedback_id: int, *, status: str | None = None, reply: str | None = None) -> None:
        self._require_moderator(actor)
        row = self._q("SELECT * FROM feedback WHERE id = ?", (feedback_id,), one=True)
        if row is None:
            raise AccountError("That feedback no longer exists.")
        if status is not None and status not in FEEDBACK_STATUSES:
            raise AccountError("Unknown status.")
        reply = (reply or "").strip()[:2000] if reply is not None else row["reply"]
        self._x("UPDATE feedback SET status = ?, reply = ?, replied_by = ?, updated_at = ? WHERE id = ?",
                (status or row["status"], reply or None, actor.username if reply else row["replied_by"], _iso(_now()), feedback_id))
        self.log("feedback_update", user=actor, detail=f"#{feedback_id} -> {FEEDBACK_STATUSES[status or row['status']].lower()}")
