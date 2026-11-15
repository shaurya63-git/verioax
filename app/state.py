"""Shared, cached objects for all pages."""
from __future__ import annotations

import streamlit as st

from client import ClientError, ScopedClient, make_client
from trustguard.accounts import AccountStore
from trustguard.config import get_settings
from trustguard.db import open_database
from trustguard.ratelimit import Rate, make_limiter

NO_ACCOUNT = 0          # owner id used when nobody is signed in: matches no scans (account ids start at 1)


@st.cache_resource(show_spinner=False)
def _shared_client():
    return make_client()


@st.cache_resource(show_spinner=False)
def accounts() -> AccountStore:
    """Accounts, the activity log and feedback live with the web app (also when it uses the separate API)."""
    s = get_settings()

    def redact(text: str) -> str:
        from trustguard.pii import analyze_pii
        return analyze_pii(text)[1].redacted_text

    store = AccountStore(open_database(s, "accounts.sqlite"),
                         moderator_pin=s.moderator_pin.get_secret_value() if s.moderator_pin else None, redact=redact)
    store.purge_activity(older_than_days=180)
    return store


@st.cache_resource(show_spinner=False)
def _scan_limiter():
    """Per-account scan limit for the web app (shared through Redis when several app processes run)."""
    s = get_settings()
    return make_limiter(s.redis_url.get_secret_value() if s.redis_url else None)


def _throttle(uid: int | None) -> None:
    s = get_settings()
    try:
        who = f"user:{uid}" if uid else f"ip:{st.context.ip_address or 'unknown'}"
    except Exception:                                  # no request context (tests)
        who = f"user:{uid or 0}"
    d = _scan_limiter().hit(f"ui-scan:{who}", Rate.parse(s.rate_limit_ui_scan))
    if not d.allowed:
        raise ClientError(f"You're scanning very quickly. Please wait {d.retry_after} second(s) and try again.")


def client() -> ScopedClient:
    """The engine client as seen by whoever is signed in on this browser session."""
    uid = st.session_state.get("uid")

    def on_scan(result) -> None:
        """A completed scan: one activity entry (type and verdict only), keyed by the scan id so it can't be logged twice."""
        store = accounts()
        user = store.get(uid) if uid else None
        if user is not None:
            store.record_scan(user, scan_id=result.scan_id, input_type=result.input_type.value, verdict=result.overall_risk.value,
                              demo=result.processing.demo)

    return ScopedClient(_shared_client(), owner_id=uid if uid else NO_ACCOUNT, on_scan=on_scan, throttle=lambda: _throttle(uid))


def ocr_available() -> bool:
    from trustguard.extract import ocr_available as _ocr
    return _ocr()
