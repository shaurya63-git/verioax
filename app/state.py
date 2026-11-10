"""Shared, cached objects for all pages."""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from client import ScopedClient, make_client
from trustguard.accounts import AccountStore
from trustguard.config import get_settings

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

    store = AccountStore(Path(s.data_dir) / "accounts.sqlite",
                         moderator_pin=s.moderator_pin.get_secret_value() if s.moderator_pin else None, redact=redact)
    store.purge_activity(older_than_days=180)
    return store


def client_label() -> str:
    """'Chrome on Windows' - enough to read traffic, without storing IP addresses or full user-agent strings."""
    try:
        ua = st.context.headers.get("User-Agent") or ""
    except Exception:                                   # no browser context (tests, scripts)
        return ""
    browser = next((b for b, mark in (("Edge", "Edg/"), ("Opera", "OPR/"), ("Samsung Internet", "SamsungBrowser"), ("Chrome", "Chrome/"),
                                      ("Firefox", "Firefox/"), ("Safari", "Safari/")) if mark in ua), "Browser")
    system = next((o for o, mark in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"), ("Windows", "Windows"),
                                     ("macOS", "Mac OS X"), ("Linux", "Linux")) if mark in ua), "")
    return f"{browser} on {system}" if system else browser


def client() -> ScopedClient:
    """The engine client as seen by whoever is signed in on this browser session."""
    uid = st.session_state.get("uid")

    def on_scan(result) -> None:
        store = accounts()
        user = store.get(uid) if uid else None
        if user is not None:
            sample = " (sample)" if result.processing.demo else ""
            store.log("scan", user=user, detail=f"{result.input_type.value} scan{sample}: {result.overall_risk.value} - {result.scan_id}",
                      session=st.session_state.get("sid"), client=client_label())

    return ScopedClient(_shared_client(), owner_id=uid if uid else NO_ACCOUNT, on_scan=on_scan)


def ocr_available() -> bool:
    from trustguard.extract import ocr_available as _ocr
    return _ocr()
