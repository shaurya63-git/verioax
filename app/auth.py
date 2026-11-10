"""Who is signed in on this browser session.

A Streamlit session lasts as long as the browser tab, so signing in again is needed after a page reload. That is
deliberate: storing a login token in the browser (cookies or local storage) would let anyone with access to the browser
reuse it. Sessions also end after IDLE_MINUTES without activity.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import streamlit as st

from state import accounts, client_label
from trustguard.accounts import User

IDLE_MINUTES = 60
_KEEP = {"sid"}                     # survives sign-out (identifies the browser session in the activity log)


def session_id() -> str:
    if "sid" not in st.session_state:
        st.session_state.sid = secrets.token_hex(6)
    return st.session_state.sid


def _end_session(notice: str | None = None) -> None:
    for k in list(st.session_state.keys()):
        if k not in _KEEP:
            del st.session_state[k]
    if notice:
        st.session_state.auth_notice = notice


def current_user() -> User | None:
    """The signed-in account, re-read every run so suspensions take effect immediately."""
    uid = st.session_state.get("uid")
    if uid is None:
        return None
    store = accounts()
    user = store.get(uid)
    if user is None or user.status != "active":
        _end_session("Your account has been suspended. Send a message to the moderators if you think this is a mistake."
                     if user else "Your account no longer exists.")
        return None
    now = datetime.now(timezone.utc)
    last = st.session_state.get("last_active")
    if last and now - last > timedelta(minutes=IDLE_MINUTES):
        store.log("session_expired", user=user, session=session_id(), client=client_label())
        store.signed_out(user)
        _end_session(f"You were signed out after {IDLE_MINUTES} minutes without activity. Sign in again to continue.")
        return None
    st.session_state.last_active = now
    store.touch(user)
    return user


def sign_in(user: User) -> None:
    _end_session()                                      # nothing from a previous account survives (scan results, filters)
    st.session_state.uid = user.id
    st.session_state.role = user.role
    st.session_state.last_active = datetime.now(timezone.utc)


def sign_out(user: User | None) -> None:
    if user is not None:
        accounts().log("logout", user=user, session=session_id(), client=client_label())
        accounts().signed_out(user)
    _end_session("You have signed out.")


def require(role: str | None = None) -> User:
    """Guard at the top of every signed-in page; moderator pages pass role='moderator'."""
    user = current_user()
    if user is None or (role and user.role != role):
        st.error("You don't have access to this page.", icon=":material/lock:")
        st.stop()
    return user


def log_page(user: User, title: str) -> None:
    """One 'opened page' event per page change (not per rerun)."""
    title = title.split(" (")[0]                       # "Consumer feedback (3 new)" is the same page as "Consumer feedback"
    if st.session_state.get("_last_page") != title:
        st.session_state._last_page = title
        accounts().log("page", user=user, detail=title, session=session_id(), client=client_label())
