"""Verioax - Streamlit front end.

Run from the repository root:   streamlit run app/streamlit_app.py

Two user interfaces share this app:
* the consumer UI (scan messages, links and files, own history, feedback), and
* the moderator UI (accounts, traffic and activity, consumer feedback, threat intelligence, analytics, settings).
Visitors who aren't signed in only see the sign-in page.

The UI contains no detection logic. Every page talks to the engines through ``client.py``: in-process by default, or the
FastAPI backend when TRUSTGUARD_API_URL is set.
"""
from __future__ import annotations

import sys
from pathlib import Path

APP = Path(__file__).resolve().parent
ROOT = APP.parent
for p in (str(ROOT), str(APP)):
    if p not in sys.path:
        sys.path.insert(0, p)

import streamlit as st  # noqa: E402

st.set_page_config(page_title="Verioax", page_icon=str(APP / "static" / "logo_icon.svg"), layout="wide", initial_sidebar_state="expanded")

import auth  # noqa: E402
import ui  # noqa: E402
from client import ClientError  # noqa: E402
from state import accounts, client  # noqa: E402

ui.inject_css()
st.logo(str(APP / "static" / "logo.svg"), icon_image=str(APP / "static" / "logo_icon.svg"), size="large")

user = auth.current_user()
scanners = [st.Page("views/scan_message.py", title="Message scanner", icon=":material/sms:"),
            st.Page("views/scan_url.py", title="URL scanner", icon=":material/link:"),
            st.Page("views/scan_file.py", title="File scanner", icon=":material/upload_file:")]
account = st.Page("views/account.py", title="My account", icon=":material/account_circle:")

if user is None:
    nav = st.navigation([st.Page("views/signin.py", title="Sign in", icon=":material/login:", default=True)], position="hidden")
elif user.is_moderator:
    new_feedback = accounts().feedback_counts()["new"]
    nav = st.navigation({
        "Moderation": [st.Page("views/mod_overview.py", title="Moderator overview", icon=":material/shield_person:", default=True),
                       st.Page("views/mod_accounts.py", title="Accounts", icon=":material/group:"),
                       st.Page("views/mod_activity.py", title="Activity log", icon=":material/timeline:"),
                       st.Page("views/mod_feedback.py", title=f"Consumer feedback ({new_feedback} new)" if new_feedback else "Consumer feedback",
                               icon=":material/forum:")],
        "New scan": scanners,
        "Records": [st.Page("views/history.py", title="Scan history", icon=":material/history:"),
                    st.Page("views/threat_intel.py", title="Threat intelligence", icon=":material/radar:"),
                    st.Page("views/reports.py", title="Reports & analytics", icon=":material/monitoring:")],
        "System": [st.Page("views/settings.py", title="Settings", icon=":material/settings:"), account],
    }, position="sidebar", expanded=True)
else:
    nav = st.navigation({
        "Overview": [st.Page("views/dashboard.py", title="Dashboard", icon=":material/space_dashboard:", default=True)],
        "New scan": scanners,
        "Records": [st.Page("views/history.py", title="Scan history", icon=":material/history:")],
        "Support": [st.Page("views/feedback.py", title="Feedback", icon=":material/rate_review:"), account],
    }, position="sidebar", expanded=True)

# ---- sidebar: who is signed in, system status, founder
with st.sidebar:
    if user is not None:
        role = ":blue-badge[Moderator]" if user.is_moderator else ":gray-badge[Consumer]"
        st.html(f"<div class='tg-user'>Signed in as <b>{ui.esc(user.username)}</b></div>")
        st.markdown(role)
        if st.button("Sign out", icon=":material/logout:", key="sign_out", width="stretch"):
            auth.sign_out(user)
            st.rerun()
    try:
        c = client()
        prefs = c.get_prefs()
        status = c.intel_status()
        online = [s for s in status if s["configured"] and s["provider"] not in ("local_ioc", "google_factcheck")]
        engine_row = ("#2DBA6B", "Engine ready" if c.kind == "local" else "Connected to API")
        net_row = ("#8090A8", "Local mode: nothing is sent online") if prefs.local_mode else ("#4C8DF6", "Online checks on")
        intel_row = ("#2DBA6B" if online else "#8090A8", f"{len(online)} online intel source(s)" if online else "Local indicator list only")
        priv_row = ("#2DBA6B", "Redaction on; originals never stored") if prefs.auto_redact else ("#FAB219", "Automatic redaction is off")
    except ClientError as exc:
        engine_row, net_row, intel_row, priv_row = ("#E05252", "Backend not reachable"), ("#8090A8", str(exc)[:60]), ("#8090A8", "-"), ("#8090A8", "-")
    rows = "".join(f"<div class='row'><span class='dot' style='background:{col}'></span><span>{ui.esc(txt)}</span></div>"
                   for col, txt in (engine_row, net_row, intel_row, priv_row))
    st.html(f"<div class='tg-status'><b>System status</b>{rows}{ui.founder_html()}</div>")

if user is not None:
    auth.log_page(user, nav.title)
nav.run()
