"""Activity log: successful sign-ins, completed scans (type and verdict only) and submitted feedback - nothing else."""
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

import auth
import ui
from state import accounts
from trustguard.accounts import ACTIVITY_EVENTS, EVENT_LABELS, FEEDBACK_KINDS, SCAN_TYPE_LABELS

auth.require("moderator")
ui.page_header("Activity log", "Three things are recorded: successful sign-ins, completed scans (their type and verdict) and submitted feedback. "
                               "Page visits, sign-outs, failed attempts and moderator actions are not. Message contents, links and files are never "
                               "logged. Entries are kept for 180 days.")
store = accounts()

users = store.list_users()
by_name = {u["username"]: u["id"] for u in users}
f1, f2, f3 = st.columns([1, 1.2, 2], vertical_alignment="bottom")
period = f1.selectbox("Period", ["Today", "Last 7 days", "Last 30 days", "Everything"], index=1, key="act_period")
who = f2.selectbox("Account", ["All accounts", *sorted(by_name, key=str.lower)], key="act_user")
events = f3.multiselect("Events", list(ACTIVITY_EVENTS), format_func=EVENT_LABELS.get, key="act_events", placeholder="All events")

now = datetime.now(timezone.utc)
since = {"Today": now.replace(hour=0, minute=0, second=0, microsecond=0), "Last 7 days": now - timedelta(days=7),
         "Last 30 days": now - timedelta(days=30), "Everything": None}[period]
rows = store.activity(limit=5000, user_id=by_name.get(who), events=events or None, since=since)
st.caption(f"{len(rows)} entr{'y' if len(rows) == 1 else 'ies'}" + (" (showing the newest 5,000)" if len(rows) == 5000 else ""))
if not rows:
    ui.empty_state("No activity", "Nothing matches these filters.")
    st.stop()


def what(r) -> str:
    if r["event"] == "scan":
        return SCAN_TYPE_LABELS.get(r.get("kind") or "", "Scan")
    if r["event"] == "feedback":
        return FEEDBACK_KINDS.get(r.get("kind") or "", "Feedback")
    return ""


df = pd.DataFrame([{"When": ui.local_time(r["at"], "%d %b %Y, %H:%M:%S"), "Account": r["username"] or "-", "Role": (r["role"] or "-").title(),
                    "Event": EVENT_LABELS.get(r["event"], r["event"]), "Type": what(r), "Verdict": r.get("verdict") or "",
                    "Reference": r.get("ref") or ""} for r in rows])
st.dataframe(df, hide_index=True, width="stretch", height=min(560, 38 + 35 * len(df)),
             column_config={"Verdict": st.column_config.TextColumn("Verdict", help="Final verdict of the scan")})
st.download_button("Download as CSV", df.to_csv(index=False).encode("utf-8"), file_name="verioax-activity.csv", mime="text/csv",
                   icon=":material/download:", on_click="ignore")
