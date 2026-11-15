"""Moderator overview: traffic, what needs attention, and the latest activity."""
import altair as alt
import pandas as pd
import streamlit as st

import auth
import charts
import ui
from client import ClientError
from state import accounts, client
from trustguard.accounts import EVENT_LABELS

user = auth.require("moderator")
ui.page_header("Moderator overview", "Who is using Verioax, how much it is being used, and what needs your attention.")
store = accounts()
tr = store.traffic(days=14)
fb = store.feedback_counts()
series = tr["series"]
scans_14 = sum(d["scans"] for d in series.values())

tiles = [("Accounts", tr["users"], f"{tr['consumers']} consumer(s), {tr['moderators']} moderator(s)"),
         ("Online now", tr["online"], "Active in the last 5 minutes"),
         ("Active today", tr["active_today"], "Accounts that signed in, scanned or sent feedback today"),
         ("New this week", tr["new_this_week"], "Accounts created in the last 7 days"),
         ("Scans, 14 days", scans_14, "Message, link and file scans"),
         ("Open feedback", fb["new"] + fb["in_review"], f"{fb['new']} new, {fb['in_review']} in review")]
for row in (tiles[:3], tiles[3:]):
    cols = st.columns(3)
    for col, (label, value, help_) in zip(cols, row, strict=True):
        col.metric(label, value, help=help_, border=True)

left, right = st.columns([1.7, 1], gap="large")
with left:
    st.subheader("Daily activity")
    names = {"active_users": "Active accounts", "logins": "Sign-ins", "scans": "Scans", "feedback": "Feedback"}
    df = pd.DataFrame([{"day": day, "measure": names[k], "count": v[k]} for day, v in sorted(series.items()) for k in names])
    df["day"] = pd.to_datetime(df["day"])
    order = list(names.values())
    colors = alt.Scale(domain=order, range=charts.SERIES_COLORS[:4])                     # categorical slots 1-4, fixed order
    base = alt.Chart(df).encode(x=alt.X("day:T", title=None, axis=alt.Axis(format="%d %b", grid=False)),
                                y=alt.Y("count:Q", title=None, axis=alt.Axis(tickMinStep=1)),
                                color=alt.Color("measure:N", scale=colors, sort=order, title=None, legend=alt.Legend(orient="top")))
    chart = base.mark_line(strokeWidth=2) + base.mark_point(filled=True, size=55).encode(
        tooltip=[alt.Tooltip("day:T", title="Day", format="%d %b %Y"), alt.Tooltip("measure:N", title="Measure"),
                 alt.Tooltip("count:Q", title="Count")])
    st.altair_chart(charts._base(chart, 240), width="stretch", theme=None)
    with st.expander("Show as a table"):
        st.dataframe(df.pivot(index="day", columns="measure", values="count").reset_index().assign(day=lambda d: d["day"].dt.strftime("%d %b %Y")),
                     hide_index=True, width="stretch")

with right:
    st.subheader("Needs attention")
    items = [(fb["new"], "new feedback message", "views/mod_feedback.py", ":material/forum:"),
             (tr["locked"], "locked account", "views/mod_accounts.py", ":material/lock:"),
             (tr["suspended"], "suspended account", "views/mod_accounts.py", ":material/block:")]
    shown = False
    for n, what, page, icon in items:
        if n:
            shown = True
            st.page_link(page, label=f"{n} {what}{'s' if n != 1 else ''}", icon=icon)
    if not shown:
        st.caption("Nothing needs your attention right now.")

st.subheader("Latest activity")
rows = store.activity(limit=12)
if rows:
    st.dataframe(pd.DataFrame([{"When": ui.local_time(r["at"], "%d %b, %H:%M"), "Account": r["username"] or "-",
                                "Role": (r["role"] or "-").title(), "Event": EVENT_LABELS.get(r["event"], r["event"]),
                                "Details": r["detail"] or ""} for r in rows]), hide_index=True, width="stretch")
    st.page_link("views/mod_activity.py", label="Open the full activity log", icon=":material/timeline:")
else:
    st.caption("No activity yet.")

st.subheader("Service health")
try:
    ops = client().ops_stats()
except ClientError as exc:
    st.caption(f"Service metrics are not available: {exc}")
else:
    lat = ops.get("latency", {})
    scan_lat = [v for k, v in lat.items() if k.startswith("scan.")]
    p95 = max((v["p95_ms"] for v in scan_lat), default=0.0)
    cols = st.columns(4)
    cols[0].metric("Scans since start", int(ops.get("scans_total", 0)), help="Completed scans handled by this process", border=True)
    cols[1].metric("Slowest p95 scan time", f"{p95 / 1000:.2f} s" if scan_lat else "-",
                   help="95% of scans of the slowest kind (message / link / file / app) finished faster than this", border=True)
    cols[2].metric("Turned away", int(ops.get("busy_rejections_total", 0) + ops.get("rate_limited_total", 0)),
                   help="Requests refused because the server was busy (503) or a client went over its limit (429)", border=True)
    cols[3].metric("Database errors", int(ops.get("db_errors_total", 0)), border=True)
    rows = []
    for p in ops.get("providers", []):
        if "circuit" not in p:
            continue
        circuit = {"closed": (ui.T.OK, "✓", "Working"), "open": (ui.T.BAD, "✕", "Paused after failures"),
                   "half_open": (ui.T.WARN, "◐", "Testing again")}.get(p["circuit"], (ui.NEUTRAL, "–", p["circuit"]))
        state = ui.pill(circuit[2], circuit[0], circuit[1]) if p["configured"] and p["enabled"] else ui.pill(
            "Off" if p["configured"] else "Not configured", ui.NEUTRAL, "–")
        rows.append([p["label"], state, str(p.get("calls", 0)), str(p.get("errors", 0) + p.get("timeouts", 0)), str(p.get("skipped", 0)),
                     f"{p.get('p95_ms', 0) / 1000:.2f} s" if p.get("calls") else "-"])
    if rows:
        st.html(ui.table(["Outside service", "State", "Calls", "Failed", "Skipped", "p95"], rows, raw_cols=(1,)))
    st.caption("Counts and timings only - no messages, links, file names or account names. Numbers are for this process and reset when it "
               "restarts; with several API workers each one keeps its own (scrape /metrics on each).")
