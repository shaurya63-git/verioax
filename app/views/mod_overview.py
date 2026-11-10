"""Moderator overview: traffic, what needs attention, and the latest activity."""
import altair as alt
import pandas as pd
import streamlit as st

import auth
import charts
import ui
from state import accounts
from trustguard.accounts import EVENT_LABELS

user = auth.require("moderator")
ui.page_header("Moderator overview", "Who is using Verioax, how much it is being used, and what needs your attention.")
store = accounts()
tr = store.traffic(days=14)
fb = store.feedback_counts()
series = tr["series"]
today = max(series)
scans_14 = sum(d["scans"] for d in series.values())

tiles = [("Accounts", tr["users"], f"{tr['consumers']} consumer(s), {tr['moderators']} moderator(s)"),
         ("Online now", tr["online"], "Active in the last 5 minutes"),
         ("Active today", tr["active_today"], "Accounts that did anything today"),
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
    names = {"active_users": "Active accounts", "logins": "Sign-ins", "scans": "Scans"}
    df = pd.DataFrame([{"day": day, "measure": names[k], "count": v[k]} for day, v in sorted(series.items()) for k in names])
    df["day"] = pd.to_datetime(df["day"])
    order = list(names.values())
    colors = alt.Scale(domain=order, range=["#3987e5", "#d95926", "#199e70"])          # categorical slots 1-3, fixed order
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
    failed_today = series[today]["failed_sign_ins"]
    items = [(fb["new"], "new feedback message", "views/mod_feedback.py", ":material/forum:"),
             (tr["locked"], "locked account", "views/mod_accounts.py", ":material/lock:"),
             (tr["suspended"], "suspended account", "views/mod_accounts.py", ":material/block:"),
             (failed_today, "failed sign-in or wrong PIN today", "views/mod_activity.py", ":material/report:")]
    shown = False
    for n, what, page, icon in items:
        if n:
            shown = True
            st.page_link(page, label=f"{n} {what}{'s' if n != 1 and not what.endswith('today') else ''}", icon=icon)
    if not shown:
        st.caption("Nothing needs your attention right now.")

st.subheader("Latest activity")
rows = store.activity(limit=12)
if rows:
    st.dataframe(pd.DataFrame([{"When": ui.local_time(r["at"], "%d %b, %H:%M"), "Account": r["username"] or "-",
                                "Type": (r["role"] or "-").title(), "Event": EVENT_LABELS.get(r["event"], r["event"]),
                                "Details": r["detail"] or ""} for r in rows]), hide_index=True, width="stretch")
    st.page_link("views/mod_activity.py", label="Open the full activity log", icon=":material/timeline:")
else:
    st.caption("No activity yet.")
