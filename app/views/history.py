from datetime import datetime, time, timezone

import pandas as pd
import streamlit as st

import auth
import results
import ui
from state import client
from trustguard import reports
from trustguard.schemas import CATEGORY_LABELS, ScamCategory

auth.require()
ui.page_header("Scan history", "Your scans, stored in their redacted, audit-safe form. Original messages are never stored, and "
                                "other people can't see your scans.")
c = client()

with st.container(border=True):
    f1, f2, f3, f4, f5 = st.columns([1.6, 1.2, 1.1, 1.3, 1.4])
    search = f1.text_input("Search", placeholder="Scan ID, verdict or file name", key="h_search")
    risk = f2.multiselect("Risk level", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INCONCLUSIVE"], format_func=str.title, key="h_risk")
    itype = f3.multiselect("Input type", ["message", "url", "file"], format_func=str.title, key="h_type")
    cat = f4.selectbox("Detection category", [None] + [c_.value for c_ in ScamCategory],
                       format_func=lambda v: "Any" if v is None else CATEGORY_LABELS[ScamCategory(v)], key="h_cat")
    dates = f5.date_input("Date range", value=(), key="h_dates")

since = until = None
if isinstance(dates, tuple) and len(dates) == 2:
    since = datetime.combine(dates[0], time.min, tzinfo=timezone.utc)
    until = datetime.combine(dates[1], time.max, tzinfo=timezone.utc)
rows = c.list_scans(limit=1000, risk=risk or None, input_type=itype or None, category=cat, search=search or None, since=since, until=until)

if not rows:
    ui.empty_state("No matching scans", "Change the filters, or run a scan from the Message, URL or File scanner.")
    st.stop()

df = pd.DataFrame([{"Scan ID": r["scan_id"], "Date / time": pd.to_datetime(r["created_at"]).strftime("%Y-%m-%d %H:%M"), "Input type": r["input_type"],
                    "Risk": r["overall_risk"].title(), "Score": r["risk_score"], "Personal data": r["pii_count"], "Scam indicators": r["scam_count"],
                    "Status": {"clean": "redacted", "needs_review": "needs review", "blocked": "blocked", "n/a": "-"}.get(r["status"], r["status"]),
                    "Verdict": r["verdict"], "Demo": "yes" if r["demo"] else ""} for r in rows])
event = st.dataframe(df, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="h_table", height=320,
                     column_config={"Score": st.column_config.NumberColumn(format="%d")})
d1, d2, _ = st.columns([1, 1, 3])
d1.download_button("Export list (CSV)", reports.history_csv(rows).encode(), file_name="verioax-history.csv", mime="text/csv",
                   on_click="ignore", icon=":material/download:", width="stretch")

selected = None
if event and event.selection and event.selection.rows:
    selected = df.iloc[event.selection.rows[0]]["Scan ID"]
elif st.query_params.get("scan"):
    selected = st.query_params.get("scan")

if selected:
    r = c.get_scan(selected)
    if r is None:
        st.warning("That scan no longer exists (it may have been deleted or passed the retention period).")
    else:
        if d2.button("Delete this scan", icon=":material/delete:", width="stretch"):
            c.delete_scan(selected)
            st.query_params.clear()
            st.toast(f"Deleted {selected}")
            st.rerun()
        st.divider()
        st.subheader(f"Report {r.scan_id}")
        results.render(r, None, key=f"hist_{r.scan_id}", client=c)
else:
    st.caption("Select a scan to open its full report.")
