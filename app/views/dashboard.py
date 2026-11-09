import pandas as pd
import streamlit as st

import charts
import ui
from client import ClientError
from state import client
from trustguard import analytics
from trustguard.demo import SAMPLES
from trustguard.schemas import AnalysisMode

ui.page_header("Dashboard", "An overview of everything you have checked: how risky it was, what kind of scams turned up and how much personal data was removed.")
c = client()


def load_demo() -> None:
    with st.spinner("Analysing the sample messages with the real engine..."):
        for s in SAMPLES:
            try:
                c.scan_message(s["text"], s["sender"] or None, AnalysisMode.FULL, demo=True)
            except ClientError as exc:
                st.error(str(exc))
                return
    st.toast("Sample scans added. They are marked as demo data.", icon=":material/science:")


q1, q2, q3, _ = st.columns([1, 1, 1, 1.2])
if q1.button("Analyse a message", icon=":material/sms:", type="primary", width="stretch"):
    st.switch_page("views/scan_message.py")
if q2.button("Check a link", icon=":material/link:", width="stretch"):
    st.switch_page("views/scan_url.py")
if q3.button("Upload a file", icon=":material/upload_file:", width="stretch"):
    st.switch_page("views/scan_file.py")

results = c.results(1000)
if not results:
    st.space("small")
    ui.empty_state("No scans yet",
                   "Paste a suspicious SMS or WhatsApp message, check a link, or upload a document to get started. "
                   "To see what a report looks like first, load a few sample scans - they are analysed by the real engine and labelled as demo data.")
    st.space("small")
    if st.button("Load sample scans", icon=":material/science:"):
        load_demo()
        st.rerun()
    st.stop()

s = analytics.summarize(results)
t = s["totals"]
if t["demo_scans"]:
    st.info(f"{t['demo_scans']} of {t['scans']} scans are sample (demo) data. Remove them in Settings > Data.", icon=":material/science:")

tiles = [("Total scans", t["scans"]), ("Suspicious messages", t["suspicious_messages"]), ("Potential scams", t["potential_scams"]),
         ("Suspicious links", t["suspicious_urls"]), ("Personal data items", t["pii_findings"]), ("High-risk detections", t["high_risk"])]
cols = st.columns(6)
for col, (label, value) in zip(cols, tiles, strict=True):
    col.metric(label, value, border=True)

a, b = st.columns(2, gap="large")
with a:
    st.subheader("Risk distribution")
    charts.risk_bars(s["risk_distribution"])
with b:
    st.subheader("Detection categories")
    cats = dict(s["categories"])
    if s["pii_types"]:
        cats["Personal data exposure"] = sum(1 for r in results if r.pii_findings)
    charts.hbar(cats, label="Findings", empty="No scam indicators found yet")

st.subheader("Recent scans")
rows = c.list_scans(limit=12)
df = pd.DataFrame([{"Scan ID": r["scan_id"], "When": pd.to_datetime(r["created_at"]).strftime("%d %b, %H:%M"), "Input": r["input_type"],
                    "Risk": r["overall_risk"].title(), "Verdict": r["verdict"], "Scam indicators": r["scam_count"], "Personal data": r["pii_count"],
                    "Demo": "yes" if r["demo"] else ""} for r in rows])
event = st.dataframe(df, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="dash_recent")
st.caption("Select a row to open the full report.")
if event and event.selection and event.selection.rows:
    st.switch_page("views/history.py", query_params={"scan": df.iloc[event.selection.rows[0]]["Scan ID"]})
