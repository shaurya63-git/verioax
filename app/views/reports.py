import pandas as pd
import streamlit as st

import auth
import charts
import ui
from state import client
from trustguard import analytics, reports

auth.require("moderator")
ui.page_header("Reports & analytics", "Trends across everyone's scans, the items that need a human look, and downloadable reports. "
                                      "Reports contain placeholders and hashes, never raw personal data.")
c = client().everyone          # platform-wide: every account's scans (counts and redacted results only)
results = c.results(1000)
if not results:
    ui.empty_state("Nothing to report yet", "Run a few scans (or load the sample scans from the Dashboard) and the analytics will appear here.")
    st.stop()

s = analytics.summarize(results)
cols = st.columns(4)
files = [("PDF report", "pdf", "application/pdf", lambda: reports.analytics_pdf(s)), ("Markdown", "md", "text/markdown", lambda: reports.analytics_markdown(s).encode()),
         ("JSON", "json", "application/json", lambda: reports.analytics_json(s).encode()),
         ("CSV (scan list)", "csv", "text/csv", lambda: reports.history_csv(c.list_scans(limit=1000)).encode())]
for col, (label, ext, mime, fn) in zip(cols, files, strict=True):
    col.download_button(label, fn(), file_name=f"verioax-analytics.{ext}", mime=mime, on_click="ignore", icon=":material/download:",
                        width="stretch", key=f"an_{ext}")
if s["totals"]["demo_scans"]:
    st.caption(f"Includes {s['totals']['demo_scans']} sample (demo) scans.")

tab_threat, tab_privacy, tab_review, tab_eval = st.tabs(["Threats", "Personal data", f"Review queue ({len(s['review_queue'])})", "Detection quality"])

with tab_threat:
    a, b = st.columns(2, gap="large")
    with a:
        st.markdown("**Findings by category**")
        charts.hbar(s["categories"], label="Findings", empty="No scam indicators yet")
        st.markdown("**Confidence of verdicts**")
        charts.hbar(s["confidence_distribution"], sort=False, label="Scans")
    with b:
        st.markdown("**Risk distribution**")
        charts.risk_bars(s["risk_distribution"])
        st.markdown("**Link assessments**")
        charts.risk_bars(s["url_assessments"])
    st.markdown("**Most frequent threat indicators**")
    charts.hbar(s["top_indicators"], label="Times seen")
    st.markdown("**Scans per day**")
    charts.timeline(s["scans_per_day"])

with tab_privacy:
    sw = s["leak_sweep"]
    m = st.columns(4)
    m[0].metric("Scans with personal data", sw["scans_with_pii"], border=True)
    m[1].metric("Average redaction coverage", f"{s['redaction_coverage']:.0%}" if s["redaction_coverage"] is not None else "-", border=True)
    m[2].metric("Caught by leak sweep", sw["caught"], border=True)
    m[3].metric("Scans blocked (still readable)", sw["blocked_scans"], border=True)
    st.markdown("**Personal data by type**")
    charts.hbar(s["pii_types"], label="Items", empty="No personal data found yet")
    st.caption("Redaction coverage is the share of detected items replaced in the output. The leak sweep re-scans every redacted output; "
               "a scan is 'blocked' if anything was still readable after the last sweep round.")

with tab_review:
    if s["review_queue"]:
        st.dataframe(pd.DataFrame(s["review_queue"]).rename(columns=str.title), hide_index=True, width="stretch", height=380)
        st.caption("Low-confidence personal data, links that couldn't be verified, claims that need checking and extraction problems.")
    else:
        st.success("Nothing is waiting for review.", icon=":material/check_circle:")

with tab_eval:
    st.markdown("Run Verioax on its labelled regression set: fake e-challan, KYC, prize, task, investment and 'digital arrest' scams, "
                "hoax forwards, and genuine messages that look similar (bank OTPs, official e-challans, scam-awareness notices).")
    st.warning("These messages were written alongside the detection rules, so the numbers show whether the rules still behave as designed. "
               "They are not an independent measure of real-world accuracy.", icon=":material/info:")
    if st.button("Run the regression set", icon=":material/play_arrow:"):
        from trustguard.evaluation import run
        with st.spinner("Analysing the labelled messages offline..."):
            st.session_state.eval = run()
    ev = st.session_state.get("eval")
    if ev:
        m = st.columns(4)
        fmt = lambda v: "-" if v is None else f"{v:.0%}"  # noqa: E731
        m[0].metric("Threats rated high/critical", fmt(ev["threat_detection_rate"]), border=True)
        m[1].metric("Hoaxes flagged", fmt(ev["hoax_flag_rate"]), border=True)
        m[2].metric("Unverifiable links flagged", fmt(ev["suspicious_flag_rate"]), border=True)
        m[3].metric("Genuine messages wrongly flagged", fmt(ev["benign_false_positive_rate"]), border=True)
        st.dataframe(pd.DataFrame(ev["rows"]).rename(columns=str.title), hide_index=True, width="stretch", height=360)
