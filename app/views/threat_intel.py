import pandas as pd
import streamlit as st

import ui
from client import ClientError
from state import client

ui.page_header("Threat intelligence", "The outside sources Verioax can ask about a link, whether each one is set up and working, "
                                      "and the local list of known scam domains.")
c = client()

STATE_BADGE = {"working (tested)": "green", "configured, not tested yet": "blue", "error on last test": "red", "not configured": "gray",
               "turned off": "gray"}
ENV = {"google_safe_browsing": "GOOGLE_SAFE_BROWSING_API_KEY", "virustotal": "VIRUSTOTAL_API_KEY", "urlhaus": "URLHAUS_AUTH_KEY",
       "phishtank": "PHISHTANK_APP_KEY (+ PHISHTANK_USERNAME)", "openphish": "Settings > Network > OpenPhish feed",
       "google_factcheck": "GOOGLE_FACTCHECK_API_KEY", "local_ioc": "built in"}

st.subheader("Sources")
st.caption("How a result was obtained is always shown on the link report: live API call, cached answer, local list, or not checked. "
           "A source is only reported as working after a successful test from this installation.")
for row in c.intel_status():
    with st.container(border=True):
        a, b, cbtn = st.columns([2.2, 2.6, 1])
        state = row["state"]
        color = "green" if state.startswith("active") else STATE_BADGE.get(state, "gray")
        a.markdown(f"**{row['label']}**  \n:{color}-badge[{state}]")
        if row["provider"] == "local_ioc":
            detail = "Mode: local list. Built in; add your own indicators below."
        else:
            detail = f"Mode: {row['mode']}. Configure with `{ENV.get(row['provider'], '-')}`."
        if row.get("last_test"):
            detail += f"  \nLast test {row['last_test']}: {row.get('last_result', '')}"
        b.markdown(detail)
        if row["provider"] != "local_ioc":
            if cbtn.button("Test", key=f"test_{row['provider']}", disabled=not row["configured"], width="stretch",
                           help="Sends one lookup for a harmless test address" if row["configured"] else "Add the API key first"):
                try:
                    res = c.test_provider(row["provider"])
                    (st.toast if res.get("ok") else st.error)(f"{row['label']}: {res.get('result')}")
                except ClientError as exc:
                    st.error(str(exc))
                st.rerun()

with st.expander("How to add API keys", icon=":material/key:"):
    st.markdown("""
Keys are read from environment variables or a `.env` file next to the app - never typed into the browser and never shown, logged or returned by the API.

1. Copy `.env.example` to `.env`.
2. Fill in the keys you have (all are optional):
   - **Google Safe Browsing** - free for non-commercial use; create a key in Google Cloud and enable the *Safe Browsing API*.
   - **VirusTotal** - free community key (rate limited to a few lookups per minute).
   - **URLhaus (abuse.ch)** - free Auth-Key from auth.abuse.ch; required for all API queries since mid-2025.
   - **PhishTank** - application key, if you have one.
   - **Google Fact Check Tools** - used for the 'claims to check' section.
3. Restart the app, then press **Test** here.

Privacy: a lookup sends the link to that service. Verioax removes query parameters that carry personal data before any lookup.
""")

st.subheader("Local indicator list")
if c.kind != "local":
    st.info("The local list is managed on the API server (data/runtime/iocs_user.txt).")
else:
    st.caption(f"{c.seed_ioc_count()} published indicators ship with Verioax (fake e-challan, courier and bank phishing domains from a December 2025 "
               "campaign report). Add your own below - matches count as confirmed threat indicators.")
    with st.form("add_ioc", clear_on_submit=True, border=True):
        x, y = st.columns([3, 1], vertical_alignment="bottom")
        ind = x.text_input("Domain, URL or IP address", placeholder="fake-challan.example or 203.0.113.7 (defanged input is fine)")
        if y.form_submit_button("Add indicator", width="stretch") and ind.strip():
            c.add_ioc(ind.strip())
            st.toast(f"Added {ind.strip()}")
    mine = c.user_iocs()
    if mine:
        for i, v in enumerate(mine):
            p, q = st.columns([4, 1], vertical_alignment="center")
            p.markdown(f"`{v.replace('.', '[.]')}`")
            if q.button("Remove", key=f"rm_{i}", width="stretch"):
                c.remove_ioc(v)
                st.rerun()
    else:
        st.caption("You haven't added any indicators yet.")

st.subheader("Recent threat-intelligence matches")
hits = []
for r in c.results(500):
    for u in r.urls:
        for rep in u.reputation:
            if rep.status in ("listed", "suspicious"):
                hits.append({"Scan": r.scan_id, "When": r.created_at.strftime("%Y-%m-%d %H:%M"), "Link": u.defanged, "Source": rep.provider,
                             "Result": rep.status, "Details": rep.verdict})
if hits:
    st.dataframe(pd.DataFrame(hits), hide_index=True, width="stretch")
else:
    st.caption("No link in your history has matched a threat-intelligence source yet.")
