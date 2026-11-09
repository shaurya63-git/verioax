import streamlit as st

import results
import ui
from client import ClientError
from state import client
from trustguard.demo import SAMPLE_URLS

ui.page_header("URL scanner", "Check a link before you open it. TrustGuard never opens it in your browser: it inspects the address, "
                              "and - when live checks are on - visits it from the backend's guarded fetcher and asks threat-intelligence services about it.")


def use_sample() -> None:
    if st.session_state.get("url_sample"):
        st.session_state.url_text = st.session_state.url_sample
        st.session_state.pop("url_result", None)


with st.container(border=True):
    st.pills("Try a sample", SAMPLE_URLS, key="url_sample", on_change=use_sample)
    url = st.text_input("Link", key="url_text", placeholder="https://example.com/... (defanged links such as hxxps://site[.]com also work)")
    b1, _ = st.columns([1, 3])
    go = b1.button("Check link", type="primary", icon=":material/link:", width="stretch", disabled=not (url or "").strip())
    prefs = client().get_prefs()
    if not prefs.network_checks:
        st.caption("Live checks are off (local mode): the link is analysed from its address only. Turn them on in Settings for redirects, page content, certificate and domain age.")

if go:
    with st.spinner("Inspecting the link..."):
        try:
            st.session_state.url_result = client().scan_url(url)
        except ClientError as exc:
            st.error(str(exc), icon=":material/error:")

res = st.session_state.get("url_result")
if res:
    st.space("small")
    results.render(res.result, res.original_text, key="url", client=client())
