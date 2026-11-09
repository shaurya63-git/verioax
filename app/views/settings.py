import streamlit as st

import ui
from state import client
from trustguard import __version__
from trustguard.config import get_settings

ui.page_header("Settings", "Detection thresholds, what may be sent online, and how long scan history is kept.")
c = client()
p = c.get_prefs()

tab_det, tab_net, tab_data, tab_keys = st.tabs(["Detection", "Network & privacy", "Data & history", "API keys"], key="set_tabs")

with tab_det:
    st.markdown("**Scam detection sensitivity**")
    sens = st.segmented_control("Sensitivity", ["conservative", "balanced", "aggressive"], default=p.scam_sensitivity, required=True,
                                format_func=str.title, label_visibility="collapsed", key="s_sens")
    st.caption("Balanced: Medium from score 25, High from 50, Critical from 75. Conservative: 30 / 55 / 80 and minor signals are ignored. "
               "Aggressive: 20 / 45 / 70.")
    st.markdown("**Personal data detection**")
    a, b = st.columns(2, gap="large")
    min_conf = a.slider("Minimum confidence to redact", 0.30, 0.90, float(p.pii_min_confidence), 0.05, key="s_minconf",
                        help="Lower values redact more: fewer leaks, more false alarms.")
    review = b.slider("Send to human review below", 0.40, 0.95, float(p.pii_review_threshold), 0.05, key="s_review")
    sweeps = a.slider("Leak-sweep rounds", 0, 3, int(p.leak_sweep_rounds), key="s_sweeps",
                      help="How many times the redacted output is re-scanned and patched.")
    lang = b.selectbox("Message language", ["auto", "en", "hi", "hinglish"], index=["auto", "en", "hi", "hinglish"].index(p.language), key="s_lang",
                       format_func={"auto": "Detect automatically", "en": "English", "hi": "Hindi", "hinglish": "Hinglish"}.get,
                       help="Used for the optional AI explanation. The detection rules always cover English, Hinglish and common Hindi phrases.")
    ner = st.toggle("Use spaCy name recognition when it is installed", p.use_ner, key="s_ner")

with tab_net:
    local = st.toggle("Local processing mode: nothing is sent online", p.local_mode, key="s_local",
                      help="Turns off live link checks, threat-intelligence lookups, the OpenPhish feed and fact-check lookups.")
    st.caption("In local mode links are judged from their address only, and links that can't be verified are reported as inconclusive.")
    a, b = st.columns(2, gap="large")
    live = a.toggle("Live link checks (guarded backend fetch, certificate, domain age)", p.network_checks and not local, disabled=local, key="s_live")
    intel = b.toggle("Threat-intelligence lookups", p.intel_lookups and not local, disabled=local, key="s_intel")
    feed = a.toggle("Download the OpenPhish community feed (refreshed every 12 hours)", p.openphish_feed and not local, disabled=local, key="s_feed")
    fc = b.toggle("Fact-check lookups for claims", p.factcheck_lookups and not local, disabled=local, key="s_fc")
    st.markdown("**Privacy**")
    redact = st.toggle("Always redact personal data (only redacted text is ever stored)", p.auto_redact, key="s_redact")
    llm = st.toggle("Plain-language explanation from a local AI model (Ollama)", p.llm_explanations, key="s_llm",
                    help="The model receives only the redacted message and the findings. It cannot change the verdict and never visits links.")

with tab_data:
    a, b, c3 = st.columns(3, gap="large")
    store = a.toggle("Keep scan history", p.store_history, key="s_store")
    retention = b.number_input("Delete scans older than (days)", 1, 365, int(p.retention_days), key="s_ret")
    max_urls = c3.number_input("Links checked per message (max)", 1, 10, int(p.max_urls_per_scan), key="s_maxurls")

if st.button("Save settings", type="primary", icon=":material/save:"):
    new = p.model_copy(update=dict(
        scam_sensitivity=sens, pii_min_confidence=min_conf, pii_review_threshold=review, leak_sweep_rounds=sweeps, use_ner=ner, language=lang,
        network_checks=bool(live and not local), intel_lookups=bool(intel and not local), openphish_feed=bool(feed and not local),
        factcheck_lookups=bool(fc and not local), llm_explanations=llm, auto_redact=redact, store_history=store, retention_days=int(retention),
        max_urls_per_scan=int(max_urls)))
    c.save_prefs(new)
    st.toast("Settings saved", icon=":material/check:")
    st.rerun()

with tab_data:
    st.divider()
    st.markdown("**Stored data**")
    if c.kind == "local":
        x, y, z = st.columns(3, gap="medium")
        if x.button("Delete sample (demo) scans", width="stretch"):
            st.toast(f"Deleted {c.clear_history(demo_only=True)} sample scans")
        if y.button("Clear lookup cache", width="stretch", help="Cached domain-age, certificate and threat-intelligence answers"):
            st.toast(f"Cleared {c.clear_cache()} cached answers")
        confirm = z.checkbox("I want to delete all scan history")
        if z.button("Delete all scan history", disabled=not confirm, width="stretch"):
            st.toast(f"Deleted {c.clear_history()} scans")
    else:
        st.info("History is managed by the API server.")

with tab_keys:
    s = get_settings()
    st.markdown("API keys are read from environment variables or a `.env` file. They are never shown here, logged, or returned by the API.")
    for name, ok in s.configured_services().items():
        st.markdown(f":{'green' if ok else 'gray'}-badge[{'configured' if ok else 'not set'}] {name.replace('_', ' ').title()}")
    st.caption("See Threat intelligence > How to add API keys. Restart the app after editing .env.")

st.caption(f"Verioax {__version__} - data folder: {get_settings().data_dir} - client: {c.kind}")
