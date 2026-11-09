import streamlit as st

import results
import ui
from client import ClientError
from state import client
from trustguard.demo import SAMPLES
from trustguard.schemas import AnalysisMode

MODES = {AnalysisMode.FULL: "Full security analysis", AnalysisMode.SCAM: "Scam & hoax only", AnalysisMode.PII: "Personal data only"}

ui.page_header("Message scanner", "Paste an SMS, WhatsApp message, email or social media message you received. "
                                  "TrustGuard checks it for scam and hoax signals, checks every link it contains, and removes personal data.")


def use_sample() -> None:
    label = st.session_state.get("msg_sample")
    s = next((x for x in SAMPLES if x["label"] == label), None)
    if s:
        st.session_state.msg_text, st.session_state.msg_sender = s["text"], s["sender"]
        st.session_state.pop("msg_result", None)


def clear() -> None:
    for k in ("msg_text", "msg_sender", "msg_result", "msg_sample"):
        st.session_state.pop(k, None)


with st.container(border=True):
    st.pills("Try a sample", [s["label"] for s in SAMPLES], key="msg_sample", on_change=use_sample)
    text = st.text_area("Message", key="msg_text", height=170, max_chars=20_000,
                        placeholder="Paste the message here, exactly as you received it - links included. Links are never opened in your browser.")
    left, right = st.columns([1, 1.25], gap="medium")
    sender = left.text_input("Sender (optional)", key="msg_sender", placeholder="VM-HDFCBK-S, +91 98xxx xxxxx or an email address",
                             help="What your phone showed as the sender. Registered business SMS headers end in -P, -S, -T or -G (government).")
    mode = right.segmented_control("Checks to run", list(MODES), format_func=MODES.get, default=AnalysisMode.FULL, key="msg_mode",
                                   required=True)
    b1, b2, _ = st.columns([1, 0.6, 2.4])
    go = b1.button("Check message", type="primary", icon=":material/shield:", width="stretch", disabled=not (text or "").strip())
    b2.button("Clear", on_click=clear, width="stretch")
    st.caption("Language is detected automatically (English, Hindi and Hinglish).")

if go:
    with st.spinner("Checking the message, its links and any personal data..."):
        try:
            st.session_state.msg_result = client().scan_message(text, sender, mode or AnalysisMode.FULL)
        except ClientError as exc:
            st.error(str(exc), icon=":material/error:")

res = st.session_state.get("msg_result")
if res:
    st.space("small")
    results.render(res.result, res.original_text, key="msg", client=client())
