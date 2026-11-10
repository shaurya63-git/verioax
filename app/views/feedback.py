"""Consumer feedback: write to the moderators and read their replies."""
import streamlit as st

import auth
import ui
from state import accounts, client
from trustguard.accounts import FEEDBACK_KINDS, AccountError

user = auth.require("consumer")
ui.page_header("Feedback", "Tell the moderators what works, what doesn't, or about a result you think is wrong. Personal details in your "
                           "message are hidden automatically before it is saved.")
store = accounts()

n = st.session_state.get("fb_n", 0)                     # bumping n gives the form fresh, empty widgets after sending
prefill = st.session_state.pop("feedback_prefill", None)    # from "Report a wrong result" on a scan
if prefill:
    st.session_state[f"fb_kind_{n}"] = prefill.get("kind", "wrong_result")
    st.session_state[f"fb_scan_{n}"] = prefill.get("scan_id", "")
sent_id = st.session_state.pop("fb_sent", None)
if sent_id:
    st.success(f"Thanks - your message #{sent_id} has been sent to the moderators. Their reply will appear below.", icon=":material/check_circle:")

recent = client().list_scans(limit=40)
labels = {"": "Don't attach a scan"} | {r["scan_id"]: f"{r['scan_id']} - {r['overall_risk'].title()} - {r['verdict'][:50]}" for r in recent}
if st.session_state.get(f"fb_scan_{n}") and st.session_state[f"fb_scan_{n}"] not in labels:
    labels[st.session_state[f"fb_scan_{n}"]] = st.session_state[f"fb_scan_{n}"]

with st.container(border=True):
    kind = st.selectbox("What is it about?", list(FEEDBACK_KINDS), format_func=FEEDBACK_KINDS.get, key=f"fb_kind_{n}")
    subject = st.text_input("Subject", max_chars=120, key=f"fb_subject_{n}", placeholder="For example: a fake recharge offer was rated low risk")
    message = st.text_area("Your message", max_chars=4000, height=150, key=f"fb_message_{n}",
                           placeholder="What happened, and what did you expect to see?")
    scan_id = st.selectbox("Attach one of your scans (optional)", list(labels), format_func=labels.get, key=f"fb_scan_{n}",
                           help="Moderators will be able to open the redacted result of this one scan. Nothing else from your history is shared.")
    if st.button("Send to moderators", type="primary", icon=":material/send:", key=f"fb_send_{n}"):
        try:
            fid = store.add_feedback(user, kind, subject, message, scan_id=scan_id or None, session=auth.session_id(), client=auth.client_label())
        except AccountError as exc:
            st.error(str(exc), icon=":material/error:")
        else:
            st.session_state.fb_n = n + 1
            st.session_state.fb_sent = fid
            st.rerun()

st.subheader("Your messages")
mine = store.feedback(user_id=user.id)
if not mine:
    st.caption("You haven't sent any feedback yet.")
for fb in mine:
    color, label = ui.FEEDBACK_PILL.get(fb["status"], (ui.NEUTRAL, fb["status"]))
    with st.container(border=True):
        st.html(f"<div class='tg-fbhead'><b>{ui.esc(fb['subject'])}</b>{ui.pill(label, color)}"
                f"{ui.pill(FEEDBACK_KINDS.get(fb['kind'], fb['kind']), ui.NEUTRAL)}</div>"
                f"<div class='tg-meta'>#{fb['id']} - sent {ui.esc(ui.local_time(fb['created_at']))}"
                + (f" - about scan {ui.esc(fb['scan_id'])}" if fb["scan_id"] else "") + "</div>"
                + f"<div class='tg-fb'>{ui.esc(fb['message'])}</div>"
                + (f"<div class='tg-reply'><b>Reply from {ui.esc(fb['replied_by'] or 'a moderator')}</b>\n{ui.esc(fb['reply'])}</div>" if fb["reply"] else ""))
