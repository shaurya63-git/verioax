"""Consumer feedback inbox: read, open attached scans, set a status and reply."""
import streamlit as st

import auth
import ui
from state import accounts, client
from trustguard.accounts import FEEDBACK_KINDS, FEEDBACK_STATUSES, AccountError

me = auth.require("moderator")
ui.page_header("Consumer feedback", "Feedback, complaints and results consumers think are wrong. Personal details were hidden before the "
                                    "messages were saved. Replies are shown to the consumer on their Feedback page.")
store = accounts()
counts = store.feedback_counts()

FILTERS = {"open": f"Open ({counts['new'] + counts['in_review']})", "new": f"New ({counts['new']})",
           "in_review": f"In review ({counts['in_review']})", "resolved": f"Resolved ({counts['resolved']})", "all": "All"}
f1, f2 = st.columns([2.4, 1], vertical_alignment="bottom")
which = f1.segmented_control("Show", list(FILTERS), format_func=FILTERS.get, default="open", key="fbm_filter", required=True)
kind = f2.selectbox("Kind", ["all", *FEEDBACK_KINDS], format_func=lambda k: "All kinds" if k == "all" else FEEDBACK_KINDS[k], key="fbm_kind")

status = {"open": ["new", "in_review"], "all": None}.get(which, [which])
items = [f for f in store.feedback(status=status) if kind == "all" or f["kind"] == kind]
if not items:
    ui.empty_state("Nothing here", "No feedback matches this filter.")
    st.stop()

for fb in items:
    color, label = ui.FEEDBACK_PILL.get(fb["status"], (ui.NEUTRAL, fb["status"]))
    with st.container(border=True):
        st.html(f"<div class='tg-fbhead'><b>{ui.esc(fb['subject'])}</b>{ui.pill(label, color)}"
                f"{ui.pill(FEEDBACK_KINDS.get(fb['kind'], fb['kind']), ui.NEUTRAL)}</div>"
                f"<div class='tg-meta'>#{fb['id']} from <b>{ui.esc(fb['username'])}</b> - {ui.esc(ui.local_time(fb['created_at']))}</div>"
                f"<div class='tg-fb'>{ui.esc(fb['message'])}</div>"
                + (f"<div class='tg-reply'><b>Reply from {ui.esc(fb['replied_by'] or 'a moderator')}</b>\n{ui.esc(fb['reply'])}</div>"
                   if fb["reply"] else ""))
        if fb["scan_id"]:
            with st.expander(f"Attached scan {fb['scan_id']}", icon=":material/description:"):
                r = client().everyone.get_scan(fb["scan_id"])
                if r is None:
                    st.caption("This scan is no longer stored (it was deleted or passed the retention period).")
                else:
                    st.html(ui.verdict_panel(r))
                    found = [f for f in r.scam_findings if f.severity.value != "info"]
                    if found:
                        st.markdown("**Findings**")
                        st.html("<ul>" + "".join(f"<li>{ui.esc(f.title)} <span class='tg-meta'>({ui.esc(f.severity.value)}, "
                                                 f"{ui.esc(f.strength.value)})</span></li>" for f in found[:12]) + "</ul>")
                    if r.redacted_text:
                        st.markdown("**Redacted text**")
                        st.code(r.redacted_text[:3000], language=None, wrap_lines=True)
                    st.caption("Only the redacted, audit-safe result is shown. The consumer chose to share this scan.")
        with st.form(f"fbm_form_{fb['id']}", border=False):
            c1, c2 = st.columns([1, 2.6], vertical_alignment="bottom")
            new_status = c1.selectbox("Status", list(FEEDBACK_STATUSES), index=list(FEEDBACK_STATUSES).index(fb["status"]),
                                      format_func=FEEDBACK_STATUSES.get, key=f"fbm_status_{fb['id']}")
            reply = c2.text_area("Reply to the consumer", value=fb["reply"] or "", height=80, max_chars=2000, key=f"fbm_reply_{fb['id']}",
                                 placeholder="Optional. The consumer sees this on their Feedback page.")
            if st.form_submit_button("Save", icon=":material/save:"):
                try:
                    store.update_feedback(me, fb["id"], status=new_status, reply=reply)
                    st.toast(f"Updated #{fb['id']}")
                    st.rerun()
                except AccountError as exc:
                    st.error(str(exc))
