"""Accounts: every consumer and moderator, their status, and moderator actions (suspend, reactivate, unlock)."""
import pandas as pd
import streamlit as st

import auth
import ui
from state import accounts
from trustguard.accounts import EVENT_LABELS, AccountError

me = auth.require("moderator")
ui.page_header("Accounts", "Every consumer and moderator account, its status and recent activity. Suspending an account signs it out "
                           "and stops it signing in again until you reactivate it.")
store = accounts()

f1, f2, f3 = st.columns([1.1, 1.6, 1.3], vertical_alignment="bottom")
role = f1.segmented_control("Account type", ["all", "consumer", "moderator"], format_func={"all": "All", "consumer": "Consumers",
                                                                                          "moderator": "Moderators"}.get,
                            default="all", key="acc_role", required=True)
state = f2.segmented_control("Status", ["all", "online", "active", "locked", "suspended"],
                             format_func=lambda s: "All" if s == "all" else ui.STATE_PILL[s][1], default="all", key="acc_state", required=True)
search = f3.text_input("Search", placeholder="Username or email", key="acc_search", label_visibility="collapsed")

rows = store.list_users()
view = [r for r in rows if (role == "all" or r["role"] == role) and (state == "all" or r["state"] == state)
        and (not search or search.lower() in r["username"].lower() or search.lower() in r["email"].lower())]
st.caption(f"{len(view)} of {len(rows)} account(s)")
if not view:
    ui.empty_state("No accounts match", "Change the filters above.")
    st.stop()

df = pd.DataFrame([{"Username": r["username"], "Email": r["email"], "Type": r["role"].title(), "Status": ui.STATE_PILL[r["state"]][1],
                    "Created": ui.local_time(r["created_at"], "%d %b %Y"), "Last sign-in": ui.local_time(r["last_login_at"], "%d %b, %H:%M"),
                    "Last seen": ui.local_time(r["last_seen_at"], "%d %b, %H:%M"), "Sign-ins": r["login_count"], "Scans": r["scans"],
                    "Feedback": r["feedback"], "Failed attempts": r["failed_attempts"]} for r in view])
sel = st.dataframe(df, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="acc_table")
picked = sel.selection.rows if sel and sel.selection else []
if not picked:
    st.caption("Select an account to see its details and activity.")
    st.stop()

target = view[picked[0]]
color, word = ui.STATE_PILL[target["state"]]
with st.container(border=True):
    st.html(f"<div class='tg-fbhead'><b>{ui.esc(target['username'])}</b>{ui.pill(word, color)}"
            f"{ui.pill(target['role'].title(), ui.NEUTRAL)}</div>")
    a, b = st.columns([1.2, 1], gap="large")
    with a:
        st.html(ui.facts_table([("Email", target["email"]), ("Created", ui.local_time(target["created_at"])),
                                ("Last sign-in", ui.local_time(target["last_login_at"])), ("Last seen", ui.local_time(target["last_seen_at"])),
                                ("Sign-ins", target["login_count"]), ("Scans run", target["scans"]), ("Feedback sent", target["feedback"]),
                                ("Failed attempts", target["failed_attempts"])]))
    with b:
        if target["id"] == me.id:
            st.caption("This is your own account. Another moderator has to change its status.")
        else:
            if target["status"] == "active":
                if st.button("Suspend account", icon=":material/block:", key=f"susp_{target['id']}", width="stretch"):
                    try:
                        store.set_status(me, target["id"], "suspended")
                        st.toast(f"Suspended {target['username']}")
                        st.rerun()
                    except AccountError as exc:
                        st.error(str(exc))
            else:
                if st.button("Reactivate account", icon=":material/check_circle:", key=f"react_{target['id']}", type="primary", width="stretch"):
                    try:
                        store.set_status(me, target["id"], "active")
                        st.toast(f"Reactivated {target['username']}")
                        st.rerun()
                    except AccountError as exc:
                        st.error(str(exc))
            if target["state"] == "locked" or target["failed_attempts"]:
                if st.button("Unlock and reset failed attempts", icon=":material/lock_open:", key=f"unlock_{target['id']}", width="stretch"):
                    store.unlock(me, target["id"])
                    st.toast(f"Unlocked {target['username']}")
                    st.rerun()

    st.markdown("**Recent activity**")
    events = store.activity(user_id=target["id"], limit=25)
    if events:
        st.dataframe(pd.DataFrame([{"When": ui.local_time(e["at"], "%d %b, %H:%M"), "Event": EVENT_LABELS.get(e["event"], e["event"]),
                                    "Details": e["detail"] or "", "Browser": e["client"] or ""} for e in events]),
                     hide_index=True, width="stretch")
    else:
        st.caption("No activity recorded for this account.")
