"""My account: details, password, and the scans stored under this account."""
import streamlit as st

import auth
import ui
from state import accounts, client
from trustguard.accounts import AccountError

user = auth.require()
ui.page_header("My account", "Your account details, your password and the scans stored under your account.")
store = accounts()
c = client()

left, right = st.columns(2, gap="large")
with left:
    with st.container(border=True):
        st.markdown("**Account**")
        facts = [("Username", user.username), ("Email", user.email), ("Account type", "Moderator" if user.is_moderator else "Consumer"),
                 ("Created", ui.local_time(user.created_at)), ("Last sign-in", ui.local_time(user.last_login_at)),
                 ("Sign-ins", str(user.login_count))]
        st.html(ui.facts_table(facts))
    with st.container(border=True):
        st.markdown("**Your scans**")
        n = len(c.list_scans(limit=10000))
        st.write(f"{n} scan{'s' if n != 1 else ''} stored under your account (redacted text only).")
        confirm = st.checkbox("I understand this permanently deletes all my stored scans", key="acct_del_confirm")
        if st.button("Delete all my scans", icon=":material/delete:", disabled=not (confirm and n), key="acct_del"):
            st.toast(f"Deleted {c.clear_history()} scans")
            st.rerun()

with right:
    with st.container(border=True):
        st.markdown("**Change password**")
        with st.form("pw_form", clear_on_submit=True, border=False):
            cur = st.text_input("Current password", type="password", autocomplete="current-password")
            new = st.text_input("New password", type="password", autocomplete="new-password", help="At least 8 characters.")
            again = st.text_input("Confirm new password", type="password", autocomplete="new-password")
            if st.form_submit_button("Change password", type="primary"):
                try:
                    store.change_password(user, cur, new, again)
                except AccountError as exc:
                    st.error(str(exc), icon=":material/error:")
                else:
                    st.success("Password changed.", icon=":material/check_circle:")
    if user.is_moderator:
        st.caption("Moderators also enter the moderator security PIN at every sign-in. The PIN is set by the administrator in the "
                   "server's configuration, not per account.")
