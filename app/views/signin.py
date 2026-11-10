"""Public entry page: sign in or create an account (consumer or moderator)."""
import streamlit as st

import auth
from state import accounts
from trustguard.accounts import AccountError

store = accounts()
ROLES = {"consumer": "Consumer", "moderator": "Moderator"}

left, gap, right = st.columns([1.15, 0.12, 1], vertical_alignment="top")

with left:
    st.html("""
<div class="tg-hero">
  <h1>Check a message before you trust it.</h1>
  <p>Verioax hides your personal details first, then checks messages, links and documents for scams and hoaxes,
     and tells you why it reached its verdict.</p>
  <div class="tg-sample" role="img" aria-label="Example: a fake e-challan message with personal details replaced by placeholders and the scam wording highlighted, rated critical risk">
    <div class="lbl">What Verioax shows you</div>
    <div class="txt">Dear <span class="ph">[PERSON_001]</span>, your vehicle <span class="ph">[VEHICLE_REG_001]</span> has a
      <span class="bad">pending e-challan</span> of Rs 590. <span class="bad">Pay immediately</span> to avoid licence suspension:
      hxxps://echallan-pay[.]vip/pay</div>
    <div class="verdict">Critical risk: claims to be Parivahan, asks for payment, links to a site Parivahan doesn't own</div>
  </div>
  <ul class="tg-steps">
    <li><b>Consumers</b> scan messages, links and files, keep their own history and can send feedback.</li>
    <li><b>Moderators</b> also see accounts, activity and consumer feedback. They need the moderator security PIN.</li>
  </ul>
</div>""")

with right:
    notice = st.session_state.pop("auth_notice", None)
    if notice:
        st.info(notice, icon=":material/info:")
    with st.container(border=True):
        sign_in_tab, sign_up_tab = st.tabs(["Sign in", "Create account"], key="auth_tabs")

        with sign_in_tab:
            role = st.segmented_control("Sign in as", list(ROLES), format_func=ROLES.get, default="consumer", key="signin_role",
                                        required=True)
            with st.form("signin_form", border=False):
                ident = st.text_input("Username or email", key="signin_ident", autocomplete="username")
                password = st.text_input("Password", type="password", key="signin_pw", autocomplete="current-password")
                pin = None
                if role == "moderator":
                    pin = st.text_input("Moderator security PIN", type="password", max_chars=6, key="signin_pin",
                                        help="The 6-digit PIN given to moderators. It is checked every time you sign in.")
                go = st.form_submit_button("Sign in", type="primary", width="stretch", icon=":material/login:")
            if go:
                if not ident.strip() or not password:
                    st.error("Enter your username or email and your password.")
                else:
                    try:
                        user = store.authenticate(ident, password, role, pin=pin, session=auth.session_id(), client=auth.client_label())
                    except AccountError as exc:
                        st.error(str(exc), icon=":material/error:")
                    else:
                        auth.sign_in(user)
                        st.rerun()

        with sign_up_tab:
            new_role = st.segmented_control("Account type", list(ROLES), format_func=ROLES.get, default="consumer", key="signup_role",
                                            required=True)
            if new_role == "moderator" and not store.pin_configured:
                st.warning("Moderator accounts aren't enabled on this server yet. The administrator has to set VERIOAX_MODERATOR_PIN "
                           "(see the README).", icon=":material/lock:")
            with st.form("signup_form", border=False):
                email = st.text_input("Email address", key="signup_email", autocomplete="email")
                username = st.text_input("Username", key="signup_user", autocomplete="username",
                                         help="3-30 characters: letters, numbers, dots, dashes or underscores.")
                pw1 = st.text_input("Password", type="password", key="signup_pw", autocomplete="new-password",
                                    help="At least 8 characters. A short sentence is easier to remember and harder to guess.")
                pw2 = st.text_input("Confirm password", type="password", key="signup_pw2", autocomplete="new-password")
                new_pin = None
                if new_role == "moderator":
                    new_pin = st.text_input("Moderator security PIN", type="password", max_chars=6, key="signup_pin",
                                            help="Ask the Verioax administrator for the 6-digit moderator PIN.")
                made = st.form_submit_button("Create account", type="primary", width="stretch", icon=":material/person_add:")
            if made:
                try:
                    user = store.create_user(username, email, pw1, new_role, pin=new_pin, confirm=pw2, session=auth.session_id(),
                                             client=auth.client_label())
                except AccountError as exc:
                    st.error(str(exc), icon=":material/error:")
                else:
                    user = store.authenticate(username, pw1, new_role, pin=new_pin, session=auth.session_id(), client=auth.client_label())
                    auth.sign_in(user)
                    st.rerun()
    st.caption("Your password is stored only as a salted scrypt hash. Five wrong attempts lock an account for 15 minutes.")
