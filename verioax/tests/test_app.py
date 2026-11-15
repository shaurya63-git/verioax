"""Headless tests of the Streamlit UI (Streamlit's AppTest): sign-in for consumers and moderators, every page of both UIs
renders without an exception, scans work, and feedback travels from a consumer to the moderators."""
import itertools
from pathlib import Path

import pytest
from conftest import TEST_PIN

APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"
CONSUMER_PAGES = ["views/dashboard.py", "views/scan_message.py", "views/scan_url.py", "views/scan_file.py", "views/history.py",
                  "views/feedback.py", "views/account.py"]
MODERATOR_PAGES = ["views/mod_overview.py", "views/mod_accounts.py", "views/mod_activity.py", "views/mod_feedback.py", "views/scan_message.py",
                   "views/history.py", "views/threat_intel.py", "views/reports.py", "views/settings.py", "views/account.py"]
_n = itertools.count()


@pytest.fixture(scope="module")
def at_factory():
    st_testing = pytest.importorskip("streamlit.testing.v1")

    def make():
        return st_testing.AppTest.from_file(str(APP), default_timeout=60)
    return make


def _ok(at):
    assert not at.exception, [e.value for e in at.exception]


def _html(at) -> str:
    return " ".join(h.value for h in at.get("html"))


def sign_up(at_factory, role="consumer", pin=None):
    """Create an account through the sign-in page and return the signed-in app and its username."""
    at = at_factory()
    at.run()
    name = f"{role[:3]}{next(_n)}user"
    at.button_group(key="signup_role").set_value(role).run()
    at.text_input(key="signup_email").set_value(f"{name}@example.com")
    at.text_input(key="signup_user").set_value(name)
    at.text_input(key="signup_pw").set_value("long enough pw 9")
    at.text_input(key="signup_pw2").set_value("long enough pw 9")
    if role == "moderator":
        at.text_input(key="signup_pin").set_value(pin or TEST_PIN)
    next(b for b in at.button if b.label == "Create account").click().run()
    return at, name


def test_visitors_only_see_the_sign_in_page(at_factory):
    at = at_factory()
    at.run()
    _ok(at)
    assert "Check a message before you trust it" in _html(at)
    assert "Founded by: <b>Shaurya Shah</b>" in _html(at)
    assert "uid" not in at.session_state


@pytest.mark.parametrize("page", CONSUMER_PAGES)
def test_consumer_pages_render(at_factory, page):
    at, _ = sign_up(at_factory)
    at.switch_page(page).run()
    _ok(at)
    assert "Founded by: <b>Shaurya Shah</b>" in _html(at)


def test_consumers_cannot_open_moderator_pages(at_factory):
    at, _ = sign_up(at_factory)
    with pytest.raises(ValueError, match="Could not find a navigation page"):     # not part of a consumer's navigation at all
        at.switch_page("views/mod_accounts.py").run()


def test_moderator_signup_needs_the_pin(at_factory):
    at, name = sign_up(at_factory, "moderator", pin="000000")
    assert "uid" not in at.session_state
    assert any("PIN is incorrect" in e.value for e in at.error)


@pytest.mark.parametrize("page", MODERATOR_PAGES)
def test_moderator_pages_render(at_factory, page):
    at, _ = sign_up(at_factory, "moderator")
    assert at.session_state["role"] == "moderator"
    at.switch_page(page).run()
    _ok(at)
    assert "Founded by: <b>Shaurya Shah</b>" in _html(at)


def test_message_scan_flow(at_factory):
    at, _ = sign_up(at_factory)
    at.switch_page("views/scan_message.py").run()
    at.text_area(key="msg_text").set_value("Your e-challan of Rs 500 is pending. Pay now: https://echallan-pay.vip/x").run()
    next(b for b in at.button if b.label == "Check message").click().run()
    _ok(at)
    assert "Likely scam" in _html(at) or any("Likely scam" in str(m.value) for m in at.markdown)


def test_sample_file_scan_flow(at_factory):
    at, _ = sign_up(at_factory)
    at.switch_page("views/scan_file.py").run()
    at.button_group(key="file_sample").set_value("KYC phishing email (PDF)").run()
    next(b for b in at.button if b.label == "Check file").click().run()
    _ok(at)
    page = _html(at)
    assert "Likely scam: fake account / KYC verification" in page or "Likely scam: bank or card phishing" in page


def test_feedback_reaches_the_moderators_and_scans_stay_private(at_factory):
    at, consumer = sign_up(at_factory)
    at.switch_page("views/scan_message.py").run()
    at.text_area(key="msg_text").set_value("KBC lottery: you won Rs 25 lakh, call our manager on 9876501234").run()
    next(b for b in at.button if b.label == "Check message").click().run()
    at.switch_page("views/feedback.py").run()
    n = at.session_state["fb_n"] if "fb_n" in at.session_state else 0
    at.text_input(key=f"fb_subject_{n}").set_value("Lottery message check")
    at.text_area(key=f"fb_message_{n}").set_value("My neighbour Sunita got this on 9876501234, please check it.")
    next(b for b in at.button if b.label == "Send to moderators").click().run()
    _ok(at)
    assert "has been sent to the moderators" in " ".join(s.value for s in at.success)

    mod, _ = sign_up(at_factory, "moderator")
    mod.switch_page("views/mod_feedback.py").run()
    _ok(mod)
    page = _html(mod)
    assert "Lottery message check" in page and consumer in page
    assert "9876501234" not in page and "[PHONE_" in page                  # personal details were redacted before saving
    mod.switch_page("views/history.py").run()
    assert "KBC" not in _html(mod)                                       # a consumer's scans are not in the moderator's history


# ----------------------------------------------------------------------------------------------- what reaches the activity log
def _store():
    from trustguard.accounts import AccountStore
    from trustguard.config import get_settings
    from trustguard.db import open_database
    return AccountStore(open_database(get_settings(), "accounts.sqlite"))     # the same database the app uses (SQLite or PostgreSQL)


def _mine(name):
    return [r for r in _store().activity(limit=5000) if r["username"] == name]


def test_pages_navigation_and_reruns_create_no_activity(at_factory):
    at, name = sign_up(at_factory)
    assert [r["event"] for r in _mine(name)] == ["login"]                  # signing up signs in once: one entry
    for page in CONSUMER_PAGES + CONSUMER_PAGES[::-1]:                   # navigate everywhere, twice
        at.switch_page(page).run()
        at.run()                                                         # and rerun each page
        _ok(at)
    assert [r["event"] for r in _mine(name)] == ["login"]


def test_one_scan_is_one_activity_entry_even_across_reruns(at_factory):
    at, name = sign_up(at_factory)
    at.switch_page("views/scan_message.py").run()
    at.text_area(key="msg_text").set_value("Your e-challan of Rs 500 is pending. Pay now: https://echallan-pay.vip/x").run()
    next(b for b in at.button if b.label == "Check message").click().run()
    at.run()
    at.run()                                                             # reruns keep showing the result; they don't rescan
    scans = [r for r in _mine(name) if r["event"] == "scan"]
    assert len(scans) == 1 and scans[0]["kind"] == "message" and scans[0]["verdict"] in ("HIGH", "CRITICAL")
    assert "echallan-pay" not in repr(scans)


def test_moderator_pages_and_actions_create_no_activity(at_factory):
    mod, name = sign_up(at_factory, "moderator")
    for page in MODERATOR_PAGES:
        mod.switch_page(page).run()
        _ok(mod)
    mod.switch_page("views/mod_activity.py").run()
    assert [r["event"] for r in _mine(name)] == ["login"]
    page = _html(mod) + " ".join(str(d.value) for d in mod.dataframe)
    assert "Opened page" not in page and "Failed sign-in" not in page


# ---------------------------------------------------------------------------------------------- result screen details
def _result_page(kind: str):
    """Render one scan result on its own page (AppTest can't drive the file uploader, so APKs are scanned in-process)."""
    import sys
    from pathlib import Path
    root = Path.cwd()
    for p in (str(root), str(root / "app"), str(root / "tests")):
        if p not in sys.path:
            sys.path.insert(0, p)
    import streamlit as st

    import results
    import ui
    from trustguard.config import Preferences, get_settings
    from trustguard.engine import TrustGuardEngine
    ui.inject_css()
    eng = TrustGuardEngine(get_settings(), Preferences(network_checks=False, intel_lookups=False, factcheck_lookups=False), store=False)
    if kind == "apk":
        import apkfactory
        r = eng.scan_file("SBI_Rewardz.apk", apkfactory.sms_stealer()).result
    else:
        r = eng.scan_message("I am giving away $3,000 to everyone who registers on luckyspin-casino.io - withdraw instantly! "
                             "Use promo code SPIN. This post will be deleted in 1 hour, only the fastest get it!").result
    st.session_state["shown"] = r.scan_id
    results.render(r, None, key="t")


@pytest.mark.parametrize("kind", ["message", "apk"])
def test_result_screen_explains_every_finding(kind, monkeypatch):
    st_testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    at = st_testing.AppTest.from_function(_result_page, args=(kind,), default_timeout=60)
    at.run()
    _ok(at)
    page = _html(at)
    md = " ".join(str(m.value) for m in at.markdown) + " ".join(str(c.value) for c in at.caption)
    labels = " ".join(e.label for e in at.expander)
    assert "Confidence" in page and "not a probability" in page                    # score and confidence shown separately
    assert "Detected by" in page and "Verioax rules" in page                        # where each finding came from
    assert "suspicious patterns, not proof" in md or "not proof" in md
    if kind == "message":
        assert "Crypto casino / betting bonus scam" in page and "High risk" in page
        assert "tg-quote" in page                                                    # the fragment that triggered a finding
        assert "Context noted" in labels and "not counted in the score" in labels
        assert "Not checked live" in page and "luckyspin-casino[.]io" in page and "https://luckyspin" not in page
    else:
        tabs = [t.label for t in at.tabs]
        assert tabs[0] == "App analysis"
        assert "com.sbi.rewardz.points" in page and "Android test key" in page and "RECEIVE_SMS" in page and "email=android@android.com" in page
        assert "never installed or run" in md
