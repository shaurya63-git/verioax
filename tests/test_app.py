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
    assert "bank impersonation" in _html(at)


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
