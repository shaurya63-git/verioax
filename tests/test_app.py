"""Headless smoke test of the Streamlit UI (Streamlit's AppTest): every page renders without an exception, and a message
scan produces a report."""
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"
PAGES = ["views/dashboard.py", "views/scan_message.py", "views/scan_url.py", "views/scan_file.py", "views/history.py",
         "views/threat_intel.py", "views/reports.py", "views/settings.py"]


@pytest.fixture(scope="module")
def at_factory():
    st_testing = pytest.importorskip("streamlit.testing.v1")

    def make():
        return st_testing.AppTest.from_file(str(APP), default_timeout=60)
    return make


@pytest.mark.parametrize("page", PAGES)
def test_page_renders(at_factory, page):
    at = at_factory()
    at.run()
    at.switch_page(page).run()
    assert not at.exception, [e.value for e in at.exception]


def test_message_scan_flow(at_factory):
    at = at_factory()
    at.run()
    at.switch_page("views/scan_message.py").run()
    at.text_area(key="msg_text").set_value("Your e-challan of Rs 500 is pending. Pay now: https://echallan-pay.vip/x").run()
    next(b for b in at.button if b.label == "Check message").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("Likely scam" in h.value for h in at.get("html")) or any("Likely scam" in str(m.value) for m in at.markdown)


def test_sample_file_scan_flow(at_factory):
    at = at_factory()
    at.run()
    at.switch_page("views/scan_file.py").run()
    at.button_group(key="file_sample").set_value("KYC phishing email (PDF)").run()
    next(b for b in at.button if b.label == "Check file").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("bank impersonation" in h.value for h in at.get("html"))
