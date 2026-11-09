import pytest

from trustguard.scam import analyze_text, detect_language
from trustguard.scam.claims import extract_claims
from trustguard.scam.sender import analyze_sender


def keys(text: str, sender=None) -> set[str]:
    return analyze_text(text, sender).matched_keys


@pytest.mark.parametrize("text", [
    "Please share the OTP you received to verify your account",
    "Apna OTP batao jaldi",
    "Send your card number and CVV to activate the reward",
])
def test_credential_requests(text):
    assert "credential_request" in keys(text)


@pytest.mark.parametrize("text", [
    "123456 is your OTP. Do not share it with anyone.",
    "Never share your OTP or PIN with anybody.",
    "OTP kisi ke saath share na karein.",
    "Enter OTP 482913 to log in to your account.",
])
def test_genuine_otp_messages_are_not_credential_requests(text):
    assert "credential_request" not in keys(text)


def test_upi_collect_trick():
    assert "upi_collect_trick" in keys("To receive your cashback of Rs 500, enter your UPI PIN on the request.")


def test_forward_demand_and_hoax_wording():
    k = keys("WhatsApp will start charging from tomorrow. Forward this message to 10 groups.")
    assert {"forward_demand", "policy_change_rumour"} <= k


def test_apk_skipped_when_play_store_is_mentioned():
    assert "apk_install" in keys("Download the RTO Challan.apk file to see your challan")
    assert "apk_install" not in keys("Download our app from the Google Play Store")


def test_claimed_entities():
    ta = analyze_text("Traffic Police: your e-challan is pending. Visit RTO. Regards SBI")
    names = [e.key for e in ta.claimed]
    assert names[0] == "parivahan" and "sbi" in names


def test_acronyms_are_case_sensitive():
    assert analyze_text("the rbi and sbi words in lowercase").claimed == []


def test_sender_mobile_number_claiming_government():
    ta = analyze_text("Your e-challan of Rs 500 is pending. Pay now.", sender="+91 98765 43210")
    f = next(x for x in ta.findings if x.indicator == "official_from_personal_number")
    assert f.strength.value == "strong"
    assert "43210" not in ta.sender.raw                                   # the number is masked before it is kept


@pytest.mark.parametrize("raw,kind,cat", [("VM-HDFCBK-S", "dlt_header", "service"), ("AX-PARIVA-G", "dlt_header", "government"),
                                          ("+855 12 345 678", "foreign_number", None), ("noreply@parivahan-gov.in", "email", None),
                                          ("9876543210", "mobile_number", None)])
def test_sender_kinds(raw, kind, cat):
    s = analyze_sender(raw)
    assert s.kind == kind and s.category == cat


@pytest.mark.parametrize("text,lang", [("आपका चालान लंबित है, तुरंत भुगतान करें", "hi"),
                                       ("Aapka challan pending hai, turant payment karein", "hinglish"),
                                       ("Your challan is pending", "en")])
def test_language(text, lang):
    assert detect_language(text) == lang


def test_claim_sentences_do_not_break_on_urls():
    claims = extract_claims("Your e-challan details are at https://echallan.parivahan.gov.in/x . Lok Adalat will waive 50% of fines on 13 Dec.")
    assert claims[0].text.endswith("/x .") or "parivahan.gov.in/x" in claims[0].text
    assert any("Lok Adalat" in c.text and "Legal Services Authority" in c.how_to_verify for c in claims)
