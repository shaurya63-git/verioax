import pytest

from trustguard.pii import analyze_pii
from trustguard.pii import validators as V
from trustguard.pii.detector import detect
from trustguard.pii.redactor import redact


def _aadhaar() -> str:
    base = "23456789012"
    d = next(base + str(x) for x in range(10) if V.verhoeff_ok(base + str(x)))
    return f"{d[:4]} {d[4:8]} {d[8:]}"


def types(text: str) -> dict[str, str]:
    return {d.type: d.text for d in detect(text, use_ner=False)}


@pytest.mark.parametrize("text,typ,value", [
    ("Mail me at priya.sharma@example.com today", "EMAIL", "priya.sharma@example.com"),
    ("Call me on +91 98765 43210", "PHONE", "+91 98765 43210"),
    ("Pay to ravi.k@ybl now", "UPI_ID", "ravi.k@ybl"),
    ("My PAN is ABCPE1234F", "TAX_ID", "ABCPE1234F"),
    ("Card 4111 1111 1111 1111 exp 12/29", "CARD_NUMBER", "4111 1111 1111 1111"),
    ("A/c no. 001234567890 debited", "BANK_ACCOUNT", "001234567890"),
    ("Your vehicle MH12AB1234 was fined", "VEHICLE_REG", "MH12AB1234"),
    ("DOB: 04/09/1998", "DOB", "04/09/1998"),
    ("Your OTP is 482913", "CREDENTIAL", "482913"),
    ("CVV 123 please", "CREDENTIAL", "123"),
    ("Passport no. K1234567", "PASSPORT", "K1234567"),
    ("Voter ID ABC1234567", "VOTER_ID", "ABC1234567"),
    ("DL no MH14 20110012345", "DRIVING_LICENCE", "MH14 20110012345"),
    ("Mr. Arjun Mehta will call", "PERSON", "Arjun Mehta"),
    ("Name: SUNITA DEVI", "PERSON", "SUNITA DEVI"),
])
def test_detects_each_type(text, typ, value):
    assert types(text).get(typ) == value


def test_aadhaar_with_checksum():
    a = _aadhaar()
    assert types(f"Aadhaar {a}")["NATIONAL_ID"] == a


def test_amount_after_otp_is_not_a_credential():
    t = types("123456 is your OTP for txn of Rs 5000 at Amazon. Do not share it.")
    assert t.get("CREDENTIAL") == "123456"
    assert "5000" not in [d.text for d in detect("OTP for txn of Rs 5000", use_ner=False)]


def test_password_words_are_not_passwords():
    assert "CREDENTIAL" not in types("Your password is required to continue.")
    assert types("password: Secr3t#99.")["CREDENTIAL"] == "Secr3t#99"


def test_reference_numbers_are_not_aadhaar_or_phone():
    base = "51234567890"
    ref = next(base + str(x) for x in range(10) if V.verhoeff_ok(base + str(x)))
    assert "NATIONAL_ID" not in types(f"UPI Ref no {ref} credited")
    assert "PHONE" not in types("Order ID 9876543210 shipped")


def test_generic_greetings_are_not_names():
    assert "PERSON" not in types("Dear Customer, your account is active. Regards, SBI Team")


def test_same_value_same_placeholder_and_phone_variants_share_one():
    rep, red, _ = analyze_pii("Call 9876543210 or +91 98765 43210. Mail a@example.com, again a@example.com", use_ner=False)
    phones = {f.placeholder for f in rep.findings if f.entity_type == "PHONE"}
    assert phones == {"[PHONE_001]"}
    assert red.redacted_text.count("[EMAIL_001]") == 2


def test_name_part_reuses_person_placeholder():
    rep, red, _ = analyze_pii("Dear Ravi Kumar, please confirm. Kumar must reply today.", use_ner=False)
    assert red.redacted_text.count("[PERSON_001]") == 2
    assert "Kumar" not in red.redacted_text


def test_redacted_text_has_no_raw_values():
    text = f"Name: Arjun Mehta, Aadhaar {_aadhaar()}, PAN ABCPE1234F, phone 9876543210, card 4111 1111 1111 1111, mail arjun@example.com"
    rep, red, restricted = analyze_pii(text, use_ner=False)
    for f in rep.findings:
        assert text[f.start:f.end] not in red.redacted_text
    assert rep.exposure.level == "HIGH"
    raw = {v for e in restricted.value_map for v in e["values"]}
    assert "ABCPE1234F" in raw                                          # the map is the only place raw values live
    assert "ABCPE1234F" not in rep.model_dump_json()


def test_leak_sweep_catches_value_written_differently():
    text = "Primary 9876543210. Backup 98765-43210."
    first = [d for d in detect(text, use_ner=False) if d.start < 18]
    red = redact(text, first, sweep_rounds=2, use_ner=False)
    assert red.caught_by_sweep >= 1 and "43210" not in red.redacted_text and red.residual == 0


def test_residual_marks_blocked():
    rep_red = redact("Call 9876543210 now", [], sweep_rounds=0, use_ner=False)
    assert rep_red.residual == 1


def test_status_needs_review_for_low_confidence():
    rep, _, _ = analyze_pii("Ref ABC1234567 noted", use_ner=False)        # bare EPIC-like code -> low confidence
    assert rep.status == "needs_review" and any(f.needs_review for f in rep.findings)


def test_offset_map_round_trip():
    text = "Hi Arjun Mehta, call 9876543210 today"
    rep, red, restricted = analyze_pii(text, use_ner=False)
    om = restricted.offset_map
    s = text.index("today")
    rs = om.to_redacted(s)
    assert red.redacted_text[rs:rs + 5] == "today"
    assert om.to_original(rs) == s
    ph = next(f for f in rep.findings if f.entity_type == "PHONE")
    assert red.redacted_text[om.to_redacted(ph.start):om.to_redacted(ph.end, end=True)] == ph.placeholder


def test_value_fingerprint_is_keyed_not_a_plain_hash():
    """A plain hash of a 10-digit phone number can be brute-forced; the stored fingerprint must need the installation key."""
    import hashlib

    from trustguard.pii.redactor import normalise, value_hash
    plain = hashlib.sha256(f"PHONE:{normalise('PHONE', '9876543210')}".encode()).hexdigest()
    a, b = value_hash("PHONE", "9876543210", b"k" * 32), value_hash("PHONE", "+91 98765 43210", b"k" * 32)
    assert a == b and not plain.startswith(a)
    assert value_hash("PHONE", "9876543210", b"x" * 32) != a


def test_engine_keeps_one_secret_per_installation(settings, prefs):
    import stat
    from pathlib import Path

    from trustguard.engine import TrustGuardEngine
    e1 = TrustGuardEngine(settings, prefs, store=False)
    e2 = TrustGuardEngine(settings, prefs, store=False)
    key_file = Path(settings.data_dir) / "secret.key"
    assert e1.hash_key == e2.hash_key == key_file.read_bytes()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    h1 = e1.scan_message("Call me on 9876543210").result.pii.findings[0].value_hash
    h2 = e2.scan_message("My number is +91 98765 43210").result.pii.findings[0].value_hash
    assert h1 == h2
