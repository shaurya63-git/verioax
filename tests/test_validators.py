import pytest

from trustguard.pii import validators as V


@pytest.mark.parametrize("num,ok", [("4111 1111 1111 1111", True), ("4111 1111 1111 1112", False), ("6011000990139424", True), ("1234", False)])
def test_luhn(num, ok):
    assert V.luhn_ok(num) is ok


def test_verhoeff_known_values():
    assert V.verhoeff_ok("2363")                # check digit of 236 is 3 (Verhoeff's worked example)
    assert not V.verhoeff_ok("2364")


def test_aadhaar_rules():
    # build a valid 12-digit number by searching the check digit
    base = "23456789012"
    valid = next(base + str(d) for d in range(10) if V.verhoeff_ok(base + str(d)))
    assert V.aadhaar_ok(valid)
    assert not V.aadhaar_ok("1" + valid[1:])     # Aadhaar never starts with 0 or 1
    assert not V.aadhaar_ok(valid[:-1] + str((int(valid[-1]) + 1) % 10))


@pytest.mark.parametrize("pan,ok", [("ABCPE1234F", True), ("ABCXE1234F", False), ("ABCP1234F", False)])
def test_pan(pan, ok):
    assert V.pan_ok(pan) is ok


def test_gstin_checksum():
    assert V.gstin_ok("27AAPFU0939F1ZV")
    assert not V.gstin_ok("27AAPFU0939F1ZW")


def test_iban():
    assert V.iban_ok("GB82 WEST 1234 5698 7654 32")
    assert not V.iban_ok("GB82 WEST 1234 5698 7654 33")


@pytest.mark.parametrize("plate,ok", [("MH12AB1234", True), ("DL 3C AB 1234", True), ("22BH1234AB", True), ("XX12AB1234", False), ("MH12AB123", False)])
def test_vehicle_registration(plate, ok):
    assert V.vehicle_reg_ok(plate) is ok


@pytest.mark.parametrize("value,digits", [("+91 98765 43210", "9876543210"), ("098765-43210", "9876543210"), ("5876543210", None)])
def test_indian_mobile(value, digits):
    assert V.indian_mobile_digits(value) == digits
