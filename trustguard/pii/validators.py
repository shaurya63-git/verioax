"""Checksum and structure validators for identifiers.

A validator only rejects values that *cannot* be real. Redaction errs toward masking: a false alarm costs a placeholder,
a miss leaks someone's data. Each function is pure and unit-tested in ``tests/test_validators.py``.
"""
from __future__ import annotations

import re

# ----------------------------------------------------------------------------------------------- Luhn (payment cards)

def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


CARD_PREFIXES = (
    ("4",), ("51", "52", "53", "54", "55"), ("2221", "2720"), ("34", "37"), ("60", "65", "81", "82", "508"),  # RuPay ranges
    ("35",), ("36", "38", "30"), ("6011", "64"),
)


def card_brand_plausible(number: str) -> bool:
    """True when the number starts like a card issued by a major network (Visa, Mastercard, RuPay, Amex, ...)."""
    d = re.sub(r"\D", "", number)
    if not 13 <= len(d) <= 19:
        return False
    if d[0] == "4":
        return True
    if d[:2] in {"51", "52", "53", "54", "55", "34", "37", "35", "36", "38", "30", "60", "65", "64", "81", "82"}:
        return True
    if d[:3] == "508" or d[:4] == "6011":
        return True
    return d[:4].isdigit() and 2221 <= int(d[:4]) <= 2720


# ----------------------------------------------------------------------------------------------- Verhoeff (Aadhaar)
# Dihedral group D5 multiplication table and the position permutation, as defined by Verhoeff (1969).
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P0 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
_P1 = [1, 5, 7, 6, 2, 8, 3, 0, 9, 4]


def _perm(pos: int) -> list[int]:
    table = _P0
    for _ in range(pos % 8):
        table = [_P1[x] for x in table]
    return table


_PERMS = [_perm(i) for i in range(8)]


def verhoeff_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not digits:
        return False
    check = 0
    for i, d in enumerate(reversed(digits)):
        check = _D[check][_PERMS[i % 8][d]]
    return check == 0


def aadhaar_ok(number: str) -> bool:
    d = re.sub(r"\D", "", number)
    return len(d) == 12 and d[0] not in "01" and verhoeff_ok(d)


# ----------------------------------------------------------------------------------------------- PAN / GSTIN

PAN_HOLDER_TYPES = set("PCHFATBLJG")   # 4th character: Person, Company, HUF, Firm, AOP, Trust, BOI, Local authority, Juridical, Govt


def pan_ok(value: str) -> bool:
    v = value.strip().upper()
    return bool(re.fullmatch(r"[A-Z]{3}[A-Z][A-Z]\d{4}[A-Z]", v)) and v[3] in PAN_HOLDER_TYPES


_GST_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_ok(value: str) -> bool:
    """15 characters: state code, PAN, entity number, 'Z' by default, base-36 checksum."""
    v = value.strip().upper()
    if not re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z][A-Z0-9][0-9A-Z]", v):
        return False
    if not 1 <= int(v[:2]) <= 38 and v[:2] not in ("97", "99"):
        return False
    total = 0
    for i, ch in enumerate(v[:14]):
        product = _GST_CHARS.index(ch) * (2 if i % 2 else 1)
        total += product // 36 + product % 36
    return _GST_CHARS[(36 - total % 36) % 36] == v[14]


# ----------------------------------------------------------------------------------------------- IBAN

def iban_ok(value: str) -> bool:
    s = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


# ----------------------------------------------------------------------------------------------- Indian vehicle registration
# Codes of states and union territories used on number plates (including legacy codes still on the road).
STATE_CODES = {
    "AN", "AP", "AR", "AS", "BR", "CG", "CH", "DD", "DL", "DN", "GA", "GJ", "HP", "HR", "JH", "JK", "KA", "KL", "LA",
    "LD", "MH", "ML", "MN", "MP", "MZ", "NL", "OD", "OR", "PB", "PY", "RJ", "SK", "TG", "TN", "TR", "TS", "UK", "UA",
    "UP", "WB",
}


def vehicle_reg_ok(value: str) -> bool:
    v = re.sub(r"[\s.-]", "", value.upper())
    if re.fullmatch(r"\d{2}BH\d{4}[A-Z]{1,2}", v):          # Bharat series: 22BH1234AB
        return True
    m = re.fullmatch(r"([A-Z]{2})(\d{1,2})([A-Z]{0,3})(\d{1,4})", v)
    if not m or m.group(1) not in STATE_CODES:
        return False
    return int(m.group(2)) > 0 and int(m.group(4)) > 0 and len(m.group(4)) == 4


# ----------------------------------------------------------------------------------------------- phone numbers

def indian_mobile_digits(value: str) -> str | None:
    """Return the 10-digit subscriber number if `value` is an Indian mobile number, else None."""
    d = re.sub(r"\D", "", value)
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 11 and d.startswith("0"):
        d = d[1:]
    return d if len(d) == 10 and d[0] in "6789" else None
