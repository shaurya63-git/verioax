"""Sender analysis: what the 'From' field says about a message.

India-specific facts used here:
* Business SMS go through registered (DLT) headers such as ``VM-HDFCBK-S``. Since May 2025 the operator appends a
  category suffix: ``-P`` promotional, ``-S`` service, ``-T`` transactional, ``-G`` government (TRAI-exempted headers).
* A government department or bank does not send notices from a personal 10-digit mobile number or a foreign number.

The sender is typed by the user and is not proof on its own: a genuine header lowers the score a little, a mismatch
raises it a lot.
"""
from __future__ import annotations

import re

from ..schemas import SenderAnalysis

_DLT = re.compile(r"^(?P<op>[A-Z]{2})-(?P<hdr>[A-Z0-9]{3,9})(?:-(?P<suf>[PSTG]))?$")
_SUFFIX = {"P": "promotional", "S": "service", "T": "transactional", "G": "government"}
_EMAIL = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
_COUNTRY = {"1": "USA/Canada", "44": "UK", "60": "Malaysia", "62": "Indonesia", "63": "Philippines", "66": "Thailand",
            "84": "Vietnam", "86": "China", "92": "Pakistan", "95": "Myanmar", "855": "Cambodia", "856": "Laos",
            "880": "Bangladesh", "971": "UAE", "977": "Nepal", "234": "Nigeria"}


def mask_number(s: str) -> str:
    """Keep the country code / first digits and the last two digits: '+91 98•••••10'. Phone numbers are personal data."""
    digits = [i for i, c in enumerate(s) if c.isdigit()]
    if len(digits) < 6:
        return s
    keep = set(digits[:4]) | set(digits[-2:])
    return "".join(c if (i in keep or not c.isdigit()) else "•" for i, c in enumerate(s))


def analyze_sender(raw: str | None) -> SenderAnalysis | None:
    res = _analyze(raw)
    if res is not None and res.kind in ("mobile_number", "foreign_number"):
        res.raw = mask_number(res.raw)
    return res


def _analyze(raw: str | None) -> SenderAnalysis | None:
    if not raw or not raw.strip():
        return None
    s = raw.strip()
    compact = re.sub(r"[\s()]", "", s)
    up = s.upper().replace(" ", "")

    m = _DLT.match(up)
    if m:
        cat = _SUFFIX.get(m.group("suf") or "")
        notes = [f"Registered business SMS header '{m.group('hdr')}'" + (f" ({cat} category)" if cat else " (no category suffix)")]
        return SenderAnalysis(raw=s, kind="dlt_header", category=cat, notes=notes)
    if re.fullmatch(r"[A-Z0-9]{6}", up) and not up.isdigit():
        return SenderAnalysis(raw=s, kind="dlt_header", notes=["Looks like a business header without operator prefix"])

    em = _EMAIL.match(s)
    if em:
        return SenderAnalysis(raw=s, kind="email", notes=[f"Email from the domain {em.group(1).lower()}"])

    digits = re.sub(r"\D", "", compact)
    if compact.startswith(("+", "00")) and not compact.lstrip("+0").startswith("91"):
        body = compact.lstrip("+")[2:] if compact.startswith("00") else compact.lstrip("+")
        cc = next((c for c in sorted(_COUNTRY, key=len, reverse=True) if body.startswith(c)), body[:3])
        where = _COUNTRY.get(cc, "outside India")
        return SenderAnalysis(raw=s, kind="foreign_number", country_code=f"+{cc}",
                              notes=[f"International number (+{cc}, {where})"])
    local = digits[2:] if len(digits) == 12 and digits.startswith("91") else digits[1:] if len(digits) == 11 and digits.startswith("0") else digits
    if len(local) == 10 and local[0] in "6789":
        return SenderAnalysis(raw=s, kind="mobile_number", country_code="+91", notes=["Personal Indian mobile number"])
    if digits and 3 <= len(digits) <= 6 and digits == compact:
        return SenderAnalysis(raw=s, kind="short_code", notes=["Short code"])
    return SenderAnalysis(raw=s, kind="unknown", notes=["Sender format not recognised"])


def sender_domain(sender: SenderAnalysis | None) -> str | None:
    if sender and sender.kind == "email":
        m = _EMAIL.match(sender.raw)
        return m.group(1).lower() if m else None
    return None
