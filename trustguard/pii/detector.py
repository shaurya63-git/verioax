"""Run every recognizer, then resolve overlaps into one list of detections.

Merge rules (documented in docs/architecture.md):
* same type overlapping   -> one detection over the union of the spans, best confidence, detectors combined;
* different types         -> the more specific type wins (priority order below) unless the other candidate is at least
                             0.20 more confident (a context-anchored value beats a bare shape guess);
* confidence              -> best base confidence + 0.03 for each additional independent detector family (cap 0.99).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import names as N
from . import recognizers as R

# Most specific first. Credentials and card numbers must never be swallowed by a broader type.
PRIORITY = ["CREDENTIAL", "CARD_NUMBER", "NATIONAL_ID", "TAX_ID", "PASSPORT", "VOTER_ID", "DRIVING_LICENCE", "BANK_ACCOUNT",
            "UPI_ID", "EMAIL", "PHONE", "VEHICLE_REG", "DOB", "ADDRESS", "PERSON"]
_RANK = {t: i for i, t in enumerate(PRIORITY)}

TYPE_LABELS = {
    "CREDENTIAL": "Password / OTP / PIN", "CARD_NUMBER": "Card number", "NATIONAL_ID": "Aadhaar number", "TAX_ID": "PAN / GSTIN",
    "PASSPORT": "Passport number", "VOTER_ID": "Voter ID (EPIC)", "DRIVING_LICENCE": "Driving licence", "BANK_ACCOUNT": "Bank account",
    "UPI_ID": "UPI ID", "EMAIL": "Email address", "PHONE": "Phone number", "VEHICLE_REG": "Vehicle registration",
    "DOB": "Date of birth", "ADDRESS": "Address", "PERSON": "Person name",
}


@dataclass
class Detection:
    type: str
    start: int
    end: int
    text: str
    confidence: float
    detectors: list[str]
    flags: list[str] = field(default_factory=list)


def _family(detector: str) -> str:
    return detector.split(":", 1)[0]


def detect(text: str, min_confidence: float = 0.5, use_ner: bool = True) -> list[Detection]:
    cands = R.scan(text) + N.detect_names(text, use_ner=use_ner)
    cands = [c for c in cands if c.end > c.start]
    # strongest claims first: type priority, then confidence, then longer spans
    cands.sort(key=lambda c: (_RANK.get(c.type, 99), -c.confidence, -(c.end - c.start)))

    accepted: list[dict] = []
    for c in cands:
        clash = next((a for a in accepted if c.start < a["end"] and a["start"] < c.end), None)
        if clash is None:
            accepted.append({"type": c.type, "start": c.start, "end": c.end, "conf": c.confidence,
                             "detectors": {c.detector}, "flags": set(c.flags)})
            continue
        if clash["type"] == c.type:
            clash["start"], clash["end"] = min(clash["start"], c.start), max(clash["end"], c.end)
            clash["conf"] = max(clash["conf"], c.confidence)
            clash["detectors"].add(c.detector)
            clash["flags"] |= set(c.flags)
        elif c.confidence - clash["conf"] >= 0.20:
            clash.update(type=c.type, start=c.start, end=c.end, conf=c.confidence, detectors={c.detector}, flags=set(c.flags))
        # otherwise the more specific, already accepted type stands

    out: list[Detection] = []
    for a in accepted:
        families = {_family(d) for d in a["detectors"]}
        conf = min(0.99, a["conf"] + 0.03 * (len(families) - 1))
        flags = set(a["flags"])
        if len(a["detectors"]) > 1 and "single_token" in flags and conf >= 0.7:
            flags.discard("single_token")                         # corroborated by another detector
        if conf < min_confidence:
            continue
        out.append(Detection(a["type"], a["start"], a["end"], text[a["start"]:a["end"]], round(conf, 3),
                             sorted(a["detectors"]), sorted(flags)))
    out.sort(key=lambda d: (d.start, d.end))
    return _drop_nested(out)


def _drop_nested(dets: list[Detection]) -> list[Detection]:
    """After type replacement a span can end up inside another accepted span; keep the outer one."""
    out: list[Detection] = []
    for d in dets:
        if out and d.start < out[-1].end:
            prev = out[-1]
            keep_prev = _RANK.get(prev.type, 99) <= _RANK.get(d.type, 99) or prev.confidence >= d.confidence
            if not keep_prev:
                out[-1] = d
            continue
        out.append(d)
    return out
