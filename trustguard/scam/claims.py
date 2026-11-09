"""Claims that need verification.

A claim is a sentence that asserts a checkable fact - "your challan of Rs 590 is pending", "Lok Adalat will waive 50 %
of fines on 13 Dec", "the government is giving free laptops". The engine never labels a claim true or false from its
wording. It reports *how to verify it*, and - only when a fact-check service is configured - attaches related
fact-checks with citations, clearly worded as "related", not as a verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..brands import find_entities

_SENT = re.compile(r"(?:[^.!?।\n]|[.!?।](?=\S))+[.!?।]?")

_KINDS: list[tuple[str, re.Pattern]] = [
    ("authority_notice", re.compile(r"(?i)\b(?:pending|fine|penalty|challan|refund|blocked|suspended|will\s+be|has\s+been|discount|waiver|waive|"
                                    r"settle(?:ment)?|lok\s+adalat|notice|summons|warrant|case)\b")),
    ("offer", re.compile(r"(?i)\b(?:won|winner|prize|free|cashback|reward|gift|discount|\d+\s?%\s*off|lottery|bonus)\b")),
    ("policy_change", re.compile(r"(?i)\b(?:from\s+tomorrow|from\s+today|new\s+rule|banned|mandatory|will\s+(?:start\s+)?charg\w*|deadline|last\s+date|with\s+effect)\b")),
    ("financial", re.compile(r"(?i)\b(?:returns?|profit|interest|guaranteed|double\s+your|investment|earn)\b")),
    ("health", re.compile(r"(?i)\b(?:cures?|kills?|prevents?|vaccine|virus|cancer|covid|dengue|remedy)\b")),
]

_HOW = {
    "parivahan": "Look up pending challans yourself at echallan.parivahan.gov.in (or the mParivahan app) using your vehicle number.",
    "lok_adalat": ("Lok Adalat dates and eligible cases are announced by your State or District Legal Services Authority and the "
                   "traffic police's official channels - not by forwarded messages."),
    "bank": "Open your bank's official app, or call the number printed on your card.",
    "government": "Look for the notice or scheme on the official .gov.in website, or check PIB Fact Check.",
    "offer": "You can't win a draw you never entered. Check the brand's official website or app for any real offer.",
    "health": "Check with a doctor or the health ministry's official advisories.",
    "financial": "Check whether the platform or adviser is registered with SEBI on sebi.gov.in.",
    "policy_change": "Check the announcement on the service's or authority's official website.",
    "default": "Look for the same claim on an official website or a recognised fact-checker before acting on it or forwarding it.",
}


@dataclass
class RawClaim:
    text: str
    kind: str
    start: int
    end: int
    how_to_verify: str


def extract_claims(text: str, max_claims: int = 3) -> list[RawClaim]:
    out: list[RawClaim] = []
    for m in _SENT.finditer(text):
        sent = m.group().strip()
        if len(sent) < 18 or not re.search(r"[A-Za-zऀ-ॿ]", sent):
            continue
        kind = next((k for k, rx in _KINDS if rx.search(sent)), None)
        has_number = bool(re.search(r"\d", sent))
        entities = find_entities(sent)
        if kind is None or (kind == "authority_notice" and not entities and not has_number):
            continue
        lead = len(m.group()) - len(m.group().lstrip())
        start = m.start() + lead
        out.append(RawClaim(sent, kind, start, start + len(sent), _how(sent, kind, entities)))
        if len(out) >= max_claims:
            break
    return out


def _how(sentence: str, kind: str, entities) -> str:
    if re.search(r"(?i)lok\s+adalat", sentence):
        return _HOW["lok_adalat"]
    keys = {e.key for e, _, _ in entities}
    kinds = {e.kind for e, _, _ in entities}
    if "parivahan" in keys:
        return _HOW["parivahan"]
    if "bank" in kinds:
        return _HOW["bank"]
    for e, _, _ in entities:
        if e.verify:
            return e.verify
    if "government" in kinds:
        return _HOW["government"]
    return _HOW.get(kind, _HOW["default"])
