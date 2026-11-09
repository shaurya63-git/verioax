"""Person names: the PII that regexes cannot see.

Three sources, highest precision first:
1. structural rules - honorifics (Mr/Smt/Dr ...), field labels ("Name:", "Account holder:"), greetings ("Dear Ravi"),
   self-introductions ("my name is ...") and sign-offs ("Regards,\\nPriya");
2. spaCy NER, when installed (``pip install trustguard-ai[ner]``) - a safety net for names in running text;
3. propagation - once a name is known, its other occurrences (full name or a distinctive part) are marked too, so the
   same person gets the same placeholder everywhere.

Guard rails: a deny list of words that look like names in scam messages but are roles or organisations ("Dear Customer",
"Traffic Police", "SBI Team"), and a shape check (every token title-case or an initial).
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache

from .recognizers import Candidate

log = logging.getLogger(__name__)

# Words that are never a person's name in this domain (greeting targets, roles, organisations, UI words).
DENY = {w.lower() for w in """
customer customers user users sir madam maam ma'am member members valued applicant candidate candidates friend friends all team
subscriber subscribers policyholder cardholder citizen citizens owner vehicle parent parents student students client clients
consumer consumers depositor holder account bank banks police traffic department officer officers support care service services
helpdesk desk india indian government govt ministry court lok adalat rto parivahan vahan echallan challan income tax uidai epfo
aadhaar aadhar pan kyc upi paytm phonepe gpay google amazon flipkart jio airtel vodafone idea bsnl whatsapp telegram facebook
instagram sbi hdfc icici axis kotak pnb canara baroda union indusind yes idfc rbi npci irctc lic post courier dtdc delhivery
bluedart fedex dhl electricity board gas indane bharat hp manager executive director head admin hr recruiter recruitment
congratulations winner lucky draw prize reward cashback offer dear hello hi regards thanks thank sincerely urgent alert notice
final warning important attention action required please kindly note immediately today tomorrow monday tuesday wednesday
thursday friday saturday sunday january february march april may june july august september october november december
mr mrs ms miss dr shri smt the and for from your you our this that with will has have new old cyber crime cell cbi customs
narcotics ed nia army navy delhi mumbai bangalore bengaluru chennai kolkata hyderabad pune india post office ltd pvt limited inc llp
""".split()}

_NAME_TOKEN = r"[A-Z][a-z]+(?:['’-][A-Za-z][a-z]+)*"
_INITIAL = r"[A-Z]\.?"
_NAME = rf"(?:{_NAME_TOKEN}|{_INITIAL})(?:\s+(?:{_NAME_TOKEN}|{_INITIAL})){{0,3}}"
_CAPS_NAME = r"[A-Z]{2,}(?:\s+[A-Z]{2,}){1,3}"

_HONORIFIC = re.compile(rf"\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Shri|Shree|Sri|Smt|Kumari|Km|Sushri)\.?\s+({_NAME_TOKEN}(?:\s+(?:{_NAME_TOKEN}|{_INITIAL})){{0,3}})")
_LABEL = re.compile(rf"(?i:\b(?:full\s+name|name|customer\s+name|account\s+holder(?:'s)?\s+name|account\s+holder|holder\s+name|beneficiary(?:\s+name)?|"
                    rf"father'?s\s+name|mother'?s\s+name|husband'?s\s+name|spouse(?:'s)?\s+name|applicant(?:\s+name)?|nominee|patient(?:\s+name)?|"
                    rf"employee\s+name|candidate\s+name|owner\s+name|registered\s+owner|driver\s+name))\s*[:\-–]\s*({_CAPS_NAME}|{_NAME})")
_GREETING = re.compile(rf"\b(?:Dear|Hi|Hello|Hey|Namaste|Namaskar|Respected)\s+({_NAME_TOKEN}(?:\s+{_NAME_TOKEN}){{0,2}})\b")
_INTRO = re.compile(rf"\b(?i:my\s+name\s+is|this\s+is|i\s+am|i'm)\s+({_NAME_TOKEN}(?:\s+{_NAME_TOKEN}){{0,2}})\b")
_SIGNOFF = re.compile(rf"(?i:\b(?:regards|thanks|thank\s+you|sincerely|warm\s+regards|best\s+regards|yours\s+(?:truly|faithfully|sincerely)))\s*,?\s*\n+\s*({_NAME_TOKEN}(?:\s+{_NAME_TOKEN}){{0,2}})\b")


def _tokens(name: str) -> list[str]:
    return re.findall(r"[A-Za-z][A-Za-z'’-]*\.?", name)


def plausible(name: str) -> bool:
    toks = _tokens(name)
    if not toks or len(name) > 60 or re.search(r"\d|@|:|/", name):
        return False
    if any(t.lower().strip(".") in DENY for t in toks):
        return False
    letters = [t for t in toks if len(t.strip(".")) > 1]
    if not letters:
        return False
    return all(t[0].isupper() for t in toks)


def _trim(name: str, start: int) -> tuple[str, int, int] | None:
    """Drop deny-listed or trailing junk tokens ('Ravi Kumar Your' -> 'Ravi Kumar'). Returns (name, start, end) or None."""
    toks = list(re.finditer(r"\S+", name))
    keep = []
    for m in toks:
        w = m.group().rstrip(",.;:!?")
        if w.lower().strip(".") in DENY or not w[:1].isupper():
            break
        keep.append((m, w))
    if not keep:
        return None
    first, last = keep[0][0], keep[-1]
    s = start + first.start()
    e = start + last[0].start() + len(last[1])
    text = name[first.start():last[0].start() + len(last[1])]
    return (text, s, e) if plausible(text) else None


def rule_names(t: str) -> list[Candidate]:
    out: list[Candidate] = []
    specs = ((_HONORIFIC, 0.90, "rule:honorific"), (_LABEL, 0.90, "rule:name-label"), (_GREETING, 0.80, "rule:greeting"),
             (_INTRO, 0.72, "rule:self-intro"), (_SIGNOFF, 0.75, "rule:sign-off"))
    for rx, conf, det in specs:
        for m in rx.finditer(t):
            raw = m.group(1)
            if raw.isupper():                                      # 'RAVI KUMAR' on forms
                if any(w.lower() in DENY for w in raw.split()):
                    continue
                out.append(Candidate("PERSON", m.start(1), m.end(1), conf - 0.05, det, ["all_caps"]))
                continue
            trimmed = _trim(raw, m.start(1))
            if trimmed:
                _, s, e = trimmed
                single = len(_tokens(t[s:e])) == 1
                out.append(Candidate("PERSON", s, e, conf - (0.08 if single else 0.0), det, ["single_token"] if single else []))
    return out


# ----------------------------------------------------------------------------------------------- optional spaCy NER
@lru_cache(maxsize=1)
def _nlp():
    try:
        import spacy
    except ImportError:
        return None
    for model in ("en_core_web_sm", "en_core_web_md", "en_core_web_lg"):
        try:
            if spacy.util.is_package(model):
                return spacy.load(model, disable=["lemmatizer", "parser", "attribute_ruler"])
        except Exception as exc:  # pragma: no cover - environment specific
            log.warning("spaCy model %s failed to load: %s", model, type(exc).__name__)
    return None


def ner_available() -> bool:
    return _nlp() is not None


def ner_names(t: str) -> list[Candidate]:
    nlp = _nlp()
    if nlp is None or not t.strip():
        return []
    out = []
    for ent in nlp(t[:100_000]).ents:
        if ent.label_ != "PERSON":
            continue
        for part in re.finditer(r"[^\n]+", ent.text):              # NER sometimes glues lines together
            trimmed = _trim(part.group(), ent.start_char + part.start())
            if trimmed:
                _, s, e = trimmed
                multi = len(_tokens(t[s:e])) >= 2
                out.append(Candidate("PERSON", s, e, 0.74 if multi else 0.52, "ner:spacy", [] if multi else ["single_token"]))
    return out


# ----------------------------------------------------------------------------------------------- propagation
def propagate(t: str, seeds: list[Candidate]) -> list[Candidate]:
    """Mark other occurrences of confidently detected names (full name, then distinctive single parts)."""
    known: set[str] = set()
    for c in seeds:
        if c.type == "PERSON" and c.confidence >= 0.72:
            name = t[c.start:c.end]
            known.add(name)
            for tok in _tokens(name):
                tok = tok.strip(".")
                if len(tok) >= 4 and tok.lower() not in DENY:
                    known.add(tok)
    if not known:
        return []
    rx = re.compile(r"(?<![A-Za-z])(" + "|".join(re.escape(k) for k in sorted(known, key=len, reverse=True)) + r")(?![A-Za-z])")
    return [Candidate("PERSON", m.start(), m.end(), 0.76, "rule:propagated") for m in rx.finditer(t)]


def detect_names(t: str, use_ner: bool = True) -> list[Candidate]:
    seeds = rule_names(t) + (ner_names(t) if use_ner else [])
    return seeds + propagate(t, seeds)
