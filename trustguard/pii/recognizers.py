"""Pattern recognizers: text -> candidate spans, each with a base confidence and the detector that produced it.

Layering (lowest to highest effort):
1. *validated patterns* - shape + checksum (cards, Aadhaar, PAN, GSTIN, IBAN, vehicle plates);
2. *context-anchored values* - a label decides the type and the value only needs the right shape
   ("A/c no. 001234567890", "OTP is 482913", "DOB: 04/09/1998");
3. *names* - in ``names.py`` (rules + optional spaCy NER + propagation).

Context raises confidence; it never creates a value that has the wrong shape.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import validators as V


@dataclass
class Candidate:
    type: str
    start: int
    end: int
    confidence: float
    detector: str
    flags: list[str] = field(default_factory=list)


def _ctx_before(text: str, pos: int, pattern: str, window: int = 32) -> bool:
    return re.search(pattern, text[max(0, pos - window):pos], re.I) is not None


def _ctx_after(text: str, pos: int, pattern: str, window: int = 24) -> bool:
    return re.search(pattern, text[pos:pos + window], re.I) is not None


# ----------------------------------------------------------------------------------------------- email / UPI
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![\w-])")
_ROLE_MAILBOX = {"info", "support", "help", "care", "customercare", "noreply", "no-reply", "donotreply", "contact", "admin",
                 "hr", "careers", "jobs", "sales", "service", "feedback", "grievance", "complaints", "nodal", "webmaster"}

# Common UPI handles (payment-service-provider suffixes). An address with one of these is almost certainly a UPI ID.
UPI_HANDLES = {
    "ybl", "ibl", "axl", "okaxis", "oksbi", "okhdfcbank", "okicici", "paytm", "ptyes", "ptsbi", "pthdfc", "ptaxis", "upi",
    "apl", "yapl", "rapl", "sbi", "icici", "hdfcbank", "axisbank", "kotak", "kbl", "fbl", "federal", "rbl", "idfcbank",
    "indus", "pnb", "barodampay", "unionbank", "cnrb", "boi", "aubank", "jupiteraxis", "slice", "freecharge", "airtel",
    "jio", "naviaxis", "abfspay", "waaxis", "wahdfcbank", "wasbi", "waicici", "yesbank", "dbs", "hsbc", "citi",
}
_UPI = re.compile(r"(?<![\w.@-])([A-Za-z0-9][A-Za-z0-9._-]{1,63})@([A-Za-z][A-Za-z0-9]{1,30})(?![\w.@-]|\.[A-Za-z])")


def emails(t: str) -> list[Candidate]:
    out = []
    for m in _EMAIL.finditer(t):
        local = m.group().split("@")[0].lower()
        role = local in _ROLE_MAILBOX
        out.append(Candidate("EMAIL", m.start(), m.end(), 0.70 if role else 0.97, "pattern:email", ["role_mailbox"] if role else []))
    return out


def upi_ids(t: str) -> list[Candidate]:
    out = []
    for m in _UPI.finditer(t):
        handle = m.group(2).lower()
        known = handle in UPI_HANDLES
        ctx = _ctx_before(t, m.start(), r"upi|vpa|pay(?:ment)?\s+to|send\s+to|gpay|phonepe|paytm|bhim", 30)
        if known or ctx:
            out.append(Candidate("UPI_ID", m.start(), m.end(), 0.95 if known else 0.80, "pattern:upi", [] if known else ["unknown_handle"]))
    return out


# ----------------------------------------------------------------------------------------------- phone numbers
_IN_MOBILE = re.compile(r"(?<![\w+])(?:(?:\+|00)?91[\s.-]?|0)?[6-9]\d{2}[\s.-]?\d{3}[\s.-]?\d{4}(?![\w])|(?<![\w+])(?:(?:\+|00)?91[\s.-]?|0)?[6-9]\d{4}[\s.-]?\d{5}(?![\w])")
_INTL = re.compile(r"(?<![\w+])\+(?!91)\d{1,3}(?:[\s.-]?\(?\d{1,5}\)?){2,5}(?![\w])")
_LANDLINE = re.compile(r"(?<![\w+])0\d{2,4}[\s-]\d{6,8}(?![\w])")
_PHONE_CTX = r"call|phone|mobile|\bmob\b|contact|whatsapp|\bwa\b|\btel\b|\bph\b|reach|dial|helpline|\bsms\b"
_REF_CTX = r"\bref|utr|rrn|txn|transaction|order|invoice|\bid\b|a/c|acct|account|policy|loan|pnr|awb|tracking"


def phones(t: str) -> list[Candidate]:
    out = []
    for m in _IN_MOBILE.finditer(t):
        if V.indian_mobile_digits(m.group()) is None:
            continue
        explicit = m.group().lstrip().startswith(("+", "00", "91"))
        if _ctx_before(t, m.start(), _REF_CTX, 18) and not _ctx_before(t, m.start(), _PHONE_CTX, 18):
            continue                                                     # 'Ref no 9876543210' is a reference, not a phone
        conf = 0.95 if explicit or _ctx_before(t, m.start(), _PHONE_CTX, 30) else 0.72
        out.append(Candidate("PHONE", m.start(), m.end(), conf, "pattern:in-mobile", [] if conf > 0.9 else ["no_context"]))
    for m in _INTL.finditer(t):
        digits = re.sub(r"\D", "", m.group())
        if 8 <= len(digits) <= 15:
            out.append(Candidate("PHONE", m.start(), m.end(), 0.90, "pattern:intl-phone"))
    for m in _LANDLINE.finditer(t):
        out.append(Candidate("PHONE", m.start(), m.end(), 0.80 if _ctx_before(t, m.start(), _PHONE_CTX) else 0.62, "pattern:landline"))
    return out


# ----------------------------------------------------------------------------------------------- government identifiers
_AADHAAR = re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])")
_AADHAAR_CTX = r"aadhaa?r|uidai|\buid\b|आधार"
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])")
_GSTIN = re.compile(r"(?<![A-Za-z0-9])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z][A-Z0-9][0-9A-Z](?![A-Za-z0-9])")
_PASSPORT = re.compile(r"(?<![A-Za-z0-9])[A-PR-WY][1-9]\d{6}(?![A-Za-z0-9])")
_PASSPORT_CTX = r"passport|पासपोर्ट"
_EPIC = re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}\d{7}(?![A-Za-z0-9])")
_EPIC_CTX = r"voter|epic|election"
_DL = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2})[- ]?(\d{2})[- ]?((?:19|20)\d{2})[- ]?(\d{7})(?![A-Za-z0-9])")
_DL_CTX = r"\bdl\b|driving|licen[cs]e"


def gov_ids(t: str) -> list[Candidate]:
    out = []
    for m in _AADHAAR.finditer(t):
        ctx = _ctx_before(t, m.start(), _AADHAAR_CTX, 30)
        if V.aadhaar_ok(m.group()):
            spaced = bool(re.search(r"[ -]", m.group()))
            if not ctx and not spaced and _ctx_before(t, m.start(), _REF_CTX, 20):
                continue                                                 # 12-digit UPI reference numbers pass Verhoeff 1 in 10 times
            conf = 0.96 if ctx else (0.88 if spaced else 0.62)
            out.append(Candidate("NATIONAL_ID", m.start(), m.end(), conf, "pattern:aadhaar+verhoeff", [] if (ctx or spaced) else ["no_context"]))
        elif ctx:
            out.append(Candidate("NATIONAL_ID", m.start(), m.end(), 0.70, "context:aadhaar", ["checksum_failed"]))
    for m in _PAN.finditer(t):
        if V.pan_ok(m.group()):
            ctx = _ctx_before(t, m.start(), r"\bpan\b|permanent account|income tax|पैन", 25)
            out.append(Candidate("TAX_ID", m.start(), m.end(), 0.95 if ctx else 0.86, "pattern:pan"))
    for m in _GSTIN.finditer(t):
        if V.gstin_ok(m.group()):
            out.append(Candidate("TAX_ID", m.start(), m.end(), 0.93, "pattern:gstin+checksum"))
    for m in _PASSPORT.finditer(t):
        if _ctx_before(t, m.start(), _PASSPORT_CTX, 30):
            out.append(Candidate("PASSPORT", m.start(), m.end(), 0.92, "context:passport"))
    for m in _EPIC.finditer(t):
        ctx = _ctx_before(t, m.start(), _EPIC_CTX, 30)
        out.append(Candidate("VOTER_ID", m.start(), m.end(), 0.92 if ctx else 0.55, "pattern:epic", [] if ctx else ["no_context"]))
    for m in _DL.finditer(t):
        if m.group(1) in V.STATE_CODES:
            ctx = _ctx_before(t, m.start(), _DL_CTX, 30)
            out.append(Candidate("DRIVING_LICENCE", m.start(), m.end(), 0.93 if ctx else 0.70, "pattern:dl"))
    return out


# ----------------------------------------------------------------------------------------------- vehicle registration
_VEHICLE = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{0,3}[\s-]?\d{4}|\d{2}[\s-]?BH[\s-]?\d{4}[\s-]?[A-Z]{1,2})(?![A-Za-z0-9])")


def vehicles(t: str) -> list[Candidate]:
    out = []
    for m in _VEHICLE.finditer(t):
        if V.vehicle_reg_ok(m.group()):
            ctx = _ctx_before(t, m.start(), r"vehicle|registration|reg\.?\s*no|car|bike|challan|number plate|गाड़ी|वाहन", 35)
            out.append(Candidate("VEHICLE_REG", m.start(), m.end(), 0.93 if ctx else 0.80, "pattern:vehicle-reg"))
    return out


# ----------------------------------------------------------------------------------------------- financial
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_ACCOUNT = re.compile(r"(?i)\b(?:a/c|acct|account|bank\s*account|savings\s*account)\s*(?:no\.?|number|num|#)?\s*[:#-]?\s*(\d{9,18})\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")


def financial(t: str) -> list[Candidate]:
    out = []
    for m in _CARD.finditer(t):
        d = re.sub(r"\D", "", m.group())
        if 13 <= len(d) <= 19 and V.luhn_ok(d):
            plausible = V.card_brand_plausible(d)
            ctx = _ctx_before(t, m.start(), r"card|credit|debit|visa|master|rupay", 30)
            if plausible or ctx:
                out.append(Candidate("CARD_NUMBER", m.start(), m.end(), 0.96 if ctx else 0.90, "pattern:card+luhn"))
    for m in _ACCOUNT.finditer(t):
        out.append(Candidate("BANK_ACCOUNT", m.start(1), m.end(1), 0.92, "context:bank-account"))
    for m in _IBAN.finditer(t):
        if V.iban_ok(m.group()):
            out.append(Candidate("BANK_ACCOUNT", m.start(), m.end(), 0.95, "pattern:iban+mod97"))
    return out


# ----------------------------------------------------------------------------------------------- credentials (secrets)
_CRED_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"(?i)\b(?:otp|one[\s-]?time\s+pass(?:word|code)|verification\s+code|security\s+code|auth(?:entication)?\s+code|login\s+code)\b"
                r"[^\d\n]{0,24}?(?<!\d)(\d{4,8})(?!\d)"), "context:otp", 0.95),
    (re.compile(r"(?i)(?<!\d)(\d{4,8})(?!\d)\s*(?:is|=|:)\s*(?:your|the)?\s*(?:otp|one[\s-]?time\s+password|verification\s+code|code)\b"), "context:otp-first", 0.95),
    (re.compile(r"(?i)\b(?:upi\s*pin|m-?pin|atm\s*pin|card\s*pin|pin\s*(?:no|number|code))\s*(?:is|:|-|=)\s*(\d{4,6})\b"), "context:pin", 0.95),
    (re.compile(r"(?i)\bcvv2?\b\s*(?:no\.?|number|code)?\s*(?:is|:|-|=)?\s*(\d{3,4})\b"), "context:cvv", 0.95),
    (re.compile(r"(?i)\b(?:password|passwd|pwd|passcode)\b\s*(?:is|:|-|=)\s*([^\s,;]{4,64})"), "context:password", 0.92),
]


_MONEY_WORDS = re.compile(r"(?i)\brs\b|\binr\b|₹|amount|\bamt\b|balance|\bbal\b|txn\s+of|worth")
_NOT_PASSWORDS = {"required", "incorrect", "expired", "expiring", "changed", "reset", "invalid", "weak", "strong", "updated"}


def credentials(t: str) -> list[Candidate]:
    out = []
    for rx, det, conf in _CRED_PATTERNS:
        for m in rx.finditer(t):
            value = m.group(1)
            gap = t[m.start():m.start(1)]
            if det == "context:otp" and _MONEY_WORDS.search(gap):
                continue                                                 # 'OTP for txn of Rs 5000': 5000 is an amount
            end = m.end(1)
            if det == "context:password":
                value = value.rstrip(".,;:!?)'\"")                       # sentence punctuation is not part of it
                end = m.start(1) + len(value)
                looks_secret = re.search(r"\d|[^A-Za-z0-9]", value) or (value.lower() != value and value.upper() != value)
                if len(value) < 4 or not looks_secret or value.lower() in _NOT_PASSWORDS:
                    continue                                             # 'password is required' is not a password
            out.append(Candidate("CREDENTIAL", m.start(1), end, conf, det))
    return out


# ----------------------------------------------------------------------------------------------- dates of birth
_MONTH = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_DATE = re.compile(rf"(?i)(?<![\w/.-])(?:\d{{1,2}}[/.-]\d{{1,2}}[/.-](?:19|20)?\d{{2}}|\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTH}\.?,?\s+(?:19|20)\d{{2}}|{_MONTH}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{{2}}|(?:19|20)\d{{2}}-\d{{2}}-\d{{2}})(?![\w/])")
_DOB_CTX = r"\bd\.?\s?o\.?\s?b\b|date\s*of\s*birth|birth\s*date|born(?:\s+on)?|birthday|जन्म"


def dobs(t: str) -> list[Candidate]:
    return [Candidate("DOB", m.start(), m.end(), 0.93, "context:dob") for m in _DATE.finditer(t) if _ctx_before(t, m.start(), _DOB_CTX, 28)]


# ----------------------------------------------------------------------------------------------- addresses (Indian + generic)
_PIN = r"(?<!\d)[1-9]\d{2}\s?\d{3}(?!\d)"
# Street suffixes only - ordinary words that also appear in addresses (Main, Block, Phase, Complex) cause false alarms.
_SUFFIX = (r"(?:Road|Rd|Street|St|Marg|Nagar|Colony|Layout|Sector|Lane|Ln|Cross|Avenue|Ave|Enclave|Vihar|Puram|Bagh|Chowk|"
           r"Society|Apartments?|Apts?|Residency|Towers?|Gali|Mohalla|Village|Taluk|Tehsil)")
_HOUSE = r"(?:(?:house|h\.?\s?no|flat|plot|door|d\.?\s?no|room|shop)\s*(?:no\.?|number|#)?\s*[:.-]?\s*[\w/-]{1,10}|#\s?[\w/-]{1,8}|\d{1,5}[A-Za-z]?(?:/\d{1,4})?)"
_STREET = re.compile(rf"(?i)(?<![\w]){_HOUSE},?\s+(?:[A-Za-z0-9'.-]+\s+){{0,5}}{_SUFFIX}\b\.?(?:(?:[ ,]+[A-Za-z0-9'.-]+){{0,6}}?[ ,-]+{_PIN})?")
_ADDR_LABEL = re.compile(r"(?i)\b(?:address|addr|residing at|resident of|lives at|permanent address|current address|पता)\s*[:\-]\s*([^\n]{8,140})")
_PIN_CTX = re.compile(rf"(?i)\b(?:pin\s*code|pincode|postal\s*code|zip)\s*[:\-]?\s*({_PIN})")


def addresses(t: str) -> list[Candidate]:
    out = []
    for m in _ADDR_LABEL.finditer(t):
        val = m.group(1).rstrip(" .;,")
        out.append(Candidate("ADDRESS", m.start(1), m.start(1) + len(val), 0.86, "context:address-label"))
    for m in _STREET.finditer(t):
        txt = m.group()
        if _ctx_before(t, m.start(), r"(?:rs\.?|inr|₹)\s*$", 6):
            continue                                                     # 'Rs 500 at the RTO office, MG Road' is an amount
        if len(txt) >= 12:
            home = _ctx_before(t, m.start(), r"home|resid|lives|stay|deliver|ship", 30)
            out.append(Candidate("ADDRESS", m.start(), m.end(), 0.82 if home else 0.72, "pattern:street-address"))
    for m in _PIN_CTX.finditer(t):
        out.append(Candidate("ADDRESS", m.start(1), m.end(1), 0.6, "context:pin-code", ["partial_address"]))
    return out


ALL = (credentials, financial, gov_ids, upi_ids, emails, phones, vehicles, dobs, addresses)


def scan(t: str) -> list[Candidate]:
    hits: list[Candidate] = []
    for fn in ALL:
        hits.extend(fn(t))
    return hits
