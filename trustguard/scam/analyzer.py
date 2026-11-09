"""Engine 2a: scam and hoax analysis of message text, sender and (in the combination pass) the links.

Two passes:
1. ``analyze_text`` - phrase indicators, who the message claims to be from, sender format, hidden characters, claims;
2. ``combine`` - rules that need several pieces of evidence at once (e.g. "claims to be the traffic police AND asks for
   payment AND links to a domain the traffic police doesn't own"). These carry most of the weight in the score because
   no single phrase proves fraud, but the combination practically does.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .. import brands as B
from ..findings import RawFinding
from ..schemas import ScamCategory as C
from ..schemas import SenderAnalysis
from ..schemas import Severity as SV
from ..schemas import Strength as ST
from ..url.analyzer import URLAnalysis
from . import indicators as I
from .claims import RawClaim, extract_claims
from .sender import analyze_sender

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_HINGLISH = re.compile(r"(?i)\b(?:aapka|aapke|aapki|apna|apne|hai|hain|karein|kare|karo|kijiye|turant|abhi|jaldi|nahi|warna|paisa|paise|"
                       r"bhejo|bhejein|bata|batayein|yojana|sarkar|khata|ho\s+jayega|jayega|kripya|dhanyavad)\b")


def detect_language(text: str) -> str:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "unknown"
    deva = sum("ऀ" <= c <= "ॿ" for c in letters) / len(letters)
    if deva > 0.3:
        return "hi"
    if len(_HINGLISH.findall(text)) >= 2:
        return "hinglish"
    return "en" if deva < 0.05 else "mixed"


@dataclass
class TextAnalysis:
    findings: list[RawFinding]
    matched_keys: set[str]
    claimed: list[B.Entity]
    sender: SenderAnalysis | None
    claims: list[RawClaim]
    language: str
    otp_advisory: bool = False
    patterns: list[str] = field(default_factory=list)
    mitigations: list[tuple[str, float]] = field(default_factory=list)     # (description, points removed)


def analyze_text(text: str, sender: str | None = None, sensitivity: str = "balanced") -> TextAnalysis:
    findings: list[RawFinding] = []
    matches = I.find(text, sensitivity)
    first: dict[str, RawFinding] = {}
    for m in sorted(matches, key=lambda m: m.start):
        ind = m.indicator
        if ind.key in first:                    # repeating a phrase is not new evidence: one finding, every place highlighted
            first[ind.key].more_spans.append((m.start, m.end))
            continue
        first[ind.key] = RawFinding(ind.key, ind.category, ind.title, ind.severity, ind.strength, ind.confidence,
                                    ind.explanation, ind.action, "message", m.start, m.end)
        findings.append(first[ind.key])
    keys = {m.indicator.key for m in matches}

    # who does it claim to be from? (first mention per entity; generic govt only when nothing more specific)
    claimed: list[B.Entity] = []
    for e, _s, _e in B.find_entities(text):
        if e not in claimed:
            claimed.append(e)
    if len(claimed) > 1:
        claimed = [e for e in claimed if e.key != "government_generic"] or claimed

    # invisible characters
    zw, bidi = len(_ZERO_WIDTH.findall(text)), len(_BIDI.findall(text))
    if bidi:
        findings.append(RawFinding("bidi_control", C.SOCIAL_ENGINEERING, "Hidden text-direction characters", SV.HIGH, ST.STRONG, 0.85,
                                   f"The message contains {bidi} invisible right-to-left control character(s). They are used to disguise links and file names "
                                   "(e.g. 'photo‮gnp.apk' displays as 'photokpa.png').", "Don't open links or files from this message.", evidence=[f"{bidi} bidi control character(s)"]))
    elif zw >= 3:
        findings.append(RawFinding("zero_width", C.SOCIAL_ENGINEERING, "Invisible characters inside words", SV.LOW, ST.WEAK, 0.7,
                                   f"The message contains {zw} zero-width characters, a trick to slip past spam filters.", evidence=[f"{zw} zero-width character(s)"]))

    snd = analyze_sender(sender)
    if snd is not None:
        findings += _sender_findings(snd, claimed, keys)

    otp_advisory = bool(re.search(r"(?i)\b(?:do\s+not|don'?t|never)\s+share\b", text) and re.search(r"(?i)\botp\b|one[\s-]?time", text)
                        and "credential_request" not in keys)
    return TextAnalysis(findings, keys, claimed, snd, extract_claims(text), detect_language(text), otp_advisory)


def _sender_findings(snd: SenderAnalysis, claimed: list[B.Entity], keys: set[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    official = [e for e in claimed if e.kind in ("government", "bank", "payments", "telecom", "utility", "courier")]
    if snd.kind in ("mobile_number", "foreign_number") and official:
        e = official[0]
        cat = C.GOVERNMENT_IMPERSONATION if e.is_government else C.BANK_IMPERSONATION if e.kind == "bank" else C.BRAND_IMPERSONATION
        where = "a personal mobile number" if snd.kind == "mobile_number" else f"an international number ({snd.country_code})"
        out.append(RawFinding("official_from_personal_number", cat, f"Claims to be {e.name} but sent from {where}", SV.HIGH, ST.STRONG, 0.88,
                              f"{e.name} sends official messages from registered sender headers (like 'XX-ABCDEF-G'), not from {where}.",
                              e.verify or "Contact the organisation through its official website or app.", "sender", evidence=[snd.raw]))
    elif snd.kind == "foreign_number":
        out.append(RawFinding("foreign_sender", C.SOCIAL_ENGINEERING, "Sent from an international number", SV.MEDIUM, ST.WEAK, 0.75,
                              f"The sender uses an international number ({snd.country_code}). Indian banks, government offices and couriers don't contact you from abroad.",
                              "Don't reply or call back.", "sender", evidence=[snd.raw]))
    if snd.kind == "dlt_header" and snd.category == "promotional" and ({"payment_request", "credential_request", "kyc_suspension"} & keys):
        out.append(RawFinding("promo_header_payment", C.SOCIAL_ENGINEERING, "Payment or account request from a promotional header", SV.MEDIUM, ST.WEAK, 0.7,
                              "Promotional (-P) headers are for marketing. Account, payment and penalty notices come from transactional (-T), service (-S) or government (-G) headers.",
                              source="sender", evidence=[snd.raw]))
    return out


# ------------------------------------------------------------------------------------------------ combination pass
def _cat_for(e: B.Entity) -> C:
    return C.GOVERNMENT_IMPERSONATION if e.is_government else C.BANK_IMPERSONATION if e.kind == "bank" else C.BRAND_IMPERSONATION


def combine(ta: TextAnalysis, urls: list[URLAnalysis], text: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    k = ta.matched_keys
    claimed = ta.claimed
    strict = [e for e in claimed if e.kind in ("government", "bank", "payments")]

    def official_for_any_claim(host: str) -> bool:
        return any(B.host_is_official_for(host, e) for e in claimed)

    reports = [u.report for u in urls if u.report.host]
    unofficial = [r for r in reports if not official_for_any_claim(r.host) and not r.restricted_registry]
    chat_links = [r for r in reports if any(c.key == "chat" for c in r.checks)]
    money_ask = {"payment_request", "fee_request"} & k
    secret_ask = {"credential_request", "credential_entry", "kyc_suspension", "upi_collect_trick"} & k

    first_bad = unofficial[0].url_id if unofficial else None

    def add(key, cat, title, sev, strength, conf, explanation, action, evidence, pattern, link: bool = False):
        # combination findings that are about a link are attached to it, so the link's own verdict reflects them
        out.append(RawFinding(key, cat, title, sev, strength, conf, explanation, action, "combination", evidence=evidence,
                              url_id=first_bad if link else None))
        ta.patterns.append(pattern)

    # C1 / C2 - claimed identity vs. where the link goes
    if claimed and unofficial:
        e = strict[0] if strict else claimed[0]
        hosts = ", ".join(sorted({r.registrable_domain or r.host for r in unofficial}))
        if money_ask or secret_ask:
            what = "payment" if money_ask else "your details"
            add("impersonation_link_request", _cat_for(e), f"Claims to be {e.name}, asks for {what}, links elsewhere", SV.CRITICAL, ST.STRONG, 0.92,
                f"The message presents itself as {e.name} and asks for {what}, but its link goes to {hosts}, which {e.name} does not own. "
                "This combination is the core of fake e-challan, KYC and refund scams.",
                e.verify or "Go to the organisation's official website yourself.",
                [f"claimed sender: {e.name}", f"requests: {', '.join(sorted(money_ask | secret_ask))}", f"link domain: {hosts}"],
                "Impersonation + request + unofficial link", link=True)
        else:
            strong = e.kind in ("government", "bank")
            add("entity_link_mismatch", _cat_for(e), f"Claims to be {e.name} but links to {hosts}", SV.HIGH if strong else SV.MEDIUM,
                ST.STRONG if strong else ST.WEAK, 0.85 if strong else 0.7,
                f"The message names {e.name}, but the link points to {hosts}, which is not one of its domains.",
                e.verify or "Use the organisation's official website or app instead of the link.",
                [f"claimed sender: {e.name}", f"link domain: {hosts}"], "Claimed sender ≠ link owner", link=True)
    # C3 prize + fee
    if "prize_claim" in k and money_ask:
        add("prize_with_fee", C.LOTTERY_PRIZE, "Prize that requires a payment", SV.HIGH, ST.STRONG, 0.9,
            "You are told you won something and must pay to receive it. Real prizes never require a fee - this is advance-fee fraud.",
            "Don't pay anything. Block the sender.", ["prize claim", "payment/fee request"], "Prize + fee")
    # C4 job + fee / chat
    if "job_lure" in k and money_ask:
        add("job_with_fee", C.FAKE_JOB, "Job offer that requires a payment", SV.HIGH, ST.STRONG, 0.9,
            "A job or 'task' that asks you to pay (registration, deposit, 'to unlock earnings') is a task scam. Real employers pay you, not the other way round.",
            "Don't pay. Report the number on Chakshu (sancharsaathi.gov.in).", ["job offer", "payment/fee request"], "Job + fee")
    elif "job_lure" in k and chat_links:
        add("job_via_chat", C.FAKE_JOB, "Job offer that moves you to a private chat", SV.MEDIUM, ST.WEAK, 0.75,
            "Task scams recruit through WhatsApp/Telegram chats with individuals rather than a company careers page.",
            "Check the company's official careers page.", ["job offer", "chat link"], "Job + private chat")
    # C4b loan + fee
    if "loan_lure" in k and money_ask:
        add("loan_with_fee", C.FINANCIAL_FRAUD, "Loan that requires an upfront fee", SV.HIGH, ST.STRONG, 0.9,
            "A loan offer that asks you to pay a processing or registration fee first is advance-fee fraud. Regulated lenders deduct charges from the loan amount.",
            "Don't pay. Check the lender on the RBI website and apply only through its official app.", ["loan offer", "upfront fee"], "Loan + fee")
    # C5 delivery + payment/link
    if "delivery_problem" in k and (money_ask or unofficial):
        add("delivery_with_payment_or_link", C.DELIVERY_PARCEL, "Delivery problem that needs a payment or a link", SV.HIGH, ST.STRONG, 0.85,
            "A 'parcel on hold' message that asks for a fee or sends you to an unofficial link is a common delivery scam.",
            "Track the parcel in the courier's official app with the tracking number from the seller.", ["delivery problem", "payment or unofficial link"],
            "Delivery issue + payment/link", link=bool(unofficial))
    # C6 KYC/account warning + link (when C1 didn't already cover it)
    if "kyc_suspension" in k and unofficial and not claimed:
        add("kyc_with_link", C.PHISHING, "Account/KYC warning with a link", SV.HIGH, ST.STRONG, 0.85,
            "An 'account blocked / KYC expired' warning that sends you to a link is the classic banking phishing pattern.",
            "Open your bank's app yourself; never update KYC through a link.", ["KYC/account warning", "link"], "KYC warning + link", link=True)
    # C7 investment + contact
    if "investment_lure" in k and (chat_links or "callback_number" in k or unofficial):
        add("investment_with_contact", C.FAKE_INVESTMENT, "High-return investment pitched through a private channel", SV.HIGH, ST.STRONG, 0.88,
            "Guaranteed or very high returns offered through a chat group, personal number or unknown site is how investment scams operate.",
            "Invest only through SEBI-registered brokers' own apps; check sebi.gov.in.", ["return promise", "private contact"], "Investment + private contact")
    # C9 electricity + callback
    if "electricity_disconnection" in k and "callback_number" in k:
        add("electricity_callback", C.FINANCIAL_FRAUD, "Disconnection threat with a personal callback number", SV.HIGH, ST.STRONG, 0.9,
            "Fake electricity notices tell you to call an 'officer' on a mobile number. Real boards don't do this.",
            "Check your bill in the official app of your electricity board.", ["disconnection threat", "callback number"], "Disconnection + callback")
    # C10 card details + link
    if "credential_entry" in k and unofficial and not (claimed and (money_ask or secret_ask)):
        add("card_details_on_link", C.PHISHING, "Asks you to enter card or banking details on a link", SV.HIGH, ST.STRONG, 0.85,
            "Banks never ask you to type card numbers, CVV or net-banking passwords on a page opened from a message.",
            "Don't enter anything.", ["card/banking details request", "unofficial link"], "Card details + link", link=True)
    # C11 official identity + personal callback number
    if strict and "callback_number" in k and not any(f.indicator == "official_from_personal_number" for f in ta.findings):
        sev, strength = (SV.HIGH, ST.STRONG) if ({"threat_of_consequence", "kyc_suspension"} & k) else (SV.MEDIUM, ST.WEAK)
        e = strict[0]
        add("official_with_personal_number", _cat_for(e), f"{e.name} message that asks you to call a mobile number", sev, strength, 0.8,
            f"{e.name} publishes official helpline numbers; a personal mobile number in its name is a common impersonation trick.",
            e.verify or "Use only the helpline on the official website.", [f"claimed sender: {e.name}", "personal mobile number"], "Official identity + personal number")
    return out


def mitigations(ta: TextAnalysis, urls: list[URLAnalysis]) -> list[tuple[str, float]]:
    """Signals that make a genuine message more likely. They lower the raw score a little and never override strong evidence."""
    out: list[tuple[str, float]] = []
    k = ta.matched_keys
    dangerous = {"credential_request", "fee_request", "upi_collect_trick", "remote_access", "apk_install", "digital_arrest"} & k
    reports = [u.report for u in urls if u.report.host]
    if reports and not dangerous and all(r.official_entity or r.restricted_registry for r in reports):
        out.append(("Every link points to a verified official or restricted-registry domain", 12.0))
    snd = ta.sender
    if snd and snd.kind == "dlt_header":
        header = snd.raw.upper()
        if snd.category == "government" and any(e.is_government for e in ta.claimed):
            out.append(("Sent from a registered government SMS header (-G)", 10.0))
        elif snd.category in ("transactional", "service") and any(kw.upper()[:4] in header for e in ta.claimed if e.kind == "bank" for kw in e.keywords):
            out.append((f"Sent from a registered {snd.category} header that matches the bank", 8.0))
    if ta.otp_advisory:
        out.append(("Contains the standard 'do not share your OTP' advisory", 5.0))
    ta.mitigations = out
    return out
