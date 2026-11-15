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
from ..url.parse import extract_urls
from . import indicators as I
from . import money
from .claims import RawClaim, extract_claims
from .normalize import normalize
from .sender import analyze_sender

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_HINGLISH = re.compile(r"(?i)\b(?:aapka|aapke|aapki|apna|apne|hai|hain|karein|kare|karo|kijiye|turant|abhi|jaldi|nahi|warna|paisa|paise|"
                       r"bhejo|bhejein|bata|batayein|yojana|sarkar|khata|ho\s+jayega|jayega|kripya|dhanyavad)\b")


# Disclosures that genuine promotions carry. They never cancel strong evidence; they stop ambiguous promotional wording
# from adding up to a "likely scam" verdict (see the promotion rules in ``combine``).
DISCLOSURE = re.compile(r"(?i)\b(?:t\s?&\s?c\'?s?\s+apply|terms\s+(?:and|&)\s+conditions\s+apply|terms\s+apply|(?:18|21)\+(?:\s+only)?|"
                        r"play\s+responsibly|gamble\s+responsibly|subject\s+to\s+market\s+risks?|not\s+(?:an?\s+)?investment\s+advice|"
                        r"read\s+(?:all\s+)?(?:scheme|offer)\s+(?:related\s+)?documents|wagering\s+requirements?|licen[cs]ed\s+(?:and\s+regulated\s+)?by|"
                        r"regulated\s+by|this\s+game\s+involves\s+(?:an\s+element\s+of\s+)?financial\s+risk|may\s+lose\s+money)")
# "Open the GPay app to see your reward": genuine reward notifications send you to the app you already use.
OFFICIAL_APP_CTA = re.compile(r"(?i)\b(?:open|check|see|use|via|in|on)\s+(?:the\s+|your\s+)?(?:official\s+)?[a-z][\w-]*(?:\s+[a-z][\w-]*)?\s+app\b")
_GIVEAWAY_WORDS = re.compile(r"(?i)\b(?:giving|give\s+away|handing\s+out|gifting|distributing|airdropping|dropping|free|giveaway|airdrop)\b")
_ANY_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[\s-]?)?(?:\(?\d{2,4}\)?[\s-]?){2,4}\d{3,4}(?!\d)")
_HELPLINE = re.compile(r"(?i)\b(?:customer\s+(?:care|care\s+number|support|service)|helpline|support\s+(?:number|team|desk)|toll[\s-]?free)\b")
_APPROVE_REQUEST = re.compile(r"(?i)\b(?:approve|accept)\b[^\n]{0,40}\b(?:request|it)\b|\brequest\b[^\n]{0,40}\b(?:approve|accept)\b")
# signals that are the same underlying evidence when one sits inside the other ("giving away" inside "giving away $5,600")
_REWARD_FAMILY = {"giveaway_lure", "reward_offer", "prize_claim", "free_offer_lure", "celebrity_giveaway", "unrealistic_reward"}


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
    spans: dict[str, list[tuple[int, int]]] = field(default_factory=dict)   # indicator key -> every place it matched
    reward: money.Amount | None = None         # the largest amount offered as a reward, if any
    disclosed: bool = False                    # carries T&C / 18+ / market-risk style disclosures
    debunk: bool = False                       # reads like a fact-check, news report or scam warning
    app_cta: bool = False                      # "open the GPay app": points to an official app instead of a link


def analyze_text(text: str, sender: str | None = None, sensitivity: str = "balanced") -> TextAnalysis:
    findings: list[RawFinding] = []
    # every match feeds the combination rules; the sensitivity setting only decides which weak findings are scored (below)
    matches = I.find(text)
    first: dict[str, RawFinding] = {}
    spans: dict[str, list[tuple[int, int]]] = {}
    for m in sorted(matches, key=lambda m: m.start):
        ind = m.indicator
        spans.setdefault(ind.key, []).append((m.start, m.end))
        if ind.key in first:                    # repeating a phrase is not new evidence: one finding, every place highlighted
            first[ind.key].more_spans.append((m.start, m.end))
            continue
        first[ind.key] = RawFinding(ind.key, ind.category, ind.title, ind.severity, ind.strength, ind.confidence,
                                    ind.explanation, ind.action, "message", m.start, m.end)
        findings.append(first[ind.key])
    keys = {m.indicator.key for m in matches}

    # an unrealistically large reward (amounts are parsed, not matched as words)
    reward = _largest_reward(text, spans)
    giveaway_framing = bool({"registration_reward", "everyone_reward"} & keys) or any(
        _GIVEAWAY_WORDS.search(text[a:b]) for a, b in spans.get("reward_offer", []))
    if reward is not None and reward.inr >= money.LARGE_REWARD_INR and giveaway_framing:
        f = RawFinding("unrealistic_reward", C.LOTTERY_PRIZE, "Unusually large reward for doing almost nothing", SV.MEDIUM, ST.WEAK, 0.8,
                       f"The message offers {reward.raw} for free. Genuine companies don't hand out sums like this to strangers; offers of this size "
                       "exist to get you onto a site that will later ask for a deposit, a fee or your details.",
                       "Don't register or pay anything to 'unlock' it.", "message", reward.start, reward.end)
        findings.append(f)
        keys.add("unrealistic_reward")
        spans["unrealistic_reward"] = [(reward.start, reward.end)]

    # a genuine reward notification ("You won a scratch card - open the GPay app") points to the official app and asks for nothing
    if "prize_claim" in first and OFFICIAL_APP_CTA.search(text) and not extract_urls(text) \
            and not ({"callback_number", "chat_handle", "fee_request", "payment_request", "credential_request"} & keys):
        f = first["prize_claim"]
        f.strength, f.confidence = ST.WEAK, 0.6
        f.evidence.append("it sends you to the official app and asks for no payment, details or contact - typical of genuine reward notifications")

    # "Do not share this with anyone" in an OTP message is the standard advisory, not a request for secrecy
    otp_advice = bool(re.search(r"(?i)\b(?:do\s+not|don'?t|never)\s+share\b", text) and re.search(r"(?i)\botp\b|one[\s-]?time|\bcode\b", text))
    if otp_advice and "credential_request" not in keys:
        findings = [f for f in findings if not (f.indicator == "secrecy" and re.search(r"(?i)share", text[f.start:f.end]))]

    findings = _drop_contained(findings)
    if sensitivity == "conservative":
        findings = [f for f in findings if not (f.strength == ST.WEAK and f.severity == SV.LOW)]

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
    ta = TextAnalysis(findings, keys, claimed, snd, extract_claims(text), detect_language(text), otp_advisory)
    ta.spans, ta.reward = spans, reward
    ta.disclosed = DISCLOSURE.search(text) is not None
    ta.debunk = I.is_debunk(text)
    ta.app_cta = OFFICIAL_APP_CTA.search(text) is not None
    return ta


def _largest_reward(text: str, spans: dict[str, list[tuple[int, int]]]) -> money.Amount | None:
    """The biggest amount that the message offers as a reward (an amount inside or right after a reward phrase)."""
    zones = spans.get("reward_offer", []) + spans.get("everyone_reward", [])
    if not zones:
        return None
    amounts = money.find_amounts(text)
    norm = normalize(text)
    if norm.text != text:                       # "$5.6OO" written with letters still counts once normalised
        for a in money.find_amounts(norm.text):
            s0, e0 = norm.span(a.start, a.end)
            if not any(s0 < b.end and b.start < e0 for b in amounts):
                amounts.append(money.Amount(s0, e0, text[s0:e0], a.value, a.currency))
    hits = [a for a in amounts if any(zs - 2 <= a.start and a.end <= ze + 2 for zs, ze in zones)]
    return max(hits, key=lambda a: a.inr, default=None)


def _drop_contained(findings: list[RawFinding]) -> list[RawFinding]:
    """The same words can't be two pieces of evidence: a finding whose text lies inside a stronger (or equally strong)
    finding's text is dropped - "immediately" inside "withdraw the bonus immediately", "giving away" inside
    "giving away $5,600". Context findings (INFO) are kept; they carry no points anyway."""
    from ..risk import points
    keep: list[RawFinding] = []
    for f in findings:
        if f.start is None or f.severity == SV.INFO:
            keep.append(f)
            continue
        inside = any(g is not f and g.start is not None and g.severity != SV.INFO and g.start <= f.start and f.end <= g.end
                     and (g.end - g.start) > (f.end - f.start) and points(g) >= points(f)
                     and (f.indicator in _REWARD_FAMILY) == (g.indicator in _REWARD_FAMILY)
                     for g in findings)
        if not inside:
            keep.append(f)
    return keep


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
    secret_ask = {"credential_request", "credential_entry", "kyc_suspension", "upi_collect_trick", "bank_details_request", "seed_phrase_request"} & k

    first_bad = unofficial[0].url_id if unofficial else None
    # links that belong to no known organisation at all (a giveaway that links to amazon.in is Amazon's own promotion)
    untrusted = [r for r in unofficial if not r.official_entity]
    first_untrusted = untrusted[0].url_id if untrusted else None

    def add(key, cat, title, sev, strength, conf, explanation, action, evidence, pattern, link: bool = False, url_id: str | None = None,
            families: tuple[str, ...] = (), quotes: list[tuple[str, int, int]] | None = None):
        # combination findings that are about a link are attached to it, so the link's own verdict reflects them
        out.append(RawFinding(key, cat, title, sev, strength, conf, explanation, action, "combination", evidence=evidence,
                              url_id=url_id or (first_bad if link else None), families=families, quotes=quotes or []))
        ta.patterns.append(pattern)

    def quote(label: str, key: str) -> list[tuple[str, int, int]]:
        return [(label, *ta.spans[key][0])] if ta.spans.get(key) else []

    promo = _promotion(ta, urls, untrusted, chat_links, text)

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
    if ({"prize_claim", "lottery_mention"} & k) and money_ask or ({"reward_offer", "unrealistic_reward"} & k and "fee_request" in k):
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
    if ({"kyc_suspension", "account_alert_lure"} & k) and unofficial and not claimed:
        add("kyc_with_link", C.PHISHING, "Account/KYC warning with a link", SV.HIGH, ST.STRONG, 0.85,
            "An 'account blocked / KYC expired' warning that sends you to a link is the classic banking phishing pattern.",
            "Open your bank's app yourself; never update KYC through a link.", ["KYC/account warning", "link"], "KYC warning + link", link=True)
    # C7 investment + contact
    if ({"investment_lure", "pump_hype"} & k) and (chat_links or {"callback_number", "chat_handle"} & k or unofficial):
        pressure = bool({"urgency", "vanishing_post", "threat_of_consequence"} & k)
        add("investment_with_contact", C.FAKE_INVESTMENT, "High-return investment pitched through a private channel", SV.HIGH, ST.STRONG, 0.88,
            "Guaranteed or very high returns offered through a chat group, personal number or unknown site is how investment scams operate.",
            "Invest only through SEBI-registered brokers' own apps; check sebi.gov.in.", ["return promise or token hype", "private contact or unknown site"],
            "Investment + private contact", link=bool(unofficial) and not (chat_links or {"callback_number", "chat_handle"} & k),
            families=("return promise", "private channel or unknown site") + (("pressure",) if pressure else ()))
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
    # C12 viral giveaway: a prize or free offer that must be forwarded to "unlock"
    giveaway_keys = {"giveaway_lure", "prize_claim", "free_offer_lure", "celebrity_giveaway", "free_scheme_claim"} & k
    forward_keys = {"share_to_unlock", "forward_demand"} & k
    if giveaway_keys and forward_keys:
        add("viral_giveaway", C.LOTTERY_PRIZE, "Giveaway that you must forward to claim", SV.HIGH, ST.STRONG, 0.9,
            "Free gifts, recharges or prizes that you have to forward to friends or groups are viral scams. The reward never arrives; the forwarding "
            "spreads the scam, and the final page collects your details, shows ads or pushes an app install.",
            "Don't forward it and don't enter anything. Check offers in the brand's or department's official app or website.",
            [f"offer: {', '.join(sorted(giveaway_keys))}", f"forwarding: {', '.join(sorted(forward_keys))}"], "Giveaway + forward demand",
            url_id=first_untrusted)
    # C13 prize / free offer / scheme + a link to a site that belongs to nobody known
    if giveaway_keys and untrusted and not promo["fired"]:
        hosts = ", ".join(sorted({r.registrable_domain or r.host for r in untrusted}))
        add("giveaway_link", C.LOTTERY_PRIZE, "Prize or free offer that sends you to an unknown site", SV.HIGH, ST.STRONG, 0.85,
            f"The message offers something for free or a prize and links to {hosts}, which doesn't belong to any brand or government body it could "
            "come from. Free-gift and fake-scheme sites ask for your phone number, Aadhaar or bank details, or a small 'delivery' or 'registration' fee.",
            "Don't open the link. Look for the offer on the official website or app.", [f"offer: {', '.join(sorted(giveaway_keys))}", f"link domain: {hosts}"],
            "Free offer + unknown link", url_id=first_untrusted)
    # C14 prize + "contact our manager" on a personal number or chat (KBC-style lottery)
    if ({"prize_claim", "lottery_mention"} & k) and ("callback_number" in k or chat_links or "chat_handle" in k):
        add("prize_with_contact", C.LOTTERY_PRIZE, "Prize that asks you to contact someone", SV.HIGH, ST.STRONG, 0.88,
            "A prize you never entered, claimed by calling or messaging a person, is the 'KBC lottery' pattern: the 'manager' then asks for a "
            "processing fee or tax before releasing the money.",
            "Don't call or reply. Block the number and report it on Chakshu (sancharsaathi.gov.in).", ["prize claim", "personal number or chat link"],
            "Prize + personal contact")
    # C15 unverified claim pushed for forwarding (hoax)
    hoax_keys = {"viral_fear_hoax", "known_hoax_claim", "health_misinformation", "policy_change_rumour", "sensational_authority", "free_scheme_claim"} & k
    spread_keys = {"forward_demand", "share_request", "share_to_unlock"} & k
    if hoax_keys and spread_keys:
        add("hoax_amplified", C.HOAX_MISINFORMATION, "Unverified claim pushed for forwarding", SV.MEDIUM, ST.STRONG, 0.85,
            "The message makes a claim it gives no source for and asks you to spread it. That combination is the signature of viral misinformation, "
            "whatever the topic.",
            "Don't forward it. Check the claim on PIB Fact Check or the official source first.",
            [f"claim: {', '.join(sorted(hoax_keys))}", f"spreading: {', '.join(sorted(spread_keys))}"], "Unsourced claim + forward request")
    # C11 official identity + personal callback number
    if strict and "callback_number" in k and not any(f.indicator == "official_from_personal_number" for f in ta.findings):
        sev, strength = (SV.HIGH, ST.STRONG) if ({"threat_of_consequence", "kyc_suspension"} & k) else (SV.MEDIUM, ST.WEAK)
        e = strict[0]
        add("official_with_personal_number", _cat_for(e), f"{e.name} message that asks you to call a mobile number", sev, strength, 0.8,
            f"{e.name} publishes official helpline numbers; a personal mobile number in its name is a common impersonation trick.",
            e.verify or "Use only the helpline on the official website.", [f"claimed sender: {e.name}", "personal mobile number"], "Official identity + personal number")
    # C21 account / SIM / KYC warning that asks you to call a mobile number (no official identity needed)
    elif ({"kyc_suspension", "account_alert_lure"} & k) and "callback_number" in k:
        add("account_warning_callback", C.PHISHING, "Account warning that asks you to call a mobile number", SV.HIGH, ST.STRONG, 0.85,
            "The message warns that an account, SIM or KYC will be blocked and gives a personal mobile number to call. Banks and telecom "
            "operators publish official helplines; the 'officer' on a mobile number asks for OTPs or remote access.",
            "Don't call the number. Check with the organisation through the helpline on its official website or app.",
            ["account / KYC warning", "personal mobile number"], "Account warning + personal number")

    # C16 / C17 money-for-nothing promotions (crypto casinos, betting apps, "free $1,000 to everyone who signs up")
    if promo["fired"] == "casino":
        add("crypto_casino_bonus", C.CRYPTO_GAMBLING, promo["title"], SV.HIGH, ST.STRONG, 0.9, promo["explanation"],
            "Don't register, deposit or pay any 'withdrawal' or 'verification' fee. If you already deposited, contact your bank and report it on 1930.",
            promo["evidence"], "Crypto / casino bonus lure", families=promo["families"], quotes=promo["quotes"])
    elif promo["fired"] == "cash":
        add("cash_giveaway_signup", C.LOTTERY_PRIZE, "Unrealistic cash reward for signing up on an outside site", SV.HIGH, ST.STRONG, 0.88,
            promo["explanation"], "Don't register or pay anything. Check the offer on the company's own official website or app.",
            promo["evidence"], "Cash giveaway + sign-up site", families=promo["families"], quotes=promo["quotes"])
    elif promo["fired"] == "weak":
        add("gambling_crypto_promo", C.CRYPTO_GAMBLING, "Crypto or gambling bonus promotion", SV.MEDIUM, ST.WEAK, 0.7,
            "The message advertises a bonus on a crypto or gambling platform. Some such offers are genuine, many are not: check that the "
            "operator is licensed, read its withdrawal conditions and never pay to unlock a bonus.",
            "Verify the operator before registering.", promo["evidence"], "Crypto / gambling promotion", quotes=promo["quotes"])
    if promo["reward"] and untrusted:
        hosts = ", ".join(sorted({r.registrable_domain or r.host for r in untrusted}))
        add("external_claim_site", C.SUSPICIOUS_LINK, "The reward has to be claimed on an outside website", SV.LOW, ST.WEAK, 0.7,
            f"To get the reward you are sent to {hosts}, which doesn't belong to any organisation Verioax can verify. That alone isn't proof "
            "of fraud - it means the site is unverified.", "Don't sign up or enter details on the site.", [f"link domain: {hosts}"],
            "Reward claimed on an unverified site", url_id=first_untrusted)
    # C18 wallet-connect / airdrop claim on an unknown site
    if "wallet_connect_lure" in k and (untrusted or chat_links or "chat_handle" in k):
        hosts = ", ".join(sorted({r.registrable_domain or r.host for r in untrusted})) or "a private chat"
        add("wallet_drainer_link", C.CRYPTO_GAMBLING, "Wallet 'claim' or 'validation' on an unknown site", SV.HIGH, ST.STRONG, 0.9,
            f"The message asks you to connect or validate your crypto wallet through {hosts}. Pages like this are wallet drainers: the "
            "approval or phrase you give them lets them move everything in the wallet.",
            "Don't connect your wallet. If you did, revoke the approval and move your funds to a new wallet.",
            ["wallet connection / validation request", f"destination: {hosts}"], "Wallet connect + unknown site", url_id=first_untrusted,
            quotes=quote("Wallet request", "wallet_connect_lure"))
    # C24 a brand's "customer care" on a personal mobile number (fake helplines found through search ads and messages)
    if claimed and "callback_number" in k and _HELPLINE.search(text) and not strict and not any(f.indicator == "official_from_personal_number" for f in ta.findings):
        e = claimed[0]
        add("fake_helpline", C.SOCIAL_ENGINEERING, f"'{e.name} customer care' on a personal mobile number", SV.HIGH, ST.STRONG, 0.86,
            f"The message gives a personal mobile number as {e.name}'s customer care or helpline. Companies publish their support numbers in their "
            "apps and on their websites; fake 'customer care' numbers lead to callers who ask for OTPs, UPI PINs or a screen-sharing app.",
            e.verify or "Use only the help section of the official app or the number on the official website.",
            [f"claimed company: {e.name}", "personal mobile number given as customer care"], "Brand helpline on a personal number",
            families=("claimed company", "personal number", "support pretext"))
    # C22 "sent by mistake - approve my request to get it back": the request takes money out of your account
    if "accidental_transfer" in k and _APPROVE_REQUEST.search(text):
        add("mistaken_transfer_request", C.FINANCIAL_FRAUD, "'Sent by mistake' story with a request to approve", SV.HIGH, ST.STRONG, 0.9,
            "The message claims money was sent to you by mistake and asks you to approve a request to 'return' it. Approving a UPI request "
            "pays money out of your account; the original 'credit' was a fake SMS or never happened.",
            "Decline the request and check your balance in your bank's own app.", ["claim of a mistaken credit", "request to approve"],
            "Mistaken credit + approval request", families=("fake credit claim", "return request", "approval request"),
            quotes=quote("Claim", "accidental_transfer"))
    # C23 fake security alert with a phone number to call
    if "tech_support_scare" in k and _ANY_PHONE.search(text):
        brand = any(e.kind in ("brand", "crypto", "platform") or e.key == "microsoft" for e in claimed)
        add("support_scare_call", C.SOCIAL_ENGINEERING, "Fake security alert with a support number", SV.HIGH, ST.STRONG, 0.88,
            "The message claims your device is infected or locked and gives a phone number for 'support'"
            + (", in the name of a well-known company" if brand else "") + ". The person who answers takes remote control of the device "
            "or charges for fake repairs.", "Don't call. Close the message and run your own antivirus.",
            ["fake infection / security alert", "phone number to call"] + (["impersonated company"] if brand else []),
            "Security scare + phone number", families=("fake alert", "phone number") + (("impersonated brand",) if brand else ())
            + (("pressure",) if {"urgency", "threat_of_consequence"} & k else ()))
    # C19 refund that needs your details, PIN or a link
    refund_needs = {"bank_details_request", "credential_entry", "credential_request", "upi_collect_trick", "kyc_suspension"} & k
    if "refund_lure" in k and (refund_needs or untrusted):
        what = "your bank details, PIN or card" if refund_needs else "a visit to an unknown site"
        add("refund_with_request", C.FINANCIAL_FRAUD, "Refund that needs your details or a link", SV.HIGH, ST.STRONG, 0.88,
            f"The message says a refund is waiting but that receiving it needs {what}. Genuine refunds go back to your original payment method "
            "on their own; asking for details or a PIN to 'release' one is a refund scam.",
            "Don't share anything. Check the refund status in the official app or website of the company.",
            ["refund offer", "request: " + (", ".join(sorted(refund_needs)) if refund_needs else "unofficial link")], "Refund + request",
            link=bool(untrusted) and not refund_needs, quotes=quote("Refund claim", "refund_lure"))
    return out


def _promotion(ta: TextAnalysis, urls: list[URLAnalysis], untrusted: list, chat_links: list, text: str) -> dict:
    """Recognises the money-for-nothing promotion pattern from independent families of evidence.

    No single ingredient is suspicious: crypto, casinos, bonuses, promo codes and sign-up offers are all normal in honest
    advertising. What genuine promotions don't combine is a reward (especially a large one) *plus* at least two of the
    mechanics below *plus* a place to register - and, when they carry the usual disclosures (T&C, 18+, market-risk
    notes), they need three mechanics before the pattern counts.
    """
    k = ta.matched_keys
    ctx = sorted(({"cryptocurrency"} if "crypto_context" in k else set()) | ({"casino / betting"} if "gambling_context" in k else set())
                 | {"crypto or gambling site name" for u in urls for sig, _ in u.signals if sig.key == "crypto_gambling_domain"})
    reward = bool({"reward_offer", "unrealistic_reward"} & k) or bool({"giveaway_lure", "free_offer_lure"} & k and ta.reward is not None)
    mech: dict[str, str] = {}
    if "everyone_reward" in k:
        mech["everyone"] = "offered to everyone"
    if "registration_reward" in k:
        mech["registration"] = "just for registering"
    if {"instant_withdrawal", "no_deposit_bonus"} & k:
        mech["instant"] = "withdrawable immediately / no deposit"
    if "vanishing_post" in k:
        mech["scarcity"] = "post will disappear / only the fastest"
    if {"self_launch_claim", "partnership_claim", "celebrity_giveaway"} & k:
        mech["persona"] = "unverified launch or partnership claim"
    if "unrealistic_reward" in k:
        mech["large"] = "unusually large amount"
    domainish = bool(I._DOMAINISH.search(normalize(text).text))
    destination = bool(untrusted or chat_links or ({"promo_code", "chat_handle", "callback_number"} & k) or (domainish and not urls))
    enough = len(mech) >= 2 and not (ta.disclosed and len(mech) < 3)
    fired = None
    if reward and destination and enough and ctx:
        fired = "casino"
    elif reward and destination and enough and ({"everyone", "registration"} & set(mech)) and ({"large", "instant", "scarcity", "persona"} & set(mech)):
        fired = "cash"
    elif reward and ctx and (destination or mech):
        fired = "weak"

    hosts = ", ".join(sorted({r.registrable_domain or r.host for r in untrusted}))
    amount = ta.reward.raw if ta.reward else ""
    evidence = ([f"reward: {amount}"] if amount else ["reward: bonus / free credit"]) + [f"mechanic: {v}" for v in mech.values()] \
        + ([f"context: {', '.join(ctx)}"] if ctx else []) + ([f"destination: {hosts} (unverified)"] if hosts else []) \
        + (["promo code required"] if "promo_code" in k else []) + (["has T&C / risk disclosures"] if ta.disclosed else [])
    quotes = []
    for label, key in (("Reward", "reward_offer"), ("Who gets it", "everyone_reward"), ("Condition", "registration_reward"),
                       ("Withdrawal claim", "instant_withdrawal"), ("Pressure", "vanishing_post"), ("Claimed association", "partnership_claim"),
                       ("Announcement", "self_launch_claim")):
        if ta.spans.get(key):
            quotes.append((label, *ta.spans[key][0]))
    families = tuple(["reward", "destination"] + (["context"] if ctx else []) + sorted(mech))
    return {"fired": fired, "reward": reward, "families": families, "evidence": evidence, "quotes": quotes,
            "title": "Crypto / casino bonus scam pattern" if fired == "casino" else "",
            "explanation": _promo_explanation(fired, amount, mech, ctx, hosts)}


def _promo_explanation(fired: str | None, amount: str, mech: dict[str, str], ctx: list[str], hosts: str) -> str:
    if fired not in ("casino", "cash"):
        return ""
    who = ("to everyone who registers" if {"everyone", "registration"} <= set(mech) else "to everyone" if "everyone" in mech
           else "just for registering" if "registration" in mech else "")
    first = " ".join(x for x in (f"The message promises {amount or 'a bonus'}", who) if x)
    first += " and claims it can be withdrawn immediately." if "instant" in mech else "."
    if fired == "casino":
        kind = "crypto-casino" if len(ctx) > 1 else ("crypto" if ctx and ctx[0] == "cryptocurrency" else "casino and betting")
        body = (f" A large, instantly withdrawable reward just for signing up is the standard lure of fake {kind} sites: they show a fake "
                "balance, then demand a deposit, 'verification' or 'withdrawal fee' before you can cash out - and nothing is ever paid out.")
    else:
        body = (" Real companies don't give strangers this kind of money for signing up. Fake reward sites use it to collect your details "
                "or to ask for a 'small' fee or deposit before the money can be released - which it never is.")
    if "scarcity" in mech:
        body += " Saying the post will soon disappear, or that only the fastest will benefit, is artificial pressure to stop you from checking."
    if "persona" in mech:
        body += " The announcement and the claimed link to another project or brand can't be verified; influencer and celebrity accounts are routinely impersonated for these posts."
    tail = (f" The website ({hosts}) is unverified: this verdict rests on what the message claims, not on proof that the site itself is malicious."
            if hosts else "")
    return first + body + tail


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
    if ta.disclosed and not dangerous:
        out.append(("Carries the terms, age or risk disclosures that genuine promotions include", 4.0))
    if ta.app_cta and not reports and not dangerous and not ({"callback_number", "chat_handle", "fee_request", "payment_request"} & k):
        out.append(("Sends you to the official app rather than to a link or a phone number", 4.0))
    ta.mitigations = out
    return out
