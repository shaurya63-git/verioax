"""The scam *type* shown to the user ("Detected scam category: Fake e-Challan").

Findings carry signal categories (phishing, social engineering, ...), which are what the score is built from. People
recognise scams by their story, so the verdict also names the scheme. The type is picked by an ordered list of rules -
most specific first, and direct theft mechanisms (OTP, UPI PIN, seed phrase) before the pretext around them - so the
same message always gets the same type and the rule that picked it can be shown.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..schemas import RiskLevel, ScamCategory


@dataclass(frozen=True)
class ScamType:
    key: str
    label: str
    summary: str


TYPES: dict[str, ScamType] = {t.key: t for t in (
    ScamType("crypto_casino", "Crypto casino / betting bonus scam",
             "Fake casino and betting sites lure people with a large 'free bonus' for signing up. The balance is fake: to withdraw it you are told to "
             "deposit money or pay a 'verification' or 'withdrawal' fee, and nothing is ever paid out."),
    ScamType("crypto_giveaway", "Crypto giveaway scam",
             "Fake giveaways promise free or doubled cryptocurrency. You are asked to send crypto first or to connect your wallet; whatever you send is lost."),
    ScamType("crypto_wallet", "Crypto wallet theft",
             "Messages about wallet problems, airdrops or unclaimed rewards try to get your recovery phrase or a wallet approval that lets them empty it."),
    ScamType("investment", "Investment / trading fraud",
             "Guaranteed or very high returns, 'VIP' trading groups, token hype and fake trading apps. Early 'profits' appear on screen, then withdrawals "
             "are blocked until you pay more."),
    ScamType("digital_arrest", "Digital arrest / fake police",
             "Callers pretending to be police, CBI or customs claim you are under investigation and demand money or constant video calls. No such procedure exists."),
    ScamType("upi_payment", "UPI / payment trick",
             "Tricks that get you to approve a collect request or enter your UPI PIN - which sends money out of your account - often after a fake "
             "'sent by mistake' message."),
    ScamType("otp_theft", "OTP / PIN theft",
             "Someone asks you to read out or forward an OTP, PIN or code. That code lets them take over an account or approve a payment."),
    ScamType("support_scam", "Fake customer support",
             "Fake helplines and 'security alerts' that get you to install a remote-access app, share codes or pay for fake support."),
    ScamType("e_challan", "Fake e-Challan / traffic fine",
             "Fake traffic-fine notices with a payment link or an app to install. Real challans are checked on echallan.parivahan.gov.in or in mParivahan."),
    ScamType("utility", "Fake electricity / utility disconnection",
             "A notice that your electricity or gas will be cut off tonight unless you call an 'officer' - who then gets you to install an app or pay."),
    ScamType("refund", "Fake refund",
             "A refund you didn't expect, 'released' only if you share bank details or a PIN, or open a link."),
    ScamType("job", "Fake job / task scam",
             "Easy online jobs (liking videos, rating hotels, 'tasks') that end with you paying deposits to 'unlock' earnings."),
    ScamType("govt_scheme", "Fake government scheme",
             "Messages about free laptops, recharges or scheme payments that collect Aadhaar, bank details or fees on sites that aren't government sites."),
    ScamType("delivery", "Courier / delivery scam",
             "A parcel is 'on hold' and needs a small fee or an address update through a link."),
    ScamType("lottery", "Lottery / prize scam",
             "You 'won' a lottery or prize you never entered. The 'manager' asks for a processing fee or tax before the prize can be released."),
    ScamType("advance_fee", "Advance-fee fraud",
             "You are asked to pay first - a processing, clearance or registration fee - to receive money, a loan, a parcel or a job. The payout never comes."),
    ScamType("giveaway", "Fake giveaway or free offer",
             "Free gifts, recharges, subscriptions or cash that lead to pages collecting your details or card number, or a small 'delivery fee'."),
    ScamType("malicious_app", "Malicious app (APK)",
             "An app sent as a file or link (.apk) instead of through the Play Store. Such apps read SMS and OTPs and can take over the phone."),
    ScamType("kyc_phishing", "Fake account / KYC verification",
             "Warnings that an account, SIM or PAN will be blocked unless you 'update KYC' through a link or a phone call."),
    ScamType("bank_phishing", "Bank or card phishing",
             "Messages that imitate a bank (reward points, card limits, unusual logins) and send you to a fake page that collects card or net-banking details."),
    ScamType("hoax", "Hoax / misinformation",
             "An unverified claim designed to be forwarded. Check it with PIB Fact Check or the official source before sharing."),
    ScamType("impersonation", "Impersonation",
             "The message claims to come from an organisation, but its links or phone numbers don't belong to that organisation."),
    ScamType("phishing", "Phishing link",
             "The message mainly pushes you to a link that shows warning signs or could not be verified."),
)}

_GOV_SCHEMES = {"pm_kisan", "ayushman", "pmay", "government_generic"}
_BANKS = {"sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bob", "canara", "union_bank"}
_CRYPTO_BRANDS = {"binance", "coinbase", "metamask", "trust_wallet", "wazirx", "coindcx", "coinswitch"}


def classify(keys: set[str], claimed: list[str], level: RiskLevel, top_category: ScamCategory | None,
             categories: set[ScamCategory] | None = None) -> ScamType | None:
    """The scam type for a verdict. None when nothing suspicious was found (LOW) or the verdict is INCONCLUSIVE.

    ``keys`` are the indicator keys that fired (message, link and combination findings, plus ``hint:*`` naming hints from
    the link checks); ``claimed`` are the organisations the message claims to be or that a lookalike link imitates."""
    if level not in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
        return None
    has = keys.__contains__
    any_of = keys.intersection
    ent = set(claimed)
    cats = categories or set()
    hoaxish = top_category == ScamCategory.HOAX_MISINFORMATION
    rules: list[tuple[str, bool]] = [
        ("digital_arrest", has("digital_arrest")),
        ("crypto_casino", has("crypto_casino_bonus") or has("hint:gambling")
         or (has("gambling_context") and bool(any_of({"gambling_crypto_promo", "cash_giveaway_signup", "giveaway_link"})))),
        ("crypto_giveaway", has("crypto_send_to_receive") or has("hint:crypto_giveaway")
         or (has("crypto_context") and bool(any_of({"cash_giveaway_signup", "celebrity_giveaway", "gambling_crypto_promo", "giveaway_link"})))),
        ("crypto_wallet", bool(any_of({"seed_phrase_request", "wallet_connect_lure", "wallet_drainer_link"})) or bool(ent & _CRYPTO_BRANDS)),
        ("upi_payment", bool(any_of({"upi_collect_trick", "accidental_transfer"}))),
        ("bank_phishing", has("card_details_request")),
        ("otp_theft", has("credential_request")),
        ("support_scam", bool(any_of({"remote_access", "tech_support_scare", "support_scare_call", "fake_helpline"}))),
        ("e_challan", "parivahan" in ent and not hoaxish),
        ("utility", bool(any_of({"electricity_disconnection", "electricity_callback"}))),
        ("refund", bool(any_of({"refund_with_request", "refund_lure"}))),
        ("job", bool(any_of({"job_lure", "job_with_fee", "job_via_chat"}))),
        ("investment", bool(any_of({"investment_lure", "pump_hype", "investment_with_contact"}))),
        ("govt_scheme", has("hint:scheme")
         or (bool(ent & _GOV_SCHEMES) and bool(any_of({"free_scheme_claim", "page_scheme_form", "scheme_lookalike", "giveaway_link", "impersonation_link_request",
                                                        "entity_link_mismatch", "bank_details_request", "free_offer_lure", "reward_offer", "unrealistic_reward",
                                                        "gov_lookalike", "lookalike_contains", "lookalike_typo"})))
         or (has("free_scheme_claim") and not hoaxish)),
        ("delivery", bool(any_of({"delivery_problem", "delivery_with_payment_or_link"}))),
        ("lottery", bool(any_of({"prize_with_fee", "prize_with_contact"})) or ("kbc" in ent and bool(any_of({"prize_claim", "lottery_mention"})))),
        ("advance_fee", bool(any_of({"fee_request", "loan_with_fee", "loan_lure"}))),
        ("hoax", top_category == ScamCategory.HOAX_MISINFORMATION),
        # a bank's reward points or card limit used as bait is bank phishing, not a giveaway
        ("bank_phishing", bool(ent & _BANKS) and bool(any_of({"credential_entry", "card_details_on_link", "page_credential_form", "impersonation_link_request",
                                                               "bank_details_request", "account_alert_lure"}))),
        ("giveaway", bool(any_of({"giveaway_lure", "free_offer_lure", "celebrity_giveaway", "viral_giveaway", "giveaway_link", "cash_giveaway_signup",
                                  "reward_offer", "prize_claim", "page_giveaway", "page_share_to_unlock", "unrealistic_reward", "giveaway_words_domain",
                                  "hint:giveaway_words"}))),
        ("malicious_app", bool(any_of({"apk_install", "page_apk", "dangerous_download"}))),
        ("kyc_phishing", bool(any_of({"kyc_suspension", "kyc_with_link", "account_warning_callback"}))),
        ("bank_phishing", bool(ent & _BANKS)
         or bool(any_of({"credential_entry", "card_details_on_link", "page_credential_form", "account_alert_lure", "bank_details_request"}))),
        ("hoax", ScamCategory.HOAX_MISINFORMATION in cats and not any_of({"impersonation_link_request", "entity_link_mismatch"})),
        ("impersonation", bool(any_of({"impersonation_link_request", "entity_link_mismatch", "official_from_personal_number", "official_with_personal_number",
                                       "lookalike_typo", "lookalike_contains", "lookalike_deceptive_subdomain", "gov_lookalike", "homograph"}))),
    ]
    for key, hit in rules:
        if hit:
            return TYPES[key]
    return TYPES["phishing"]
