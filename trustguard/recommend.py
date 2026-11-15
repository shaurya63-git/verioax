"""Context-sensitive recommended actions. Each action is triggered by specific findings, so the list explains itself."""
from __future__ import annotations

from .findings import RawFinding
from .schemas import Recommendation, RiskLevel, Severity, URLReport

# (id, priority, title, detail, trigger indicator keys or "category:<name>")
RULES: list[tuple[str, int, str, str, set[str]]] = [
    ("no_secrets", 1, "Don't share OTPs, PINs, CVV or passwords",
     "No bank, government office or delivery company ever asks for them - not by SMS, call or link.",
     {"credential_request", "credential_entry", "upi_collect_trick", "page_credential_form", "card_details_on_link", "bank_details_request"}),
    ("no_seed_phrase", 1, "Never share your wallet recovery phrase",
     "No wallet, exchange or support team ever asks for it, and anyone who has it can empty your wallet. Don't connect your wallet to sites from messages.",
     {"seed_phrase_request", "wallet_connect_lure", "wallet_drainer_link"}),
    ("no_crypto_send", 1, "Don't send crypto to 'receive more back'",
     "Crypto transfers can't be reversed. A giveaway that asks you to send coins first - to 'verify' or to get double back - is always a scam.",
     {"crypto_send_to_receive"}),
    ("no_bonus_deposit", 1, "Don't register, deposit or pay to 'withdraw' a bonus",
     "Fake casino, betting and crypto sites show a balance that can never be withdrawn. Any 'deposit', 'verification' or 'withdrawal fee' is the scam itself.",
     {"crypto_casino_bonus", "cash_giveaway_signup", "gambling_crypto_promo", "no_deposit_bonus"}),
    ("no_return", 1, "Don't 'return' money that was 'sent by mistake'",
     "Check your balance in your bank's own app first. Never approve a collect request or enter your PIN to send money back.", {"accidental_transfer"}),
    ("no_support_call", 1, "Don't call numbers from security alerts",
     "Microsoft, Apple, Google and antivirus companies never put phone numbers in alerts. Close the message and run your own antivirus.",
     {"tech_support_scare"}),
    ("no_pin_to_receive", 1, "Never enter your UPI PIN to receive money",
     "Entering the PIN always sends money out of your account. Decline the collect request.", {"upi_collect_trick"}),
    ("no_remote_apps", 1, "Don't install remote-access or unknown apps",
     "Uninstall AnyDesk/TeamViewer or any APK you installed at someone's request, then change your banking passwords.",
     {"remote_access", "apk_install", "dangerous_download", "page_apk"}),
    ("digital_arrest", 1, "Hang up - 'digital arrest' is a scam",
     "Police, CBI, customs and courts never question or arrest anyone over video calls or ask for money. Call 1930.", {"digital_arrest"}),
    ("verify_challan", 2, "Check challans only on the official portal",
     "Open echallan.parivahan.gov.in or the mParivahan app yourself and search with your vehicle number.", {"entity:parivahan"}),
    ("contact_bank", 2, "Contact your bank through its official channel",
     "Use the bank's own app or the phone number printed on your card - not numbers or links from the message.",
     {"category:bank_impersonation", "kyc_suspension", "kyc_with_link"}),
    ("verify_official", 2, "Verify the sender through an official channel",
     "Find the organisation's contact details yourself (official website, app or bill) and ask them directly.",
     {"category:government_impersonation", "category:brand_impersonation", "official_from_personal_number", "entity_link_mismatch",
      "impersonation_link_request", "official_with_personal_number"}),
    ("no_fees", 2, "Don't pay any 'fee' to receive a prize, parcel, loan or job",
     "Genuine payouts never require you to pay first.", {"fee_request", "prize_with_fee", "job_with_fee", "delivery_with_payment_or_link"}),
    ("no_payment", 3, "Don't pay through links in messages",
     "If you think you owe money, open the official website or app yourself and check there.", {"payment_request", "impersonation_link_request"}),
    ("investment", 3, "Check investment offers with SEBI",
     "Use only SEBI-registered brokers' own apps. Search the adviser or platform on sebi.gov.in.", {"investment_lure", "investment_with_contact", "pump_hype"}),
    ("verify_promoter", 2, "Check the announcement on the verified official account",
     "Influencer, celebrity and brand accounts are impersonated for fake giveaways. Look for the same post on their verified profile or official website.",
     {"self_launch_claim", "partnership_claim", "celebrity_giveaway"}),
    ("refund_official", 2, "Refunds never need your PIN, OTP or bank details",
     "Genuine refunds go back to the original payment method on their own. Check the refund status in the company's official app.",
     {"refund_lure", "refund_with_request"}),
    ("dont_forward", 3, "Don't forward it until it's checked",
     "Look for the claim on the official website or a fact-checker such as PIB Fact Check (pib.gov.in/factcheck).",
     {"category:hoax_misinformation", "forward_demand"}),
]


# Wording for a scan of a bare link: there is no message or sender to verify or report.
LINK_ONLY: dict[str, tuple[str, str]] = {
    "verify_official": ("Find the official website yourself",
                        "Search for the organisation's own website or app instead of using this link, and compare the address carefully."),
    "report": ("Report the link",
               "Report it to Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish). If it reached you in a message, also "
               "report that on Chakshu (sancharsaathi.gov.in). If you lost money, call 1930 or file at cybercrime.gov.in immediately."),
    "inconclusive": ("Treat the link as unverified", "Don't open it or enter anything until you've confirmed it through the organisation's official website or app."),
}


APP_RULES: list[tuple[str, int, str, str, set[str]]] = [
    ("app_dont_install", 1, "Don't install this app",
     "Delete the file. Install apps only from the Google Play Store, and only the organisation's official app.", {"*"}),
    ("app_if_installed", 1, "If you already installed it",
     "Switch on airplane mode, remove it as device administrator (Settings > Security) if it is one, uninstall it, then call your bank to block "
     "cards and UPI and change your banking passwords from a different phone. Report it on 1930 or cybercrime.gov.in.",
     {"apk_otp_theft", "apk_banking_trojan", "apk_sms_access", "apk_accessibility", "apk_dropper", "apk_call_forwarding", "apk_impersonation"}),
    ("app_official", 2, "Get the official app instead",
     "Search for the organisation's own app in the Play Store and check the publisher name before installing.", {"apk_impersonation"}),
    ("app_lookup", 3, "Look the file up yourself if you want a second opinion",
     "Verioax doesn't upload apps anywhere. You can search the SHA-256 shown in the app report on VirusTotal - only the fingerprint, not the file.", {"*"}),
]


def build(findings: list[RawFinding], level: RiskLevel, urls: list[URLReport], claimed: list[str], pii_types: list[str],
          id_of: dict[int, str], *, link_only: bool = False, app: bool = False) -> list[Recommendation]:
    if app:
        keys = {f.indicator for f in findings}
        out = []
        for rid, prio, title, detail, triggers in APP_RULES:
            if (triggers == {"*"} and (rid != "app_dont_install" or level != RiskLevel.LOW)) or keys & triggers:
                refs = [id_of[id(f)] for f in findings if f.indicator in triggers and id(f) in id_of][:6]
                out.append(Recommendation(id=rid, priority=prio, title=title, detail=detail, triggered_by=refs or ["overall"]))
        if level == RiskLevel.LOW:
            out.insert(0, Recommendation(id="app_caution", priority=1, title="Prefer the Play Store version",
                                         detail="Nothing high-risk was found, but apps sent as files aren't vetted. If the app is on the Play Store, install it from there.",
                                         triggered_by=["overall"]))
        return sorted(out, key=lambda r: r.priority)[:6]
    keys = {f.indicator for f in findings}
    cats = {f"category:{f.category.value}" for f in findings if f.severity not in (Severity.INFO,)}
    ents = {f"entity:{c}" for c in claimed}
    present = keys | cats | ents
    out: list[Recommendation] = []

    bad_links = [u for u in urls if u.final_assessment in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.INCONCLUSIVE)]
    if bad_links:
        doms = ", ".join(sorted({u.defanged.split("/")[2] if "://" in u.defanged else u.defanged for u in bad_links}))
        out.append(Recommendation(id="dont_click", priority=1, title="Don't open the link",
                                  detail=f"The link ({doms}) is suspicious or couldn't be verified. If you already opened it, don't enter anything.",
                                  triggered_by=[u.url_id for u in bad_links]))
    elif urls and all(u.official_entity or u.restricted_registry for u in urls) and level in (RiskLevel.LOW, RiskLevel.MEDIUM):
        out.append(Recommendation(id="official_link", priority=3, title="The link goes to an official domain",
                                  detail="Before entering anything, check the address bar shows exactly the same domain. When in doubt, type the address yourself.",
                                  triggered_by=[u.url_id for u in urls]))

    # suppress actions that only make sense for a different scenario
    if level in (RiskLevel.LOW,) and not (keys & {"credential_request", "upi_collect_trick"}):
        present -= {"category:brand_impersonation"}
    for rid, prio, title, detail, triggers in RULES:
        hit = present & triggers
        if hit:
            refs = [id_of[id(f)] for f in findings if (f.indicator in hit or f"category:{f.category.value}" in hit) and id(f) in id_of][:6]
            if not refs and any(t.startswith("entity:") for t in hit):
                refs = [h for h in hit if h.startswith("entity:")]
            out.append(Recommendation(id=rid, priority=prio, title=title, detail=detail, triggered_by=refs))

    if pii_types:
        out.append(Recommendation(id="share_redacted", priority=3, title="Share only the redacted version",
                                  detail=f"This content contains {', '.join(pii_types[:4])}. Use the redacted text if you forward it or ask anyone for help.",
                                  triggered_by=["pii"]))
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        out.append(Recommendation(id="report", priority=2, title="Report it",
                                  detail="Report the message on Chakshu (sancharsaathi.gov.in). If you lost money, call 1930 or file at cybercrime.gov.in immediately - "
                                         "fast reporting improves the chance of freezing the money.", triggered_by=["overall"]))
    if level == RiskLevel.INCONCLUSIVE:
        out.append(Recommendation(id="inconclusive", priority=2, title="Treat it as unverified",
                                  detail="Don't open the link or reply until you've confirmed the message through an official channel.", triggered_by=["overall"]))
    if level == RiskLevel.LOW and not out:
        out.append(Recommendation(id="stay_alert", priority=4, title="No action needed - stay alert",
                                  detail="Nothing suspicious was found, which is not a guarantee. Verify unexpected requests for money or details through official channels.",
                                  triggered_by=["overall"]))
    if link_only:
        out = [r.model_copy(update=dict(zip(("title", "detail"), LINK_ONLY[r.id], strict=True))) if r.id in LINK_ONLY else r for r in out]
    seen, uniq = set(), []
    for r in sorted(out, key=lambda r: r.priority):
        if r.id not in seen:
            seen.add(r.id)
            uniq.append(r)
    return uniq[:7]
