"""Context-sensitive recommended actions. Each action is triggered by specific findings, so the list explains itself."""
from __future__ import annotations

from .findings import RawFinding
from .schemas import Recommendation, RiskLevel, Severity, URLReport

# (id, priority, title, detail, trigger indicator keys or "category:<name>")
RULES: list[tuple[str, int, str, str, set[str]]] = [
    ("no_secrets", 1, "Don't share OTPs, PINs, CVV or passwords",
     "No bank, government office or delivery company ever asks for them - not by SMS, call or link.",
     {"credential_request", "credential_entry", "upi_collect_trick", "page_credential_form", "card_details_on_link"}),
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
     "Use only SEBI-registered brokers' own apps. Search the adviser or platform on sebi.gov.in.", {"investment_lure", "investment_with_contact"}),
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


def build(findings: list[RawFinding], level: RiskLevel, urls: list[URLReport], claimed: list[str], pii_types: list[str],
          id_of: dict[int, str], *, link_only: bool = False) -> list[Recommendation]:
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
