"""Structured result schemas shared by every engine, the API, storage and the UI.

Privacy rule baked into these models: nothing here holds a raw PII value. PII findings carry a placeholder, a short
hash and offsets; text excerpts in scam findings and claims are taken from the *redacted* text. Raw values live only in
``RestrictedData`` (see ``trustguard.engine``), which is never serialised into reports or the scan history.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------------------------- enums
class InputType(str, Enum):
    MESSAGE = "message"
    URL = "url"
    FILE = "file"


class AnalysisMode(str, Enum):
    FULL = "full"          # scam & hoax + link integrity + PII
    SCAM = "scam"          # scam & hoax + link integrity
    PII = "pii"            # PII detection and redaction only


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Strength(str, Enum):
    """How much a single finding proves on its own (independent of how sure we are that we read it right)."""
    CONFIRMED = "confirmed"    # verifiable fact: threat-intel listing, APK download, card form on an impersonating page
    STRONG = "strong"          # a pattern scammers use and legitimate senders practically never do
    WEAK = "weak"              # common in scams but also in ordinary messages (urgency, a new domain)


class ScamCategory(str, Enum):
    PHISHING = "phishing"
    FINANCIAL_FRAUD = "financial_fraud"
    OTP_SCAM = "otp_scam"
    BANK_IMPERSONATION = "bank_impersonation"
    GOVERNMENT_IMPERSONATION = "government_impersonation"
    FAKE_JOB = "fake_job"
    FAKE_INVESTMENT = "fake_investment"
    LOTTERY_PRIZE = "lottery_prize"
    DELIVERY_PARCEL = "delivery_parcel"
    URGENT_PAYMENT = "urgent_payment"
    SOCIAL_ENGINEERING = "social_engineering"
    SUSPICIOUS_LINK = "suspicious_link"
    BRAND_IMPERSONATION = "brand_impersonation"
    HOAX_MISINFORMATION = "hoax_misinformation"
    CLAIM_VERIFICATION = "claim_verification"


CATEGORY_LABELS: dict[ScamCategory, str] = {
    ScamCategory.PHISHING: "Phishing",
    ScamCategory.FINANCIAL_FRAUD: "Financial fraud",
    ScamCategory.OTP_SCAM: "OTP / credential scam",
    ScamCategory.BANK_IMPERSONATION: "Bank impersonation",
    ScamCategory.GOVERNMENT_IMPERSONATION: "Government impersonation",
    ScamCategory.FAKE_JOB: "Fake job offer",
    ScamCategory.FAKE_INVESTMENT: "Fake investment scheme",
    ScamCategory.LOTTERY_PRIZE: "Lottery / prize scam",
    ScamCategory.DELIVERY_PARCEL: "Delivery / parcel scam",
    ScamCategory.URGENT_PAYMENT: "Urgent payment request",
    ScamCategory.SOCIAL_ENGINEERING: "Social engineering",
    ScamCategory.SUSPICIOUS_LINK: "Suspicious link",
    ScamCategory.BRAND_IMPERSONATION: "Brand impersonation",
    ScamCategory.HOAX_MISINFORMATION: "Hoax / misinformation",
    ScamCategory.CLAIM_VERIFICATION: "Claim needs verification",
}

CheckStatus = Literal["pass", "warn", "fail", "info", "unavailable"]
CheckSource = Literal["static", "live", "intel", "cache", "local"]


# --------------------------------------------------------------------------------------------- PII
class PIIFinding(BaseModel):
    id: str                                   # P001 ...
    entity_type: str                          # PERSON, EMAIL, PHONE, NATIONAL_ID ...
    placeholder: str                          # [PERSON_001]
    confidence: float
    band: Literal["high", "medium", "low"]
    start: int                                # offsets in the original text (restricted view only)
    end: int
    location: str                             # "message", "page 2", "row 4" ...
    detectors: list[str]
    value_hash: str                           # keyed fingerprint (HMAC, installation secret): same value -> same hash, not reversible
    length: int
    redacted: bool = True
    needs_review: bool = False
    origin: Literal["detector", "leak_sweep"] = "detector"
    flags: list[str] = Field(default_factory=list)


class PlaceholderSummary(BaseModel):
    placeholder: str
    entity_type: str
    occurrences: int


class LeakSweep(BaseModel):
    rounds: list[dict[str, int]] = Field(default_factory=list)   # [{"round": 0, "hits": 2}, ...]
    caught: int = 0                                                # extra items found and redacted by the sweep
    residual: int = 0                                              # still present after the last round -> blocked
    passed: bool = True


class PrivacyExposure(BaseModel):
    level: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    score: int
    drivers: list[str] = Field(default_factory=list)              # "card number", "OTP" ...


class PIIReport(BaseModel):
    findings: list[PIIFinding] = Field(default_factory=list)
    status: Literal["clean", "needs_review", "blocked"] = "clean"
    status_reasons: list[str] = Field(default_factory=list)
    by_type: dict[str, int] = Field(default_factory=dict)
    distinct_values: int = 0
    placeholders: list[PlaceholderSummary] = Field(default_factory=list)
    leak_sweep: LeakSweep = Field(default_factory=LeakSweep)
    exposure: PrivacyExposure = Field(default_factory=lambda: PrivacyExposure(level="NONE", score=0))
    redaction_coverage: float = 1.0                                # share of detected spans replaced in the output


# --------------------------------------------------------------------------------------------- scam / hoax
class TextSpan(BaseModel):
    start: int                                # original-text offsets
    end: int
    redacted_start: int | None = None         # the same span in the redacted text
    redacted_end: int | None = None


class ScamFinding(BaseModel):
    id: str                                   # S001 ...
    indicator: str                            # machine name, e.g. "credential_request"
    category: ScamCategory
    title: str
    severity: Severity
    strength: Strength
    confidence: float
    matched_text: str = ""                    # excerpt taken from the REDACTED text (safe to store)
    start: int | None = None                  # original-text offsets (None = message-level finding)
    end: int | None = None
    redacted_start: int | None = None         # the same span in the redacted text
    redacted_end: int | None = None
    more_spans: list[TextSpan] = Field(default_factory=list)   # further places the same indicator matched (counted once)
    explanation: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = ""
    source: Literal["message", "sender", "url", "page", "intel", "combination", "file"] = "message"


class FactCheckRef(BaseModel):
    publisher: str
    title: str = ""
    url: str
    rating: str = ""
    review_date: str | None = None


class Claim(BaseModel):
    id: str                                   # C001 ...
    text: str                                 # from the redacted text
    kind: str                                 # authority_notice | offer | policy_change | health | viral_forward | financial
    start: int | None = None
    end: int | None = None
    verification_status: Literal["unverified", "related_fact_checks_found", "no_fact_checks_found", "not_checked"] = "not_checked"
    fact_checks: list[FactCheckRef] = Field(default_factory=list)
    how_to_verify: str = ""


class SenderAnalysis(BaseModel):
    raw: str                                  # as typed by the user (a header or a phone number; not PII-redacted on purpose
    kind: Literal["dlt_header", "mobile_number", "foreign_number", "email", "short_code", "unknown"]
    category: str | None = None               # transactional / service / promotional / government (from the TRAI suffix)
    country_code: str | None = None
    notes: list[str] = Field(default_factory=list)


class ScamReport(BaseModel):
    findings: list[ScamFinding] = Field(default_factory=list)
    categories: dict[str, int] = Field(default_factory=dict)
    claims: list[Claim] = Field(default_factory=list)
    sender: SenderAnalysis | None = None
    claimed_entities: list[str] = Field(default_factory=list)     # who the message says it is from
    patterns: list[str] = Field(default_factory=list)              # combination rules that fired
    mitigations: list[str] = Field(default_factory=list)           # signals that lowered the score
    language: str = "en"


# --------------------------------------------------------------------------------------------- URL integrity
class URLCheck(BaseModel):
    key: str
    label: str
    status: CheckStatus
    summary: str
    explanation: str = ""
    source: CheckSource = "static"
    details: dict[str, Any] = Field(default_factory=dict)


class RedirectHop(BaseModel):
    url: str                                  # defanged
    status_code: int | None = None
    host: str = ""
    note: str = ""


class IntelResult(BaseModel):
    provider: str
    status: Literal["listed", "suspicious", "clean", "not_found", "not_configured", "disabled", "error", "unavailable"]
    mode: Literal["live", "cache", "local", "none"] = "none"
    verdict: str = ""                         # provider-specific wording
    details: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime | None = None
    attribution: str = ""


class TLSInfo(BaseModel):
    ok: bool
    reachable: bool = True                    # False = could not connect at all (that is not evidence about the certificate)
    error: str | None = None
    issuer: str | None = None
    subject: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    age_days: int | None = None
    san_count: int | None = None


class DomainInfo(BaseModel):
    source: str = "rdap"
    registered: datetime | None = None
    age_days: int | None = None
    registrar: str | None = None
    status: list[str] = Field(default_factory=list)
    error: str | None = None


class PageInspection(BaseModel):
    fetched: bool = False
    final_url: str | None = None              # defanged
    http_status: int | None = None
    content_type: str | None = None
    title: str | None = None
    bytes_read: int = 0
    forms: list[dict[str, Any]] = Field(default_factory=list)      # {"action_host":..., "sensitive_fields": [...]}
    sensitive_fields: list[str] = Field(default_factory=list)      # card_number, cvv, otp, upi_pin, password ...
    brand_terms: list[str] = Field(default_factory=list)           # government / bank words seen on the page
    hidden_text_chars: int = 0
    ai_directed_text: bool = False                                 # text addressed to AI scanners (prompt injection)
    apk_download: bool = False
    meta_refresh: str | None = None
    notes: list[str] = Field(default_factory=list)
    lure_signals: list[str] = Field(default_factory=list)          # scam/hoax indicator keys found in the visible page text
    lure_excerpts: dict[str, str] = Field(default_factory=dict)    # indicator key -> short excerpt of the page text (<= 140 chars)
    share_links: int = 0                                           # "share on WhatsApp / Facebook / Telegram" links
    debunk_context: bool = False                                   # the page reads like a fact-check or scam warning


class URLReport(BaseModel):
    url_id: str                               # U001 ...
    submitted_url: str                        # redaction-safe, NOT defanged (use `defanged` for display)
    defanged: str
    scheme: str = ""
    host: str = ""
    registrable_domain: str = ""
    suffix: str = ""
    official_entity: str | None = None        # set when the domain is a verified official domain
    restricted_registry: str | None = None    # gov.in / nic.in / bank.in ... (registry-restricted suffix)
    checks: list[URLCheck] = Field(default_factory=list)
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    reputation: list[IntelResult] = Field(default_factory=list)
    tls: TLSInfo | None = None
    domain_info: DomainInfo | None = None
    page: PageInspection | None = None
    visited: bool = False
    visit_note: str = ""
    final_assessment: RiskLevel = RiskLevel.INCONCLUSIVE
    assessment_summary: str = ""
    indicator_ids: list[str] = Field(default_factory=list)        # ScamFinding ids raised from this URL
    start: int | None = None                                       # position in the message (original text)
    end: int | None = None


# --------------------------------------------------------------------------------------------- unified result
class Recommendation(BaseModel):
    id: str
    priority: int                             # 1 = do this first
    title: str
    detail: str
    triggered_by: list[str] = Field(default_factory=list)


class ReviewItem(BaseModel):
    kind: Literal["pii", "scam", "url", "claim", "extraction"]
    ref: str
    reason: str


class ProcessingMetadata(BaseModel):
    engine_version: str
    modules: list[str]
    network_mode: Literal["online", "local"]
    config: dict[str, Any] = Field(default_factory=dict)
    config_hash: str = ""
    rules_applied: list[str] = Field(default_factory=list)
    providers: list[dict[str, str]] = Field(default_factory=list)
    timings_ms: dict[str, int] = Field(default_factory=dict)
    demo: bool = False


class ScanResult(BaseModel):
    scan_id: str
    created_at: datetime
    input_type: InputType
    mode: AnalysisMode
    source_name: str = ""
    language: str = "en"
    overall_risk: RiskLevel
    risk_basis: Literal["threat", "privacy"] = "threat"
    risk_score: int
    model_confidence: float
    confidence_label: Literal["Low", "Medium", "High"]
    verdict_title: str
    verdict_summary: str
    evidence_summary: dict[str, int] = Field(default_factory=dict)  # confirmed / strong / weak counts
    pii: PIIReport | None = None
    scam: ScamReport | None = None
    urls: list[URLReport] = Field(default_factory=list)
    recommended_actions: list[Recommendation] = Field(default_factory=list)
    review_items: list[ReviewItem] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    redacted_text: str | None = None
    text_length: int = 0
    ai_explanation: str | None = None          # optional local-LLM summary of the findings (never decides the verdict)
    processing: ProcessingMetadata

    # ---- convenience views used by the dashboard and history (derived, not stored separately)
    @property
    def scam_findings(self) -> list[ScamFinding]:
        return self.scam.findings if self.scam else []

    @property
    def pii_findings(self) -> list[PIIFinding]:
        return self.pii.findings if self.pii else []

    def counts(self) -> dict[str, int]:
        sf = self.scam_findings
        return {
            "scam_indicators": sum(f.source not in ("url", "page", "intel") for f in sf),
            "url_indicators": sum(f.source in ("url", "page", "intel") for f in sf),
            "pii_findings": len(self.pii_findings),
            "critical_warnings": sum(f.severity == Severity.CRITICAL for f in sf),
            "claims": len(self.scam.claims) if self.scam else 0,
            "review_items": len(self.review_items),
        }
