"""TrustGuardEngine - the single entry point used by the API and the UI.

    engine = TrustGuardEngine()
    outcome = engine.scan_message("Your vehicle has a pending challan...", sender="+91 98765 43210")
    outcome.result      # ScanResult - audit-safe, stored in history, returned by the API
    outcome.restricted  # RestrictedData - original text + placeholder map, memory only

Pipeline for one input (each step is a separate module with its own tests):
    validate -> PII detect + redact + leak sweep -> scam/hoax text indicators -> link extraction -> URL integrity
    (static, guarded live, threat intel) -> combination rules + mitigations -> claims (+ optional fact-checks)
    -> risk score, level and confidence -> recommendations, review queue -> (optional) local-LLM explanation -> history
"""
from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, recommend, risk
from .cache import TTLCache
from .config import Preferences, Settings, get_settings, load_preferences
from .extract import ExtractionError, extract
from .findings import RawFinding
from .intel import IntelHub
from .llm import OllamaExplainer
from .pii import TYPE_LABELS, RestrictedPII, analyze_pii, ner_available
from .pii.redactor import OffsetMap
from .scam import analyze_text, combine, mitigations
from .scam.analyzer import TextAnalysis
from .scam.sender import sender_domain
from .schemas import (
    CATEGORY_LABELS,
    AnalysisMode,
    Claim,
    InputType,
    PIIReport,
    ProcessingMetadata,
    ReviewItem,
    RiskLevel,
    ScamCategory,
    ScamFinding,
    ScamReport,
    ScanResult,
    Severity,
    Strength,
    TextSpan,
)
from .storage import ScanStore
from .url import URLAnalyzer, extract_urls
from .url.analyzer import URLAnalysis
from .url.lexical import check as lexical_check
from .url.parse import FoundURL, URLParseError, parse

MAX_MESSAGE_CHARS = 20_000


class InputError(ValueError):
    """The input cannot be analysed (empty, too long, malformed URL, unsupported file)."""


@dataclass
class RestrictedData:
    """Raw content of one scan. Memory only: never stored, logged or returned by default."""
    original_text: str
    value_map: list[dict] = field(default_factory=list)
    offset_map: OffsetMap | None = None
    locate: Callable[[int], str] | None = None


@dataclass
class ScanOutcome:
    result: ScanResult
    restricted: RestrictedData


def installation_key(data_dir: Path) -> bytes:
    """Per-installation secret for value fingerprints (``data_dir/secret.key``, created on first use, owner-only)."""
    path = Path(data_dir) / "secret.key"
    try:
        key = path.read_bytes()
        if len(key) >= 32:
            return key
    except OSError:
        pass
    key = secrets.token_bytes(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except OSError:
        pass                                    # read-only data directory: the key lives for this process only
    return key


def new_scan_id(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"TG-{now:%Y%m%d}-{secrets.token_hex(3).upper()}"


class TrustGuardEngine:
    def __init__(self, settings: Settings | None = None, prefs: Preferences | None = None, *, store: ScanStore | None | bool = None,
                 cache: TTLCache | None = None, hub: IntelHub | None = None, url_analyzer: URLAnalyzer | None = None,
                 llm: OllamaExplainer | None = None):
        self.settings = settings or get_settings()
        self.prefs = prefs or load_preferences(self.settings)
        data_dir = Path(self.settings.data_dir)
        self.cache = cache if cache is not None else TTLCache(data_dir / "cache.sqlite")
        self.hub = hub or IntelHub(self.settings, self.prefs, self.cache)
        self.urls = url_analyzer or URLAnalyzer(self.settings, self.prefs, self.hub, self.cache)
        if store is False:
            self.store = None
        else:
            self.store = store if isinstance(store, ScanStore) else ScanStore(data_dir / "history.sqlite")
        self.llm = llm or OllamaExplainer(self.settings.ollama_url, self.settings.ollama_model)
        self.hash_key = installation_key(data_dir)

    def update_preferences(self, prefs: Preferences) -> None:
        self.prefs = prefs
        self.hub = IntelHub(self.settings, prefs, self.cache)
        self.urls = URLAnalyzer(self.settings, prefs, self.hub, self.cache)

    # ------------------------------------------------------------------ public entry points
    def scan_message(self, text: str, *, sender: str | None = None, mode: AnalysisMode = AnalysisMode.FULL,
                     source_name: str = "Pasted message", demo: bool = False) -> ScanOutcome:
        if text is None or not text.strip():
            raise InputError("There is no text to analyse. Paste a message first.")
        if len(text) > MAX_MESSAGE_CHARS:
            raise InputError(f"The message is too long ({len(text):,} characters). The limit is {MAX_MESSAGE_CHARS:,}; use the File Scanner for documents.")
        return self._run(text, InputType.MESSAGE, mode, source_name, sender=sender, demo=demo)

    def scan_url(self, url: str, *, demo: bool = False) -> ScanOutcome:
        url = (url or "").strip()
        if not url:
            raise InputError("Enter a link to check.")
        if len(url) > 2048 or any(c.isspace() for c in url):
            raise InputError("That doesn't look like a single link (it contains spaces or is too long).")
        try:
            parse(url)
        except URLParseError as exc:
            raise InputError(f"That doesn't look like a valid web link: {exc}.") from None
        return self._run(url, InputType.URL, AnalysisMode.FULL, "Submitted link", single_url=url, demo=demo)

    def scan_file(self, filename: str, data: bytes, *, mode: AnalysisMode = AnalysisMode.FULL, demo: bool = False) -> ScanOutcome:
        try:
            doc = extract(filename, data)
        except ExtractionError as exc:
            raise InputError(f"Couldn't read '{filename}': {exc}.") from None
        if not doc.text.strip():
            raise InputError(f"No readable text was found in '{filename}'. " + " ".join(doc.warnings))
        return self._run(doc.text, InputType.FILE, mode, filename, locate=doc.locate, extraction_warnings=doc.warnings, demo=demo)

    # ------------------------------------------------------------------ pipeline
    def _run(self, text: str, input_type: InputType, mode: AnalysisMode, source_name: str, *, sender: str | None = None,
             single_url: str | None = None, locate: Callable[[int], str] | None = None, extraction_warnings: list[str] | None = None,
             demo: bool = False) -> ScanOutcome:
        prefs = self.prefs
        t0 = time.perf_counter()
        timings: dict[str, int] = {}
        warnings: list[str] = list(extraction_warnings or [])
        created = datetime.now(timezone.utc)
        scan_id = new_scan_id(created)
        locate = locate or (lambda pos: f"line {text.count(chr(10), 0, pos) + 1}" if input_type == InputType.MESSAGE else "link")

        # ---- engine 1: PII (always when automatic redaction is on, so that only redacted text is ever stored)
        pii_report: PIIReport | None = None
        restricted_pii: RestrictedPII | None = None
        redacted_text: str | None = None
        use_ner = prefs.use_ner and ner_available()
        if mode in (AnalysisMode.FULL, AnalysisMode.PII) or prefs.auto_redact:
            t = time.perf_counter()
            pii_report, red, restricted_pii = analyze_pii(text, min_confidence=prefs.pii_min_confidence, review_threshold=prefs.pii_review_threshold,
                                                          sweep_rounds=prefs.leak_sweep_rounds, use_ner=use_ner, locate=locate,
                                                          extraction_warnings=extraction_warnings, hash_key=self.hash_key)
            redacted_text = red.redacted_text
            timings["pii_ms"] = _ms(t)
            if prefs.use_ner and not ner_available() and mode != AnalysisMode.SCAM:
                warnings.append("spaCy is not installed, so names are found by rules only (install the 'ner' extra for wider name coverage).")
        omap = restricted_pii.offset_map if restricted_pii else None

        # ---- engine 2: scam / hoax / links
        raw: list[RawFinding] = []
        analyses: list[URLAnalysis] = []
        ta: TextAnalysis | None = None
        mit_points = 0.0
        if mode != AnalysisMode.PII:
            t = time.perf_counter()
            ta = analyze_text("" if input_type == InputType.URL else text, sender, prefs.scam_sensitivity)
            raw += ta.findings
            timings["scam_ms"] = _ms(t)

            t = time.perf_counter()
            found = [FoundURL(single_url, single_url, 0, len(single_url), True)] if single_url else extract_urls(text, limit=50)
            if len(found) > prefs.max_urls_per_scan:
                warnings.append(f"Only the first {prefs.max_urls_per_scan} of {len(found)} links were analysed (Settings → max links per scan).")
                found = found[: prefs.max_urls_per_scan]
            claimed_keys = [e.key for e in ta.claimed]
            for i, f in enumerate(found, start=1):
                ua = self.urls.analyze(f.url, url_id=f"U{i:03d}", claimed_entities=claimed_keys,
                                       start=None if single_url else f.start, end=None if single_url else f.end)
                analyses.append(ua)
                if not single_url:
                    raw.append(RawFinding("link", ScamCategory.SUSPICIOUS_LINK, "Link in the message", Severity.INFO, Strength.WEAK, 1.0,
                                          "Links are checked separately in the link report.", source="message", start=f.start, end=f.end,
                                          url_id=ua.report.url_id))
                for sig, src in ua.signals:
                    raw.append(RawFinding(sig.key, sig.category, sig.title, sig.severity, sig.strength, sig.confidence, sig.explanation,
                                          sig.action, src, None if single_url else f.start, None if single_url else f.end,
                                          evidence=list(sig.evidence) + [ua.report.defanged], url_id=ua.report.url_id))
            dom = sender_domain(ta.sender)
            if dom:
                try:
                    lex = lexical_check(parse(dom), claimed_entities=claimed_keys)
                    raw += [RawFinding(s.key, s.category, f"Sender address: {s.title}", s.severity, s.strength, s.confidence, s.explanation,
                                       s.action, "sender", evidence=s.evidence) for s in lex.signals if s.key.startswith(("lookalike", "gov_", "homograph"))]
                except URLParseError:
                    pass
            timings["url_ms"] = _ms(t)
            raw += combine(ta, analyses, text)
            mit_points = sum(p for _, p in mitigations(ta, analyses))
            if analyses and not prefs.network_checks:
                warnings.append("Live link checks are off (local processing mode): links were analysed from their text only.")
            if analyses and not any(self.hub.status_of(p) for p in ("google_safe_browsing", "virustotal", "urlhaus", "phishtank", "openphish")):
                warnings.append("No online threat-intelligence service is configured; reputation comes from the local indicator list only.")

        # ---- numbering + redaction-safe excerpts
        raw.sort(key=lambda f: (f.severity == Severity.INFO, -f.rank()[0], -f.rank()[1], f.start if f.start is not None else 10**9))
        findings: list[ScamFinding] = []
        id_of: dict[int, str] = {}
        for n, f in enumerate(raw, start=1):
            fid = f"S{n:03d}"
            id_of[id(f)] = fid
            ex, rs, re_ = self._excerpt(f, redacted_text, omap, analyses)
            more: list[TextSpan] = []
            for s0, e0 in f.more_spans:
                if omap is not None and redacted_text is not None:
                    a0, b0 = omap.to_redacted(s0), omap.to_redacted(e0, end=True)
                    more.append(TextSpan(start=s0, end=e0, redacted_start=a0, redacted_end=b0))
                    ex = f"{ex} … {redacted_text[a0:b0]}"
                else:
                    more.append(TextSpan(start=s0, end=e0))
            evidence = list(f.evidence) + ([f"Appears {len(more) + 1} times in the message (counted once)"] if more else [])
            findings.append(ScamFinding(id=fid, indicator=f.indicator, category=f.category, title=f.title, severity=f.severity, strength=f.strength,
                                        confidence=round(f.confidence, 2), matched_text=ex[:300], start=f.start, end=f.end, redacted_start=rs,
                                        redacted_end=re_, more_spans=more, explanation=f.explanation, evidence=evidence,
                                        recommended_action=f.action, source=f.source))

        # ---- per-link assessment
        for ua in analyses:
            mine = [f for f in raw if f.url_id == ua.report.url_id and f.indicator != "link"]
            verified = ua.report.visited or any(r.mode in ("live", "cache") and r.status in ("listed", "suspicious", "clean", "not_found")
                                                for r in ua.report.reputation)
            trusted = bool(ua.report.official_entity or ua.report.restricted_registry)
            a = risk.assess(mine, sensitivity=prefs.scam_sensitivity, unverified_link=not (verified or trusted))
            ua.report.final_assessment = a.level
            ua.report.indicator_ids = [id_of[id(f)] for f in mine]
            ua.report.assessment_summary = _url_summary(a.level, mine, ua)

        # ---- overall assessment
        claims = self._claims(ta, redacted_text, omap) if ta else []
        if mode == AnalysisMode.PII:
            level, score, basis, rules, evidence = self._privacy_level(pii_report)
            conf = _pii_confidence(pii_report)
        else:
            unverified = bool(analyses) and not any(
                ua.report.visited or ua.report.official_entity or ua.report.restricted_registry
                or any(r.mode in ("live", "cache") and r.status in ("listed", "suspicious", "clean", "not_found") for r in ua.report.reputation)
                for ua in analyses)
            a = risk.assess(raw, sensitivity=prefs.scam_sensitivity, mitigation_points=mit_points, unverified_link=unverified)
            level, score, basis, rules, evidence = a.level, a.score, "threat", a.rules, a.evidence
            conf = risk.confidence(raw, level, text_len=len(text), urls_total=len(analyses),
                                   urls_live=sum(ua.report.visited for ua in analyses),
                                   online_intel=any(r.mode in ("live", "cache") for ua in analyses for r in ua.report.reputation),
                                   input_is_url=input_type == InputType.URL)
            if ta:
                rules = rules + [f"pattern: {p}" for p in ta.patterns] + [f"mitigation: {m}" for m, _ in ta.mitigations]

        title, summary = _verdict(level, basis, raw, ta, pii_report, analyses)
        pii_types = [TYPE_LABELS.get(t, t).lower() for t in (pii_report.by_type if pii_report else {})]
        recs = recommend.build(raw, level, [ua.report for ua in analyses], [e.key for e in ta.claimed] if ta else [], pii_types, id_of,
                               link_only=input_type == InputType.URL)

        review: list[ReviewItem] = []
        if pii_report and mode != AnalysisMode.SCAM:
            review += [ReviewItem(kind="pii", ref=f.id, reason=f"{TYPE_LABELS.get(f.entity_type, f.entity_type)} detected with {f.confidence:.0%} confidence"
                                  + (" (checksum failed)" if "checksum_failed" in f.flags else "")) for f in pii_report.findings if f.needs_review]
        review += [ReviewItem(kind="url", ref=ua.report.url_id, reason="link could not be verified" + (f" - {ua.report.visit_note}" if ua.report.visit_note else ""))
                   for ua in analyses if ua.report.final_assessment == RiskLevel.INCONCLUSIVE]
        review += [ReviewItem(kind="claim", ref=c.id, reason="claim needs independent verification") for c in claims]
        review += [ReviewItem(kind="extraction", ref="file", reason=w) for w in (extraction_warnings or [])]

        scam_report = None
        if ta is not None:
            cats: dict[str, int] = {}
            for f in findings:
                if f.severity != Severity.INFO:
                    cats[f.category.value] = cats.get(f.category.value, 0) + 1
            scam_report = ScamReport(findings=findings, categories=cats, claims=claims, sender=ta.sender,
                                     claimed_entities=[e.name for e in ta.claimed], patterns=ta.patterns,
                                     mitigations=[m for m, _ in ta.mitigations], language=ta.language)

        modules = (["pii"] if pii_report and mode != AnalysisMode.SCAM else []) + (["scam", "url"] if ta else []) + \
                  (["intel"] if analyses else [])
        result = ScanResult(
            scan_id=scan_id, created_at=created, input_type=input_type, mode=mode, source_name=source_name,
            language=ta.language if ta else "en", overall_risk=level, risk_basis=basis, risk_score=score,
            model_confidence=conf, confidence_label=risk.confidence_label(conf), verdict_title=title, verdict_summary=summary,
            evidence_summary=evidence, pii=pii_report if mode != AnalysisMode.SCAM else None, scam=scam_report,
            urls=[ua.report for ua in analyses], recommended_actions=recs, review_items=review, warnings=warnings,
            redacted_text=redacted_text, text_length=len(text),
            processing=ProcessingMetadata(engine_version=__version__, modules=modules, network_mode="local" if prefs.local_mode else "online",
                                          config=prefs.model_dump(), config_hash=prefs.fingerprint(), rules_applied=rules,
                                          providers=[{"name": r["provider"], "state": r["state"]} for r in self.hub.status()],
                                          timings_ms=timings, demo=demo))

        if prefs.llm_explanations and redacted_text and ta is not None:
            t = time.perf_counter()
            top = [f"{f.title} ({f.strength.value})" for f in findings if f.severity != Severity.INFO][:8]
            result.ai_explanation = self.llm.explain(redacted_text, title, level.value, top, result.language)
            timings["llm_ms"] = _ms(t)
            if result.ai_explanation is None:
                warnings.append("The local LLM explanation was skipped (Ollama not reachable, or its answer failed validation).")
            else:
                result.processing.modules.append("llm")
        timings["total_ms"] = _ms(t0)
        result.processing.timings_ms = timings

        if self.store is not None and prefs.store_history:
            self.store.save(result, retention_days=prefs.retention_days)
        restricted = RestrictedData(original_text=text, value_map=restricted_pii.value_map if restricted_pii else [],
                                    offset_map=omap, locate=locate)
        return ScanOutcome(result, restricted)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _excerpt(f: RawFinding, redacted: str | None, omap: OffsetMap | None, analyses: list[URLAnalysis]) -> tuple[str, int | None, int | None]:
        if f.url_id:
            ua = next((u for u in analyses if u.report.url_id == f.url_id), None)
            ex = ua.report.defanged if ua else ""
        else:
            ex = ""
        if f.start is None or omap is None or redacted is None:
            return ex, None, None
        rs, re_ = omap.to_redacted(f.start), omap.to_redacted(f.end, end=True)
        return (ex or redacted[rs:re_][:200]), rs, re_

    def _claims(self, ta: TextAnalysis, redacted: str | None, omap: OffsetMap | None) -> list[Claim]:
        out: list[Claim] = []
        fc = self.hub.factcheck
        can_check = fc.configured() and self.prefs.factcheck_lookups and not self.prefs.local_mode
        for n, rc in enumerate(ta.claims, start=1):
            if redacted is None or omap is None:
                text = ""
            else:
                text = redacted[omap.to_redacted(rc.start):omap.to_redacted(rc.end, end=True)].strip()
            claim = Claim(id=f"C{n:03d}", text=text, kind=rc.kind, start=rc.start, end=rc.end, how_to_verify=rc.how_to_verify)
            if can_check and text:
                refs = fc.search(text, language="hi" if ta.language == "hi" else "en")
                if refs is None:
                    claim.verification_status = "not_checked"
                elif refs:
                    claim.verification_status, claim.fact_checks = "related_fact_checks_found", refs
                else:
                    claim.verification_status = "no_fact_checks_found"
            out.append(claim)
        return out

    @staticmethod
    def _privacy_level(pii: PIIReport | None):
        if pii is None:
            return RiskLevel.LOW, 0, "privacy", [], {}
        mapping = {"NONE": RiskLevel.LOW, "LOW": RiskLevel.LOW, "MEDIUM": RiskLevel.MEDIUM, "HIGH": RiskLevel.HIGH, "CRITICAL": RiskLevel.CRITICAL}
        rules = [f"privacy exposure {pii.exposure.level} from: {', '.join(pii.exposure.drivers)}"] if pii.exposure.drivers else []
        if pii.status == "blocked":
            rules.append("leak sweep: residual personal data after redaction")
        return mapping[pii.exposure.level], pii.exposure.score, "privacy", rules, {}


# --------------------------------------------------------------------------------------------- text helpers
def _ms(t: float) -> int:
    return int((time.perf_counter() - t) * 1000)


def _pii_confidence(pii: PIIReport | None) -> float:
    if not pii or not pii.findings:
        return 0.7
    return round(sum(f.confidence for f in pii.findings) / len(pii.findings), 2)


def _url_summary(level: RiskLevel, mine: list[RawFinding], ua: URLAnalysis) -> str:
    rep = ua.report
    top = sorted(mine, key=lambda f: f.rank(), reverse=True)[:2]
    if level == RiskLevel.INCONCLUSIVE:
        return "Couldn't be verified: no live check or online reputation source was available. Treat it as unsafe until confirmed."
    if not top:
        if rep.official_entity:
            return f"Verified official domain of {rep.official_entity}. No warning signs found."
        if rep.restricted_registry:
            return "Domain under a restricted registry (only eligible organisations can register it). No warning signs found."
        return "No warning signs found in the checks that could be run. That is not a guarantee the site is safe."
    return "; ".join(f.title for f in top) + "."


# short phrases for the one-line verdict summary (the findings list keeps the full titles)
SHORT = {
    "impersonation_link_request": "asks for payment or details through a link the sender doesn't own",
    "entity_link_mismatch": "links to a domain the sender doesn't own", "official_from_personal_number": "sent from a personal or foreign number",
    "official_with_personal_number": "asks you to call a personal number", "intel_listed": "the link is on a threat-intelligence list",
    "lookalike_typo": "lookalike domain", "lookalike_contains": "brand name in an unofficial domain", "lookalike_deceptive_subdomain": "disguised domain",
    "gov_lookalike": "fake government-style domain", "homograph": "lookalike characters in the domain", "payment_request": "payment demand",
    "fee_request": "upfront fee demanded", "credential_request": "asks for an OTP, PIN or password", "upi_collect_trick": "UPI PIN requested to 'receive' money",
    "threat_of_consequence": "threats of penalties or blocking", "urgency": "pressure to act fast", "digital_arrest": "'digital arrest' threat",
    "secrecy": "asks you to keep it secret", "remote_access": "asks you to install a remote-access app", "apk_install": "asks you to install an APK",
    "prize_claim": "prize or lottery claim", "prize_with_fee": "prize that requires a payment", "job_with_fee": "job that requires a payment",
    "loan_with_fee": "loan that requires a fee", "forward_demand": "chain-forward request", "kyc_suspension": "account/KYC suspension warning",
    "page_credential_form": "the page collects card or banking details", "page_apk": "the page offers an APK", "new_domain": "very new domain",
    "shortener": "shortened link hides the destination", "dangerous_download": "the link downloads an app",
}


def _verdict(level: RiskLevel, basis: str, raw: list[RawFinding], ta: TextAnalysis | None, pii: PIIReport | None,
             analyses: list[URLAnalysis]) -> tuple[str, str]:
    if basis == "privacy":
        if not pii or not pii.findings:
            return "No personal data found", "No personal data was detected. Detection is not perfect - review before sharing widely."
        drivers = ", ".join(pii.exposure.drivers) or "personal data"
        return (f"Contains sensitive personal data ({pii.exposure.level.lower()} exposure)",
                f"{len(pii.findings)} item(s) found, including {drivers}. Share only the redacted version.")
    meaningful = [f for f in raw if f.severity != Severity.INFO]
    ranked = sorted(meaningful, key=lambda f: risk.points(f), reverse=True)
    cats: dict[ScamCategory, float] = {}
    for f in meaningful:
        cats[f.category] = cats.get(f.category, 0.0) + risk.points(f)
    top_cat = max(cats, key=cats.get) if cats else None
    hoax = top_cat == ScamCategory.HOAX_MISINFORMATION
    label = CATEGORY_LABELS.get(top_cat, "").lower() if top_cat else ""
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        title = "Likely hoax / misinformation" if hoax else f"Likely scam: {label}"
    elif level == RiskLevel.MEDIUM:
        title = "Possible hoax: verify before forwarding" if hoax else "Suspicious: verify before acting"
    elif level == RiskLevel.INCONCLUSIVE:
        title = "Couldn't verify the link: treat with caution"
    else:
        title = "No significant threat indicators found"
    parts: list[str] = []
    if ta and ta.claimed and level not in (RiskLevel.LOW,):
        parts.append(f"Presents itself as {ta.claimed[0].name}.")
    if ranked and level != RiskLevel.LOW:
        phrases = list(dict.fromkeys(SHORT.get(f.indicator, f.title[0].lower() + f.title[1:]) for f in ranked))[:3]
        parts.append("Main signals: " + "; ".join(phrases) + ".")
    if level == RiskLevel.LOW:
        parts.append("Nothing suspicious was found in the checks that ran. This is not a guarantee that the message is safe.")
    if level == RiskLevel.INCONCLUSIVE:
        parts.append("The message depends on a link that could not be checked live or against online reputation sources.")
    return title, " ".join(parts)
