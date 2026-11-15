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

import hashlib
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from . import __version__, recommend, risk
from .cache import TTLCache
from .config import Preferences, Settings, get_settings, load_preferences
from .db import IntegrityError, open_database
from .extract import MAX_APK_BYTES, MAX_FILE_BYTES, ExtractionError, extract, is_apk
from .findings import RawFinding
from .intel import IntelHub
from .intel.resilience import Resilience
from .llm import OllamaExplainer
from .metrics import REGISTRY
from .pii import TYPE_LABELS, RestrictedPII, analyze_pii, ner_available
from .pii.redactor import OffsetMap
from .scam import analyze_text, combine, mitigations
from .scam.analyzer import TextAnalysis
from .scam.indicators import quoted_or_reported
from .scam.normalize import normalize
from .scam.sender import sender_domain
from .scam.types import classify as classify_scam
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
    URLReport,
)
from .storage import ScanStore
from .url import URLAnalyzer, extract_urls
from .url.analyzer import URLAnalysis
from .url.lexical import check as lexical_check
from .url.parse import FoundURL, URLParseError, parse

MAX_MESSAGE_CHARS = 20_000


class InputError(ValueError):
    """The input cannot be analysed (empty, too long, malformed URL, unsupported file)."""


class TooLargeError(InputError):
    """The upload is bigger than the limit for its type."""


class BusyError(RuntimeError):
    """All scan slots are taken and none freed up within the queue timeout. The caller should retry shortly."""

    retry_after = 5


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


def installation_key(data_dir: Path, configured: str | None = None) -> bytes:
    """Secret for value fingerprints: ``VERIOAX_SECRET_KEY`` when set (needed when several servers share one database, so the
    same value gets the same fingerprint everywhere), otherwise ``data_dir/secret.key`` (created on first use, owner-only)."""
    if configured:
        return hashlib.sha256(configured.encode("utf-8")).digest()
    path = Path(data_dir) / "secret.key"

    def read() -> bytes | None:
        try:
            key = path.read_bytes()
            return key if len(key) >= 32 else None
        except OSError:
            return None

    if (key := read()) is not None:
        return key
    key = secrets.token_bytes(32)
    for _ in range(40):
        # O_EXCL: when several workers start together exactly one creates the key and the others read that one
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if (existing := read()) is not None:
                return existing
            time.sleep(0.05)                    # another worker is still writing it
            continue
        except OSError:
            return key                          # read-only data directory: the key lives for this process only
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return key
    return read() or key


def new_scan_id(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"VX-{now:%Y%m%d}-{secrets.token_hex(3).upper()}"


class TrustGuardEngine:
    def __init__(self, settings: Settings | None = None, prefs: Preferences | None = None, *, store: ScanStore | None | bool = None,
                 cache: TTLCache | None = None, hub: IntelHub | None = None, url_analyzer: URLAnalyzer | None = None,
                 llm: OllamaExplainer | None = None):
        self.settings = settings or get_settings()
        self.prefs = prefs or load_preferences(self.settings)
        data_dir = Path(self.settings.data_dir)
        self.cache = cache if cache is not None else TTLCache(data_dir / "cache.sqlite")
        # connection pools, circuit breakers and per-provider limits survive preference changes (which rebuild the hub)
        self.hub = hub or IntelHub(self.settings, self.prefs, self.cache, resilience=Resilience())
        self.urls = url_analyzer or URLAnalyzer(self.settings, self.prefs, self.hub, self.cache)
        if store is False:
            self.store = None
        else:
            self.store = store if isinstance(store, ScanStore) else ScanStore(open_database(self.settings, "history.sqlite"))
        self.llm = llm or OllamaExplainer(self.settings.ollama_url, self.settings.ollama_model)
        self.hash_key = installation_key(data_dir, self.settings.secret_key.get_secret_value() if self.settings.secret_key else None)
        # bounded work: at most N scans at once in this process (and fewer file scans, which parse PDFs, run OCR or open APKs);
        # a request that can't get a slot within the queue timeout is refused with BusyError instead of piling up
        self._slots = threading.BoundedSemaphore(self.settings.max_concurrent_scans)
        self._file_slots = threading.BoundedSemaphore(self.settings.max_concurrent_file_scans)

    @contextmanager
    def _slot(self, kind: str):
        sem = self._file_slots if kind == "file" else self._slots
        REGISTRY.gauge_add("scans_waiting", 1)
        try:
            got = sem.acquire(timeout=self.settings.scan_queue_timeout_s)
        finally:
            REGISTRY.gauge_add("scans_waiting", -1)
        if not got:
            REGISTRY.inc("busy_total", kind=kind)
            raise BusyError("Verioax is busy right now. Please try again in a few seconds.")
        REGISTRY.gauge_add("scans_in_flight", 1)
        t = time.perf_counter()
        try:
            yield
        finally:
            REGISTRY.observe(f"scan.{kind}", time.perf_counter() - t)
            REGISTRY.gauge_add("scans_in_flight", -1)
            sem.release()

    def _replay(self, owner_id: int | None, key: str | None) -> ScanOutcome | None:
        """A retried request (same Idempotency-Key, same account) gets the earlier result instead of a second scan."""
        if not key or self.store is None:
            return None
        prev = self.store.by_idempotency_key(owner_id, key)
        return ScanOutcome(prev, RestrictedData(original_text="")) if prev else None

    def update_preferences(self, prefs: Preferences) -> None:
        self.prefs = prefs
        self.hub = IntelHub(self.settings, prefs, self.cache, resilience=self.hub.res)
        self.urls = URLAnalyzer(self.settings, prefs, self.hub, self.cache)

    # ------------------------------------------------------------------ public entry points
    def scan_message(self, text: str, *, sender: str | None = None, mode: AnalysisMode = AnalysisMode.FULL,
                     source_name: str = "Pasted message", demo: bool = False, owner_id: int | None = None,
                     idempotency_key: str | None = None) -> ScanOutcome:
        if text is None or not text.strip():
            raise InputError("There is no text to analyse. Paste a message first.")
        if len(text) > MAX_MESSAGE_CHARS:
            raise InputError(f"The message is too long ({len(text):,} characters). The limit is {MAX_MESSAGE_CHARS:,}; use the File Scanner for documents.")
        if (prev := self._replay(owner_id, idempotency_key)) is not None:
            return prev
        with self._slot("message"):
            return self._run(text, InputType.MESSAGE, mode, source_name, sender=sender, demo=demo, owner_id=owner_id, idem_key=idempotency_key)

    def scan_url(self, url: str, *, demo: bool = False, owner_id: int | None = None, idempotency_key: str | None = None) -> ScanOutcome:
        url = (url or "").strip()
        if not url:
            raise InputError("Enter a link to check.")
        if len(url) > 2048 or any(c.isspace() for c in url):
            raise InputError("That doesn't look like a single link (it contains spaces or is too long).")
        try:
            parse(url)
        except URLParseError as exc:
            raise InputError(f"That doesn't look like a valid web link: {exc}.") from None
        if (prev := self._replay(owner_id, idempotency_key)) is not None:
            return prev
        with self._slot("url"):
            return self._run(url, InputType.URL, AnalysisMode.FULL, "Submitted link", single_url=url, demo=demo, owner_id=owner_id,
                             idem_key=idempotency_key)

    def scan_file(self, filename: str, data: bytes | BinaryIO, *, mode: AnalysisMode = AnalysisMode.FULL, demo: bool = False,
                  owner_id: int | None = None, idempotency_key: str | None = None) -> ScanOutcome:
        """Scan a document, an image or an Android app. ``data`` may be bytes or a file object (read only once a slot is free)."""
        if (prev := self._replay(owner_id, idempotency_key)) is not None:
            return prev
        with self._slot("file"):
            if not isinstance(data, (bytes, bytearray)):
                data = data.read(MAX_APK_BYTES + 1)
            apk = is_apk(filename, data)
            limit = MAX_APK_BYTES if apk else MAX_FILE_BYTES
            if len(data) > limit:
                raise TooLargeError(f"'{filename}' is too large (limit {limit // (1024 * 1024)} MB for this file type).")
            if apk:
                return self._run_app(filename, bytes(data), owner_id=owner_id, demo=demo, idem_key=idempotency_key)
            try:
                doc = extract(filename, data)
            except ExtractionError as exc:
                raise InputError(f"Couldn't read '{filename}': {exc}.") from None
            if not doc.text.strip():
                raise InputError(f"No readable text was found in '{filename}'. " + " ".join(doc.warnings))
            return self._run(doc.text, InputType.FILE, mode, filename, locate=doc.locate, extraction_warnings=doc.warnings, demo=demo,
                             owner_id=owner_id, idem_key=idempotency_key)

    # ------------------------------------------------------------------ pipeline
    def _run(self, text: str, input_type: InputType, mode: AnalysisMode, source_name: str, *, sender: str | None = None,
             single_url: str | None = None, locate: Callable[[int], str] | None = None, extraction_warnings: list[str] | None = None,
             demo: bool = False, owner_id: int | None = None, idem_key: str | None = None) -> ScanOutcome:
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
            found = [FoundURL(single_url, single_url, 0, len(single_url), True)] if single_url else find_urls(text)
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
            quoted = self._quotes(f, redacted_text, omap)
            evidence += [f"{label}: \u201c{q}\u201d" for label, q in quoted]
            if not ex and quoted:
                ex = " … ".join(q for _, q in quoted[:3])
            findings.append(ScamFinding(id=fid, indicator=f.indicator, category=f.category, title=f.title, severity=f.severity, strength=f.strength,
                                        confidence=round(f.confidence, 2), matched_text=ex[:300], start=f.start, end=f.end, redacted_start=rs,
                                        redacted_end=re_, more_spans=more, explanation=f.explanation, evidence=evidence,
                                        recommended_action=f.action, source=f.source, detected_by=_detected_by(f, analyses)))

        # ---- per-link assessment
        for ua in analyses:
            mine = [f for f in raw if f.url_id == ua.report.url_id and f.indicator != "link"]
            verified = ua.report.visited or any(r.mode in ("live", "cache") and r.status in ("listed", "suspicious", "clean", "not_found")
                                                for r in ua.report.reputation)
            trusted = bool(ua.report.official_entity or ua.report.restricted_registry)
            a = risk.assess(mine, sensitivity=prefs.scam_sensitivity, unverified_link=not (verified or trusted))
            ua.report.final_assessment = a.level
            ua.report.indicator_ids = [id_of[id(f)] for f in mine]
            ua.report.check_status, ua.report.check_note = _check_status(ua.report, prefs.network_checks)
            ua.report.assessment_summary = _url_summary(a.level, mine, ua)

        # ---- overall assessment
        claims = self._claims(ta, redacted_text, omap) if ta else []
        if mode == AnalysisMode.PII:
            level, score, basis, rules, evidence = self._privacy_level(pii_report)
            conf = _pii_confidence(pii_report)
        else:
            # links that a fact-check or warning only quotes ("the post saying 'register at x.com' is fake") are mentioned, not offered
            quoted = quoted_or_reported(text) if ta and ta.debunk else []
            offered = [ua for ua in analyses if not (ua.report.start is not None and any(a <= ua.report.start and ua.report.end <= b for a, b in quoted))]
            unverified = bool(offered) and not any(
                ua.report.visited or ua.report.official_entity or ua.report.restricted_registry
                or any(r.mode in ("live", "cache") and r.status in ("listed", "suspicious", "clean", "not_found") for r in ua.report.reputation)
                for ua in offered)
            a = risk.assess(raw, sensitivity=prefs.scam_sensitivity, mitigation_points=mit_points, unverified_link=unverified)
            level, score, basis, rules, evidence = a.level, a.score, "threat", a.rules, a.evidence
            conf = risk.confidence(raw, level, text_len=len(text), urls_total=len(analyses),
                                   urls_live=sum(ua.report.visited for ua in analyses),
                                   online_intel=any(r.mode in ("live", "cache") for ua in analyses for r in ua.report.reputation),
                                   input_is_url=input_type == InputType.URL)
            if ta:
                rules = rules + [f"pattern: {p}" for p in ta.patterns] + [f"mitigation: {m}" for m, _ in ta.mitigations]

        stype = None
        if basis == "threat":
            keys = {f.indicator for f in raw} | (ta.matched_keys if ta else set())
            keys |= {f"hint:{h}" for ua in analyses for sig, _ in ua.signals for h in sig.hints}
            imitated = [sig.entity for ua in analyses for sig, _ in ua.signals if sig.entity]
            stype = classify_scam(keys, ([e.key for e in ta.claimed] if ta else []) + imitated, level, _top_category(raw),
                                  {f.category for f in raw if f.severity != Severity.INFO})
        title, summary = _verdict(level, basis, raw, ta, pii_report, analyses, stype)
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
            scam_type=stype.key if stype else None, scam_type_label=stype.label if stype else None, scam_type_summary=stype.summary if stype else None,
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

        REGISTRY.inc("scans_total", type=input_type.value, verdict=level.value)
        restricted = RestrictedData(original_text=text, value_map=restricted_pii.value_map if restricted_pii else [],
                                    offset_map=omap, locate=locate)
        return self._store(ScanOutcome(result, restricted), owner_id, idem_key)

    # ------------------------------------------------------------------ Android apps
    def _run_app(self, filename: str, data: bytes, *, owner_id: int | None, demo: bool, idem_key: str | None) -> ScanOutcome:
        """Static analysis of an APK: nothing is installed, executed or uploaded; URLs inside it are listed, never visited."""
        from . import appscan
        from .extract.apk import APKError, APKInfo, analyze_apk
        t0 = time.perf_counter()
        created = datetime.now(timezone.utc)
        prefs = self.prefs
        warnings: list[str] = []
        try:
            info = analyze_apk(data)
        except APKError as exc:
            info = APKInfo(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            info.limitations.append(str(exc))
        claimed = appscan._claimed(info) if info.manifest_ok else None
        raw = appscan.findings(info, claimed) if info.manifest_ok else []
        raw.sort(key=lambda f: (-f.rank()[0], -f.rank()[1], -f.rank()[2]))
        if info.manifest_ok:
            a = risk.assess(raw, sensitivity=prefs.scam_sensitivity)
            level, score, rules, evidence = a.level, a.score, a.rules, a.evidence
        else:
            level, score, rules, evidence = RiskLevel.INCONCLUSIVE, 0, ["inconclusive: the app could not be analysed"], {}
        findings = [ScamFinding(id=f"S{n:03d}", indicator=f.indicator, category=f.category, title=f.title, severity=f.severity, strength=f.strength,
                                confidence=round(f.confidence, 2), matched_text="; ".join(f.evidence[:3])[:300], explanation=f.explanation,
                                evidence=list(f.evidence), recommended_action=f.action, source="file") for n, f in enumerate(raw, start=1)]
        report = appscan.build_report(info, claimed)
        title, summary = _app_verdict(level, report, raw)
        stype = classify_scam({f.indicator for f in raw} | {"apk_install"}, [claimed.key] if claimed else [], level, ScamCategory.MALICIOUS_APP)
        if stype is not None and stype.key not in ("malicious_app", "bank_phishing", "e_challan", "govt_scheme", "kyc_phishing"):
            stype = None
        if stype is None and level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
            from .scam.types import TYPES
            stype = TYPES["malicious_app"]
        if info.limitations:
            warnings += [f"App analysis: {x}" for x in info.limitations]
        id_of = {id(f): s.id for f, s in zip(raw, findings, strict=True)}
        recs = recommend.build(raw, level, [], [claimed.key] if claimed else [], [], id_of, app=True)
        conf = appscan.confidence(info, level.value)
        result = ScanResult(
            scan_id=new_scan_id(created), created_at=created, input_type=InputType.FILE, mode=AnalysisMode.SCAM, source_name=filename,
            language="en", overall_risk=level, risk_basis="threat", risk_score=score, model_confidence=conf, confidence_label=risk.confidence_label(conf),
            verdict_title=title, verdict_summary=summary, scam_type=stype.key if stype else None, scam_type_label=stype.label if stype else None,
            scam_type_summary=stype.summary if stype else None, evidence_summary=evidence,
            scam=ScamReport(findings=findings, categories={ScamCategory.MALICIOUS_APP.value: sum(f.severity != Severity.INFO for f in findings)}),
            app=report, recommended_actions=recs, warnings=warnings, text_length=0,
            review_items=[ReviewItem(kind="extraction", ref="file", reason=x) for x in info.limitations],
            processing=ProcessingMetadata(engine_version=__version__, modules=["app"], network_mode="local", config=prefs.model_dump(),
                                          config_hash=prefs.fingerprint(), rules_applied=rules, timings_ms={"total_ms": _ms(t0)}, demo=demo))
        REGISTRY.inc("scans_total", type="app", verdict=level.value)
        return self._store(ScanOutcome(result, RestrictedData(original_text="")), owner_id, idem_key)

    def _store(self, outcome: ScanOutcome, owner_id: int | None, idem_key: str | None) -> ScanOutcome:
        if self.store is None or not self.prefs.store_history:
            return outcome
        try:
            self.store.save(outcome.result, retention_days=self.prefs.retention_days, owner_id=owner_id, idem_key=idem_key)
        except IntegrityError:                     # the same Idempotency-Key raced in twice: return the stored result
            prev = self.store.by_idempotency_key(owner_id, idem_key) if idem_key else None
            if prev is None:
                raise
            return ScanOutcome(prev, RestrictedData(original_text=""))
        return outcome

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

    @staticmethod
    def _quotes(f: RawFinding, redacted: str | None, omap: OffsetMap | None) -> list[tuple[str, str]]:
        """Message excerpts quoted by a combination finding, taken from the REDACTED text (never the original)."""
        if not f.quotes or redacted is None or omap is None:
            return []
        spans = sorted({(qs, qe, label) for label, qs, qe in f.quotes}, key=lambda x: (x[0], -x[1]))
        kept = [x for x in spans if not any(y is not x and y[0] <= x[0] and x[1] <= y[1] and (y[1] - y[0]) > (x[1] - x[0]) for y in spans)]
        out = []
        for qs, qe, label in kept:
            a, b = omap.to_redacted(qs), omap.to_redacted(qe, end=True)
            if b - a < 25:                      # a very short match ("linked to"): show the rest of its clause for context
                m = re.search(r"[.!?\n]", redacted[b:b + 80])
                b = b + (m.start() if m else min(80, len(redacted) - b))
            snippet = " ".join(redacted[a:b].split())[:160]
            if snippet:
                out.append((label, snippet))
        return out

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


def find_urls(text: str, limit: int = 50) -> list[FoundURL]:
    """Links in the text as written plus links that are only readable once evasion tricks are undone ("nyxwin dot com",
    "c a s h r o y a l e . c o m"). Offsets always refer to the original text."""
    found = extract_urls(text, limit=limit)
    norm = normalize(text)
    if norm.text != text:
        for f in extract_urls(norm.text, limit=limit):
            s0, e0 = norm.span(f.start, f.end)
            if not any(s0 < g.end and g.start < e0 for g in found):
                found.append(FoundURL(text[s0:e0], f.url, s0, e0, f.had_scheme))
    found.sort(key=lambda f: f.start)
    return found[:limit]


def _detected_by(f: RawFinding, analyses: list[URLAnalysis]) -> str:
    if f.source == "page":
        return "live_check"
    if f.source != "intel":
        return "local"
    ua = next((u for u in analyses if u.report.url_id == f.url_id), None)
    modes = {r.mode for r in (ua.report.reputation if ua else []) if r.status in ("listed", "suspicious")}
    return "live_intel" if "live" in modes else "cached_intel" if "cache" in modes else "local_list"


def _check_status(rep: URLReport, live: bool) -> tuple[str, str]:
    """Whether the link was actually checked - so 'nothing found' is never mistaken for 'safe'."""
    online = [r for r in rep.reputation if r.mode in ("live", "cache") and r.status in ("listed", "suspicious", "clean", "not_found")]
    failed = [r.provider for r in rep.reputation if r.status in ("error", "unavailable")]
    src = f" and answered by {len(online)} threat-intelligence source(s)" if online else ""
    note_fail = f" {', '.join(failed)} could not be reached." if failed else ""
    if rep.official_entity or rep.restricted_registry:
        return "checked", "Verified official or restricted-registry domain." + note_fail
    if rep.visited:
        return "checked", "Visited in the guarded backend" + src + "." + note_fail
    if online:
        return "partly_checked", "Checked with threat intelligence only; the page itself was not visited." + note_fail
    if not live:
        return "not_checked", "Not checked live: live checks are off, so only the link's text and the local indicator list were checked." + note_fail
    if rep.visit_note.startswith("Not visited"):
        return "not_visited", rep.visit_note + note_fail
    return "unreachable", ((rep.visit_note or "The site could not be reached.") + " That is not evidence that the site is safe - or that it is malicious."
                           + note_fail)


def _top_category(raw: list[RawFinding]) -> ScamCategory | None:
    cats: dict[ScamCategory, float] = {}
    for f in raw:
        if f.severity != Severity.INFO:
            cats[f.category] = cats.get(f.category, 0.0) + risk.points(f)
    return max(cats, key=cats.get) if cats else None


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
    "crypto_casino_bonus": "a large, instantly withdrawable bonus for signing up on an outside site",
    "cash_giveaway_signup": "an unrealistic cash reward for signing up", "gambling_crypto_promo": "a crypto or gambling bonus promotion",
    "unrealistic_reward": "an unusually large reward for nothing", "reward_offer": "free money or bonus credit", "everyone_reward": "a reward for everyone",
    "registration_reward": "a reward just for registering", "instant_withdrawal": "claims of instant withdrawal", "no_deposit_bonus": "a 'no deposit' bonus",
    "vanishing_post": "a countdown: the post will disappear", "self_launch_claim": "an unverifiable 'I launched my own' announcement",
    "partnership_claim": "an unverified partnership claim", "crypto_send_to_receive": "'send crypto to get more back'",
    "seed_phrase_request": "asks for your wallet recovery phrase", "wallet_connect_lure": "asks you to connect your wallet to claim something",
    "wallet_drainer_link": "a wallet 'claim' on an unknown site", "pump_hype": "pump-and-dump hype", "refund_lure": "an unexpected refund",
    "refund_with_request": "a refund that needs your details", "bank_details_request": "asks for bank details",
    "accidental_transfer": "'money sent by mistake - return it'", "account_alert_lure": "an account security alert",
    "account_warning_callback": "an account warning with a mobile number to call", "tech_support_scare": "a fake virus alert with a number to call",
    "chat_handle": "moves you to a private chat", "external_claim_site": "the reward is claimed on an unverified site",
    "fake_helpline": "a brand's 'customer care' on a personal mobile number", "support_scare_call": "a fake security alert with a number to call",
    "mistaken_transfer_request": "'sent by mistake' with a request to approve", "lottery_mention": "mentions a lottery",
}


def _verdict(level: RiskLevel, basis: str, raw: list[RawFinding], ta: TextAnalysis | None, pii: PIIReport | None,
             analyses: list[URLAnalysis], stype=None) -> tuple[str, str]:
    if basis == "privacy":
        if not pii or not pii.findings:
            return "No personal data found", "No personal data was detected. Detection is not perfect - review before sharing widely."
        drivers = ", ".join(pii.exposure.drivers) or "personal data"
        return (f"Contains sensitive personal data ({pii.exposure.level.lower()} exposure)",
                f"{len(pii.findings)} item(s) found, including {drivers}. Share only the redacted version.")
    meaningful = [f for f in raw if f.severity != Severity.INFO]
    ranked = sorted(meaningful, key=lambda f: risk.points(f), reverse=True)
    top_cat = _top_category(raw)
    hoax = top_cat == ScamCategory.HOAX_MISINFORMATION and (stype is None or stype.key == "hoax")
    label = _lower_first(stype.label) if stype else (CATEGORY_LABELS.get(top_cat, "").lower() if top_cat else "")
    if level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        title = "Likely hoax / misinformation" if hoax else f"Likely scam: {label}"
    elif level == RiskLevel.MEDIUM:
        title = ("Possible hoax: verify before forwarding" if hoax else
                 f"Suspicious: possible {label}" if stype and stype.key != "phishing" else "Suspicious: verify before acting")
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
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL, RiskLevel.MEDIUM) and analyses:
        listed = [ua for ua in analyses if any(r.status == "listed" for r in ua.report.reputation)]
        unverified = [ua for ua in analyses if not listed and ua.report.check_status != "checked"
                      and not (ua.report.official_entity or ua.report.restricted_registry)]
        if listed:
            parts.append("A threat-intelligence source lists the link as malicious.")
        elif unverified and level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            doms = ", ".join(sorted({ua.report.registrable_domain or ua.report.host for ua in unverified if ua.report.host}))
            parts.append(f"The link ({doms}) could not be verified, so this verdict rests on what the message says and asks for - "
                         "not on proof that the site itself is malicious.")
    return title, " ".join(parts)


def _app_verdict(level: RiskLevel, rep, raw: list[RawFinding]) -> tuple[str, str]:
    name = f"'{rep.label}'" if rep.label else "This app"
    if level == RiskLevel.INCONCLUSIVE:
        why = rep.limitations[0] if rep.limitations else "the file could not be read"
        return ("Couldn't analyse this Android app",
                f"The file could not be analysed ({why}). That is not a sign that it is safe: don't install apps that were sent to you.")
    top = [f for f in raw if f.indicator != "apk_sideloaded"][:3]
    signals = "; ".join(f.title[0].lower() + f.title[1:] for f in top)
    claim = f" It presents itself as {rep.claimed_entity}." if rep.claimed_entity else ""
    if level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        return ("Likely malicious app: don't install it", f"{name} has capabilities that match Android banking and OTP-stealing malware.{claim} "
                f"Main signals: {signals}. Found by static analysis only - the app was not run.")
    if level == RiskLevel.MEDIUM:
        return ("Risky app: install only from the Play Store", f"{name} asks for sensitive access.{claim} Main signals: {signals}. "
                "Static analysis can't tell whether the access is misused; an APK received in a message deserves extra caution.")
    return ("No high-risk capabilities found",
            f"Static analysis of {name} found no high-risk combination of permissions or code.{claim} That is not proof the app is safe: "
            "apps from outside the Play Store aren't vetted, and harmful code can be downloaded later.")


def _lower_first(s: str) -> str:
    return s[0].lower() + s[1:] if len(s) > 1 and s[1].islower() else s
