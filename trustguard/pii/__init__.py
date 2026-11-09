"""Engine 1: PII detection and redaction.

``analyze_pii(text)`` returns the audit-safe ``PIIReport`` and a ``RestrictedPII`` bundle. Only the bundle contains raw
values (the placeholder map); callers must keep it out of logs, reports and storage.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from ..schemas import LeakSweep, PIIFinding, PIIReport, PlaceholderSummary, PrivacyExposure
from .detector import PRIORITY, TYPE_LABELS, Detection, detect
from .names import ner_available
from .redactor import OffsetMap, Redaction, redact, value_hash

__all__ = ["analyze_pii", "RestrictedPII", "TYPE_LABELS", "PRIORITY", "ner_available", "OffsetMap"]

# Sensitivity of each type for the privacy-exposure score (documented in docs/scoring.md).
EXPOSURE_WEIGHT = {
    "CREDENTIAL": 45, "CARD_NUMBER": 35, "NATIONAL_ID": 30, "BANK_ACCOUNT": 25, "PASSPORT": 25, "TAX_ID": 20,
    "DRIVING_LICENCE": 20, "VOTER_ID": 18, "UPI_ID": 15, "DOB": 12, "ADDRESS": 10, "PHONE": 10, "EMAIL": 8,
    "VEHICLE_REG": 8, "PERSON": 5,
}
HIGH_EXPOSURE = {"CARD_NUMBER", "NATIONAL_ID", "BANK_ACCOUNT", "PASSPORT"}


def band(conf: float) -> str:
    return "high" if conf >= 0.85 else "medium" if conf >= 0.65 else "low"


@dataclass
class RestrictedPII:
    """Raw values. Hold in memory only; the UI shows them behind an explicit confirmation."""
    value_map: list[dict]
    offset_map: OffsetMap


def exposure(types: Counter) -> PrivacyExposure:
    if not types:
        return PrivacyExposure(level="NONE", score=0)
    score = 0.0
    for t, n in types.items():
        score += EXPOSURE_WEIGHT.get(t, 5) * (1 + 0.15 * (n - 1))
    score = min(100, round(score))
    if "CREDENTIAL" in types:
        level = "CRITICAL"
    elif HIGH_EXPOSURE & set(types) or score >= 60:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
    ranked = sorted(types, key=lambda t: -EXPOSURE_WEIGHT.get(t, 5))
    return PrivacyExposure(level=level, score=score, drivers=[TYPE_LABELS.get(t, t).lower() for t in ranked[:4]])


def analyze_pii(text: str, *, min_confidence: float = 0.5, review_threshold: float = 0.65, sweep_rounds: int = 2,
                use_ner: bool = True, locate: Callable[[int], str] | None = None,
                extraction_warnings: list[str] | None = None, hash_key: bytes | None = None) -> tuple[PIIReport, Redaction, RestrictedPII]:
    locate = locate or (lambda pos: f"line {text.count(chr(10), 0, pos) + 1}")
    dets: list[Detection] = detect(text, min_confidence=min_confidence, use_ner=use_ner)
    red = redact(text, dets, min_confidence=min_confidence, sweep_rounds=sweep_rounds, use_ner=use_ner)

    findings: list[PIIFinding] = []
    order = sorted(range(len(red.detections)), key=lambda i: (red.detections[i].start, red.detections[i].end))
    for n, i in enumerate(order, start=1):
        d, origin, ph = red.detections[i], red.origins[i], red.placeholders[i]
        review = d.confidence < review_threshold or "checksum_failed" in d.flags
        findings.append(PIIFinding(
            id=f"P{n:03d}", entity_type=d.type, placeholder=ph, confidence=d.confidence, band=band(d.confidence),
            start=d.start, end=d.end, location=locate(d.start), detectors=d.detectors, value_hash=value_hash(d.type, d.text, hash_key),
            length=len(d.text), redacted=True, needs_review=review, origin=origin, flags=d.flags,
        ))

    by_type = Counter(f.entity_type for f in findings)
    reasons: list[str] = []
    status = "clean"
    if red.residual:
        status = "blocked"
        reasons.append(f"{red.residual} item(s) still readable after {sweep_rounds} sweep round(s): {', '.join(red.residual_types)}")
    else:
        reasons += [f"extraction warning: {w}" for w in (extraction_warnings or [])]
        low = [f for f in findings if f.needs_review]
        if low:
            reasons.append(f"{len(low)} finding(s) below confidence {review_threshold:.2f} or with a failed checksum")
        if reasons:
            status = "needs_review"

    placeholders = [PlaceholderSummary(placeholder=e["placeholder"], entity_type=e["type"], occurrences=e["occurrences"])
                    for e in red.registry.value_map()]
    replaced = sum(1 for f in findings if f.placeholder and f.placeholder in red.redacted_text)
    report = PIIReport(
        findings=findings, status=status, status_reasons=reasons,
        by_type=dict(sorted(by_type.items(), key=lambda kv: (PRIORITY.index(kv[0]) if kv[0] in PRIORITY else 99))),
        distinct_values=len(placeholders), placeholders=placeholders,
        leak_sweep=LeakSweep(rounds=red.sweep_rounds, caught=red.caught_by_sweep, residual=red.residual, passed=red.residual == 0),
        exposure=exposure(by_type),
        redaction_coverage=round(replaced / len(findings), 3) if findings else 1.0,
    )
    return report, red, RestrictedPII(value_map=red.registry.value_map(), offset_map=red.offset_map)
