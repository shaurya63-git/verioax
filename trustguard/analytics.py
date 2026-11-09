"""Aggregate statistics over the scan history for the dashboard and the Reports & Analytics page."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .pii import TYPE_LABELS
from .schemas import CATEGORY_LABELS, RiskLevel, ScamCategory, ScanResult, Severity

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INCONCLUSIVE"]
CONF_BINS = [(0.0, 0.5, "Low (<0.50)"), (0.5, 0.75, "Medium (0.50-0.74)"), (0.75, 1.01, "High (≥0.75)")]


def summarize(results: list[ScanResult]) -> dict[str, Any]:
    risk = Counter(r.overall_risk.value for r in results)
    threat = [r for r in results if r.risk_basis == "threat"]
    cats: Counter = Counter()
    indicators: Counter = Counter()
    pii_types: Counter = Counter()
    url_levels: Counter = Counter()
    conf: Counter = Counter()
    sweep = {"caught": 0, "residual": 0, "blocked_scans": 0, "scans_with_pii": 0}
    coverage: list[float] = []
    review: list[dict] = []
    per_day: Counter = Counter()
    for r in results:
        per_day[r.created_at.astimezone(timezone.utc).date().isoformat()] += 1
        for lo, hi, label in CONF_BINS:
            if lo <= r.model_confidence < hi:
                conf[label] += 1
        for f in r.scam_findings:
            if f.severity != Severity.INFO:
                cats[f.category.value] += 1
                indicators[f.title] += 1
        if r.pii:
            for t, n in r.pii.by_type.items():
                pii_types[t] += n
            if r.pii.findings:
                sweep["scans_with_pii"] += 1
                coverage.append(r.pii.redaction_coverage)
            sweep["caught"] += r.pii.leak_sweep.caught
            sweep["residual"] += r.pii.leak_sweep.residual
            sweep["blocked_scans"] += r.pii.status == "blocked"
        for u in r.urls:
            url_levels[u.final_assessment.value] += 1
        for item in r.review_items:
            review.append({"scan_id": r.scan_id, "date": r.created_at.isoformat(timespec="minutes"), "kind": item.kind, "ref": item.ref,
                           "reason": item.reason})
    high = sum(r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) for r in threat)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "totals": {
            "scans": len(results),
            "suspicious_messages": sum(r.input_type.value != "url" and r.overall_risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL) for r in threat),
            "potential_scams": sum(r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
                                   and any(f.category != ScamCategory.HOAX_MISINFORMATION and f.severity != Severity.INFO for f in r.scam_findings) for r in threat),
            "suspicious_urls": sum(url_levels[k] for k in ("MEDIUM", "HIGH", "CRITICAL")),
            "pii_findings": sum(len(r.pii_findings) for r in results),
            "high_risk": high,
            "demo_scans": sum(r.processing.demo for r in results),
        },
        "risk_distribution": {k: risk.get(k, 0) for k in RISK_ORDER},
        "categories": {CATEGORY_LABELS[ScamCategory(k)]: v for k, v in cats.most_common()},
        "top_indicators": dict(indicators.most_common(10)),
        "pii_types": {TYPE_LABELS.get(k, k): v for k, v in pii_types.most_common()},
        "confidence_distribution": {label: conf.get(label, 0) for _, _, label in CONF_BINS},
        "url_assessments": {k: url_levels.get(k, 0) for k in RISK_ORDER},
        "leak_sweep": sweep,
        "redaction_coverage": round(sum(coverage) / len(coverage), 3) if coverage else None,
        "review_queue": review[:200],
        "scans_per_day": dict(sorted(per_day.items())),
    }
