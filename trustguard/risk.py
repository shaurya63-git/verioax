"""Risk aggregation: findings -> one deterministic, documented score (see docs/scoring.md).

Risk score (0-100) answers "how dangerous does this look?". Model confidence (0-1) answers "how much evidence did we
actually have?". They are computed separately and shown separately.

Scoring:
1. Each finding is worth   SEVERITY_POINTS[severity] x STRENGTH_FACTOR[strength] x confidence.
2. Within one category the k-th strongest finding counts 1, 1/2, 1/4 ... (ten urgency words are not ten times as bad).
3. Mitigations (e.g. every link is a verified official domain) subtract points - only when there is no strong or
   confirmed high-severity finding.
4. score = round(100 x (1 - e^(-raw/45)))  - saturates smoothly, so 0-100 never overflows.
5. Level thresholds depend on the sensitivity preference (balanced: 25 / 50 / 75).
6. Rules on top of the score:
   * floor: a CONFIRMED critical finding -> CRITICAL; a CONFIRMED high or STRONG critical finding -> at least HIGH;
   * ceiling: with only WEAK findings the level can be at most MEDIUM;
   * INCONCLUSIVE: the message hinges on a link that could not be verified and nothing else raised the level.
   When a rule moves the level, the score is moved to the edge of that level, so score and level never disagree.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from .findings import RawFinding
from .schemas import RiskLevel, Severity, Strength

SEVERITY_POINTS = {Severity.INFO: 0.0, Severity.LOW: 6.0, Severity.MEDIUM: 14.0, Severity.HIGH: 28.0, Severity.CRITICAL: 45.0}
STRENGTH_FACTOR = {Strength.WEAK: 0.5, Strength.STRONG: 1.0, Strength.CONFIRMED: 1.4}
THRESHOLDS = {"conservative": (30, 55, 80), "balanced": (25, 50, 75), "aggressive": (20, 45, 70)}
SCALE = 45.0
ORDER = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


@dataclass
class Assessment:
    level: RiskLevel
    score: int
    raw_points: float
    rules: list[str] = field(default_factory=list)
    evidence: dict[str, int] = field(default_factory=dict)


def points(f: RawFinding) -> float:
    return SEVERITY_POINTS[f.severity] * STRENGTH_FACTOR[f.strength] * f.confidence


def _level_for(score: int, thr: tuple[int, int, int]) -> RiskLevel:
    medium, high, critical = thr
    if score >= critical:
        return RiskLevel.CRITICAL
    if score >= high:
        return RiskLevel.HIGH
    if score >= medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _floor_score(level: RiskLevel, thr: tuple[int, int, int]) -> int:
    return {RiskLevel.LOW: 0, RiskLevel.MEDIUM: thr[0], RiskLevel.HIGH: thr[1], RiskLevel.CRITICAL: thr[2]}[level]


def assess(findings: list[RawFinding], *, sensitivity: str = "balanced", mitigation_points: float = 0.0,
           unverified_link: bool = False) -> Assessment:
    thr = THRESHOLDS.get(sensitivity, THRESHOLDS["balanced"])
    rules: list[str] = []
    by_cat: dict[str, list[float]] = defaultdict(list)
    for f in findings:
        by_cat[f.category.value].append(points(f))
    raw = 0.0
    for pts in by_cat.values():
        for i, p in enumerate(sorted(pts, reverse=True)):
            raw += p / (2 ** i)

    strong_high = any(f.strength in (Strength.STRONG, Strength.CONFIRMED) and f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    if mitigation_points and not strong_high:
        raw = max(0.0, raw - mitigation_points)
        rules.append(f"mitigation: -{mitigation_points:g} points")

    score = round(100 * (1 - math.exp(-raw / SCALE)))
    level = _level_for(score, thr)

    confirmed_crit = any(f.strength == Strength.CONFIRMED and f.severity == Severity.CRITICAL for f in findings)
    confirmed_high = any(f.strength == Strength.CONFIRMED and f.severity == Severity.HIGH for f in findings)
    strong_crit = any(f.strength == Strength.STRONG and f.severity == Severity.CRITICAL for f in findings)
    only_weak = findings and all(f.strength == Strength.WEAK for f in findings)

    def raise_to(target: RiskLevel, why: str) -> None:
        nonlocal level, score
        if ORDER.index(level) < ORDER.index(target):
            level, score = target, max(score, _floor_score(target, thr))
            rules.append(why)

    if confirmed_crit:
        raise_to(RiskLevel.CRITICAL, "floor: confirmed critical indicator -> CRITICAL")
    elif confirmed_high or strong_crit:
        raise_to(RiskLevel.HIGH, "floor: confirmed high / strong critical indicator -> at least HIGH")
    if only_weak and ORDER.index(level) > ORDER.index(RiskLevel.MEDIUM):
        level, score = RiskLevel.MEDIUM, min(score, thr[1] - 1)
        rules.append("ceiling: only weak indicators -> at most MEDIUM")
    if unverified_link and level == RiskLevel.LOW:
        level = RiskLevel.INCONCLUSIVE
        rules.append("inconclusive: the link could not be verified and nothing else decides the case")

    evidence = {s.value: sum(f.strength == s for f in findings if f.severity != Severity.INFO) for s in Strength}
    return Assessment(level, int(score), round(raw, 2), rules, evidence)


def confidence(findings: list[RawFinding], level: RiskLevel, *, text_len: int, urls_total: int, urls_live: int,
               online_intel: bool, input_is_url: bool = False) -> float:
    """How much evidence the verdict rests on - independent of the score (docs/scoring.md, 'Confidence')."""
    meaningful = [f for f in findings if f.severity != Severity.INFO]
    if level == RiskLevel.INCONCLUSIVE:
        return 0.3
    if not meaningful:
        c = 0.55 + (0.1 if urls_total and urls_live == urls_total else 0.0) + (0.05 if online_intel else 0.0)
        c -= 0.1 if (text_len < 40 and not input_is_url) else 0.0
        return round(min(c, 0.75), 2)                  # absence of evidence is never high confidence
    families = {f.source for f in meaningful if f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)}
    c = 0.5 + 0.08 * min(len(families), 3)
    if any(f.strength == Strength.CONFIRMED for f in meaningful):
        c += 0.15
    elif any(f.strength == Strength.STRONG for f in meaningful):
        c += 0.07
    if urls_total:
        c += 0.08 * (urls_live / urls_total)
        if urls_live == 0:
            c -= 0.1
    if text_len < 40 and not input_is_url:
        c -= 0.1
    return round(max(0.2, min(c, 0.97)), 2)


def confidence_label(c: float) -> str:
    return "High" if c >= 0.75 else "Medium" if c >= 0.5 else "Low"
