from trustguard import risk
from trustguard.findings import RawFinding
from trustguard.schemas import RiskLevel
from trustguard.schemas import ScamCategory as C
from trustguard.schemas import Severity as SV
from trustguard.schemas import Strength as ST


def f(sev, strength, cat=C.SOCIAL_ENGINEERING, conf=0.9, source="message"):
    return RawFinding("x", cat, "t", sev, strength, conf, "e", source=source)


def test_only_weak_findings_cap_at_medium():
    many = [f(SV.HIGH, ST.WEAK, cat=c) for c in list(C)[:8]]
    a = risk.assess(many)
    assert a.level == RiskLevel.MEDIUM and a.score < 50 and any("ceiling" in r for r in a.rules)


def test_confirmed_critical_is_critical():
    a = risk.assess([f(SV.CRITICAL, ST.CONFIRMED, conf=0.6)])
    assert a.level == RiskLevel.CRITICAL and a.score >= 75


def test_strong_critical_floors_at_high():
    a = risk.assess([f(SV.CRITICAL, ST.STRONG, conf=0.5)])
    assert a.level == RiskLevel.HIGH and 50 <= a.score < 75


def test_diminishing_returns_within_category():
    one = risk.assess([f(SV.MEDIUM, ST.STRONG)]).raw_points
    three = risk.assess([f(SV.MEDIUM, ST.STRONG)] * 3).raw_points
    assert three < 2 * one


def test_mitigation_never_overrides_strong_high():
    strong = [f(SV.HIGH, ST.STRONG)]
    assert risk.assess(strong, mitigation_points=30).raw_points == risk.assess(strong).raw_points
    weak = [f(SV.MEDIUM, ST.WEAK)]
    assert risk.assess(weak, mitigation_points=30).raw_points == 0


def test_inconclusive_only_when_nothing_else_decides():
    assert risk.assess([], unverified_link=True).level == RiskLevel.INCONCLUSIVE
    assert risk.assess([f(SV.CRITICAL, ST.STRONG)], unverified_link=True).level == RiskLevel.HIGH


def test_sensitivity_thresholds():
    fs = [f(SV.MEDIUM, ST.STRONG, conf=0.9), f(SV.LOW, ST.WEAK, cat=C.PHISHING)]
    assert risk.assess(fs, sensitivity="aggressive").level == RiskLevel.MEDIUM
    assert risk.assess(fs, sensitivity="conservative").level == RiskLevel.LOW


def test_confidence_is_separate_from_score():
    findings = [f(SV.CRITICAL, ST.CONFIRMED, source="intel"), f(SV.HIGH, ST.STRONG, source="message")]
    hi = risk.confidence(findings, RiskLevel.CRITICAL, text_len=200, urls_total=1, urls_live=1, online_intel=True)
    lo = risk.confidence([], RiskLevel.LOW, text_len=20, urls_total=0, urls_live=0, online_intel=False)
    assert hi > 0.8 and lo <= 0.75 and risk.confidence_label(lo) in ("Low", "Medium")
