"""Regression floors on the labelled message set (data/eval/messages.jsonl).

The set was written alongside the rules, so these numbers guard against regressions; they are not a claim about
real-world accuracy (see README, 'Known limitations')."""
from trustguard.evaluation import run


def test_regression_floors(settings, prefs):
    r = run(settings, prefs)
    assert r["benign_false_positive_rate"] == 0.0, [x for x in r["rows"] if x["label"] == "benign" and not x["ok"]]
    assert r["threat_detection_rate"] >= 0.9, [x for x in r["rows"] if x["label"] == "threat" and not x["ok"]]
    assert r["hoax_flag_rate"] >= 0.8
    assert r["suspicious_flag_rate"] >= 0.5
