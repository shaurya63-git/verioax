"""Evaluation sets (data/eval).

* The development set (messages.jsonl) is what the rules are tuned against, so its floors guard against regressions;
  they are not a claim about real-world accuracy (see docs/evaluation.md).
* The held-out set (holdout.jsonl) was frozen before the detection changes it measures and is never tuned against.
  The tests only check that it is unchanged and that the evaluator can score it - deliberately no accuracy floors,
  so that nobody (human or tool) is ever pushed to fit the rules to it.
"""
import hashlib

from trustguard.evaluation import SETS, binary, confusion, load, run, summarise

HOLDOUT_SHA256 = "118719f052a01102f16ef5b5db050a60278605be7a05094c44e1235ded128b76"


def test_development_set_floors(settings, prefs):
    r = run(settings, prefs)
    benign_bad = [x for x in r["rows"] if x["label"] == "benign" and x["level"] not in ("LOW", "INCONCLUSIVE")]
    assert r["benign_alarm_rate"] == 0.0, benign_bad
    assert r["benign_high_rate"] == 0.0
    assert r["benign_false_positive_rate"] <= 0.05
    assert r["threat_detection_rate"] >= 0.95, [x for x in r["rows"] if x["label"] == "threat" and not x["ok"]]
    assert r["hoax_flag_rate"] >= 0.9
    assert r["suspicious_flag_rate"] >= 0.5
    assert r["likely_scam"]["precision"] >= 0.95


def test_the_crypto_casino_post_is_a_permanent_regression_case(settings, prefs):
    rows = {x["id"]: x for x in run(settings, prefs)["rows"]}
    assert rows["D001"]["level"] in ("HIGH", "CRITICAL") and rows["D001"]["score"] >= 50
    assert rows["D001"]["scam_type"] == "crypto_casino"


def test_holdout_set_is_frozen():
    # line endings normalised: a Windows checkout with core.autocrlf=true stores the same rows with CRLF
    digest = hashlib.sha256(SETS["holdout"].read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    assert digest == HOLDOUT_SHA256, "the held-out set changed - it must stay frozen (create a new set instead, see docs/evaluation.md)"
    items = load(SETS["holdout"])
    assert len(items) == 133 and len({i["id"] for i in items}) == 133


def test_holdout_set_can_be_scored(settings, prefs):
    r = run(settings, prefs, path=SETS["holdout"])
    assert r["samples"] == 133
    assert set(r["confusion_matrix"]) == {"threat", "hoax", "suspicious", "benign", "neutral"}


def test_metric_definitions():
    from trustguard.evaluation import Row

    def row(label, level):
        return Row(id="x", label=label, category="c", acceptable=["c"], level=level, score=0, confidence=0.5, scam_type=None, verdict="", ok=True)

    rows = [row("threat", "HIGH"), row("threat", "MEDIUM"), row("threat", "LOW"), row("benign", "LOW"), row("benign", "MEDIUM"),
            row("benign", "INCONCLUSIVE")]
    alert = binary(rows, ("threat",), ("benign",), ("MEDIUM", "HIGH", "CRITICAL"))
    assert (alert["tp"], alert["fn"], alert["fp"], alert["tn"]) == (2, 1, 1, 2)
    assert alert["precision"] == round(2 / 3, 3) and alert["recall"] == round(2 / 3, 3) and alert["false_positive_rate"] == 0.333
    cm = confusion(rows)
    assert cm["threat"]["HIGH"] == 1 and cm["benign"]["INCONCLUSIVE"] == 1
    s = summarise(rows)
    assert s["benign_alarm_rate"] == 0.333 and s["benign_inconclusive"] == 1
