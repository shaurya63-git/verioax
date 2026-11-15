"""Labelled evaluation of the detection engine: precision, recall, F1, false-positive rate, confusion matrix and
per-category results.

Two sets live in ``data/eval``:

* ``messages.jsonl`` - the **development set**. Rules are written and tuned against it, so its numbers are a regression
  check (they catch rules that break or start firing on genuine messages), not evidence of real-world accuracy.
* ``holdout.jsonl`` - the **held-out set**. It was written and committed before the detection changes it is used to
  measure, and rules are never tuned against it. It is still synthetic and written by the project, so it is not an
  independent benchmark either: see docs/evaluation.md for what the numbers can and cannot tell you.

Row format (JSON lines)::

    {"id": "H001", "label": "threat", "category": "crypto_casino", "alt_categories": ["crypto_giveaway"],
     "text": "...", "sender": "+91 ..."}          # or "url": "https://..." for a link scanned on its own

Labels: ``threat`` (a scam: expected HIGH or CRITICAL), ``hoax`` (expected MEDIUM+ with a hoax finding),
``suspicious`` (unverifiable phishing-style text: expected anything but LOW), ``benign`` (expected LOW) and
``neutral`` (an unknown but legitimate site: LOW or INCONCLUSIVE).
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .config import Preferences, Settings
from .schemas import RiskLevel, ScamCategory

EVAL_DIR = Path(__file__).resolve().parents[1] / "data" / "eval"
EVAL_FILE = EVAL_DIR / "messages.jsonl"
SETS = {"dev": EVAL_DIR / "messages.jsonl", "holdout": EVAL_DIR / "holdout.jsonl"}
LEVELS = ["LOW", "INCONCLUSIVE", "MEDIUM", "HIGH", "CRITICAL"]
FLAGGED = (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
HIGH_PLUS = (RiskLevel.HIGH, RiskLevel.CRITICAL)
POSITIVE = ("threat", "hoax", "suspicious")
ALIASES = {"generic_phishing": "phishing"}           # dataset category name -> scam type key
NEGATIVE = ("benign", "neutral")


@dataclass
class Row:
    id: str
    label: str
    category: str
    acceptable: list[str]
    level: str
    score: int
    confidence: float
    scam_type: str | None
    verdict: str
    ok: bool
    note: str = ""
    extra: dict = field(default_factory=dict)


def load(path: Path = EVAL_FILE) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def expected_ok(label: str, level: RiskLevel, hoax_finding: bool) -> bool:
    if label == "threat":
        return level in HIGH_PLUS
    if label == "hoax":
        return level in FLAGGED and hoax_finding
    if label == "suspicious":
        return level != RiskLevel.LOW
    if label == "neutral":                      # "not verified" is fine for an unknown site, a warning is not
        return level in (RiskLevel.LOW, RiskLevel.INCONCLUSIVE)
    return level == RiskLevel.LOW


def _engine(settings: Settings | None, prefs: Preferences | None):
    import tempfile

    from .engine import TrustGuardEngine

    base = prefs or Preferences()
    # offline and without history, so the evaluation is reproducible and never touches the user's scan history
    p = base.model_copy(update={"network_checks": False, "intel_lookups": False, "factcheck_lookups": False, "openphish_feed": False,
                                "llm_explanations": False, "store_history": False})
    s = settings or Settings(_env_file=None, data_dir=Path(tempfile.mkdtemp(prefix="vx-eval-")))
    return TrustGuardEngine(s, p, store=False)


def score_items(items: list[dict], settings: Settings | None = None, prefs: Preferences | None = None) -> list[Row]:
    eng = _engine(settings, prefs)
    rows: list[Row] = []
    for item in items:
        if "url" in item:                       # a link scanned on its own
            r = eng.scan_url(item["url"]).result
        else:
            r = eng.scan_message(item["text"], sender=item.get("sender")).result
        cats = {f.category for f in r.scam_findings if f.severity.value != "info"}
        lab = item["label"]
        category = item.get("category") or "uncategorised"
        acceptable = [ALIASES.get(c, c) for c in [category] + list(item.get("alt_categories", []))]
        rows.append(Row(id=item["id"], label=lab, category=category, acceptable=acceptable,
                        level=r.overall_risk.value, score=r.risk_score, confidence=r.model_confidence,
                        scam_type=getattr(r, "scam_type", None), verdict=r.verdict_title,
                        ok=expected_ok(lab, r.overall_risk, ScamCategory.HOAX_MISINFORMATION in cats), note=item.get("note", "")))
    return rows


# ------------------------------------------------------------------------------------------------ metrics
def binary(rows: list[Row], positives: tuple[str, ...], negatives: tuple[str, ...], flagged: tuple) -> dict:
    """Precision / recall / F1 / false-positive rate for one operating point."""
    lv = {getattr(x, "value", x) for x in flagged}
    tp = sum(r.label in positives and r.level in lv for r in rows)
    fn = sum(r.label in positives and r.level not in lv for r in rows)
    fp = sum(r.label in negatives and r.level in lv for r in rows)
    tn = sum(r.label in negatives and r.level not in lv for r in rows)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if prec is not None and rec is not None else None)
    fpr = fp / (fp + tn) if fp + tn else None
    rnd = lambda v: None if v is None else round(v, 3)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": rnd(prec), "recall": rnd(rec), "f1": rnd(f1), "false_positive_rate": rnd(fpr)}


def confusion(rows: list[Row]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for lab in POSITIVE + NEGATIVE:
        sub = [r for r in rows if r.label == lab]
        if sub:
            c = Counter(r.level for r in sub)
            out[lab] = {lv: c.get(lv, 0) for lv in LEVELS}
    return out


def per_category(rows: list[Row]) -> dict[str, dict]:
    """Per true category: how many met their expectation (recall for scam categories, 1 - false alarms for genuine ones)
    and, for detected scams, how often the reported scam type was an acceptable one."""
    groups: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        groups[r.category].append(r)
    out: dict[str, dict] = {}
    for cat, sub in sorted(groups.items()):
        label = Counter(r.label for r in sub).most_common(1)[0][0]
        ok = sum(r.ok for r in sub)
        d = {"label": label, "n": len(sub), "as_expected": ok, "rate": round(ok / len(sub), 3)}
        detected = [r for r in sub if r.label in ("threat", "hoax") and r.ok]
        if detected and any(r.scam_type is not None for r in rows):
            d["type_correct"] = sum(r.scam_type in r.acceptable for r in detected)
            d["type_accuracy"] = round(d["type_correct"] / len(detected), 3)
        out[cat] = d
    return out


def per_type_precision(rows: list[Row]) -> dict[str, dict]:
    """Per reported scam type (HIGH+ verdicts, plus hoax verdicts at MEDIUM+): how many were of that type."""
    out: dict[str, dict] = {}
    for r in rows:
        if r.scam_type is None:
            continue
        flagged = r.level in ("HIGH", "CRITICAL") or (r.scam_type == "hoax" and r.level == "MEDIUM")
        if not flagged:
            continue
        d = out.setdefault(r.scam_type, {"predicted": 0, "correct": 0})
        d["predicted"] += 1
        d["correct"] += int(r.label in POSITIVE and r.scam_type in r.acceptable)
    for d in out.values():
        d["precision"] = round(d["correct"] / d["predicted"], 3)
    return dict(sorted(out.items()))


def summarise(rows: list[Row]) -> dict:
    def rate(label: str) -> float | None:
        sub = [x for x in rows if x.label == label]
        return round(sum(x.ok for x in sub) / len(sub), 3) if sub else None

    benign = [x for x in rows if x.label == "benign"]
    neutral = [x for x in rows if x.label == "neutral"]
    return {
        "samples": len(rows),
        "labels": dict(Counter(r.label for r in rows)),
        "threat_detection_rate": rate("threat"),          # threats rated HIGH or CRITICAL
        "hoax_flag_rate": rate("hoax"),                   # hoaxes rated MEDIUM+ with a hoax indicator
        "suspicious_flag_rate": rate("suspicious"),       # unverifiable / generic phishing not rated LOW
        "benign_false_positive_rate": round(sum(not x.ok for x in benign) / len(benign), 3) if benign else None,
        # strict: anything but LOW counts. alarm: an actual warning (MEDIUM or worse). INCONCLUSIVE means "a link in it could not be
        # verified" - offline, every unknown link is unverifiable - so it is reported separately and not counted as an alarm.
        "benign_alarm_rate": round(sum(x.level in ("MEDIUM", "HIGH", "CRITICAL") for x in benign) / len(benign), 3) if benign else None,
        "benign_inconclusive": sum(x.level == "INCONCLUSIVE" for x in benign),
        "benign_high_rate": round(sum(x.level in ("HIGH", "CRITICAL") for x in benign) / len(benign), 3) if benign else None,
        "neutral_false_alarm_rate": round(sum(not x.ok for x in neutral) / len(neutral), 3) if neutral else None,
        # operating point 1: any warning (MEDIUM, HIGH, CRITICAL) on scams, hoaxes and suspicious items
        "alert": binary(rows, POSITIVE, NEGATIVE, FLAGGED),
        # operating point 2: "likely scam" verdicts (HIGH, CRITICAL) on scams only
        "likely_scam": binary(rows, ("threat",), NEGATIVE, HIGH_PLUS),
        "confusion_matrix": confusion(rows),
        "per_category": per_category(rows),
        "per_type_precision": per_type_precision(rows),
        "missed": [{"id": r.id, "category": r.category, "level": r.level, "score": r.score} for r in rows
                   if r.label in POSITIVE and not r.ok],
        "false_alarms": [{"id": r.id, "category": r.category, "level": r.level, "score": r.score} for r in rows
                         if r.label in NEGATIVE and not r.ok],
    }


def run(settings: Settings | None = None, prefs: Preferences | None = None, path: Path = EVAL_FILE) -> dict:
    rows = score_items(load(path), settings, prefs)
    res = summarise(rows)
    res["rows"] = [asdict(r) for r in rows]
    res["set"] = path.name
    res["note"] = ("Development set: rules are tuned against it - a regression check, not a benchmark." if path.name == "messages.jsonl"
                   else "Held-out set: never used for tuning, but synthetic and written by the project - see docs/evaluation.md.")
    return res


def _print(res: dict, aggregate_only: bool, verbose: bool) -> None:
    print(f"== {res['set']}: {res['samples']} samples {res['labels']}")
    if not aggregate_only:
        for row in res["rows"]:
            if verbose or not row["ok"]:
                print(f"  {'ok  ' if row['ok'] else 'MISS'} {row['id']:<5} {row['label']:<10} {row['category']:<18} {row['level']:<12} "
                      f"{row['score']:>3}  {row['scam_type'] or '-':<16} {row['verdict']}")
    for k in ("threat_detection_rate", "hoax_flag_rate", "suspicious_flag_rate", "benign_false_positive_rate", "benign_alarm_rate",
              "benign_inconclusive", "benign_high_rate", "neutral_false_alarm_rate"):
        print(f"  {k}: {res[k]}")
    for op in ("alert", "likely_scam"):
        m = res[op]
        print(f"  {op:<12} precision={m['precision']} recall={m['recall']} f1={m['f1']} fpr={m['false_positive_rate']} "
              f"(tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']})")
    print("  confusion matrix (rows = label, columns = verdict): " + " / ".join(LEVELS))
    for lab, cnt in res["confusion_matrix"].items():
        print(f"    {lab:<10} " + "  ".join(f"{cnt[lv]:>4}" for lv in LEVELS))
    print("  per category: n, as expected, rate" + (", type accuracy" if any("type_accuracy" in d for d in res["per_category"].values()) else ""))
    for cat, d in res["per_category"].items():
        print(f"    {cat:<20} {d['label']:<10} {d['n']:>3} {d['as_expected']:>3} {d['rate']:>6}" + (f"  {d['type_accuracy']}" if "type_accuracy" in d else ""))
    if res["per_type_precision"]:
        print("  per reported scam type: predicted, correct, precision")
        for t, d in res["per_type_precision"].items():
            print(f"    {t:<20} {d['predicted']:>3} {d['correct']:>3} {d['precision']:>6}")
    print("  " + res["note"])


def main(argv: list[str] | None = None) -> int:
    """``python -m trustguard.evaluation [--set dev|holdout|all] [--json out.json]`` - exit code 1 on regression (dev set)."""
    import argparse

    ap = argparse.ArgumentParser(description="Run the labelled evaluation sets offline.")
    ap.add_argument("--set", choices=("dev", "holdout", "all"), default="dev")
    ap.add_argument("--min-detection", type=float, default=0.9, help="minimum threat detection rate on the dev set (default 0.9)")
    ap.add_argument("--max-fp", type=float, default=0.1, help="maximum share of genuine dev messages rated MEDIUM or worse (default 0.1)")
    ap.add_argument("--verbose", action="store_true", help="list every sample, not just the misses")
    ap.add_argument("--aggregate-only", action="store_true", help="print only the totals (use for the held-out set while developing)")
    ap.add_argument("--json", type=Path, help="also write the full results as JSON")
    args = ap.parse_args(argv)
    names = ["dev", "holdout"] if args.set == "all" else [args.set]
    results = {}
    for name in names:
        res = run(path=SETS[name])
        results[name] = res
        _print(res, args.aggregate_only, args.verbose)
    if args.json:
        hidden = ("rows", "missed", "false_alarms")          # per-sample detail stays out of aggregate-only output
        payload = {k: ({kk: vv for kk, vv in v.items() if kk not in hidden} if args.aggregate_only else v) for k, v in results.items()}
        args.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    dev = results.get("dev")
    if dev:
        failed = (dev["threat_detection_rate"] or 0) < args.min_detection or (dev["benign_alarm_rate"] or 0) > args.max_fp
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
