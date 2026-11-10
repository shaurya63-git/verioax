"""Regression evaluation on the labelled message set in ``data/eval/messages.jsonl``.

Be clear about what this measures: the set was written alongside the rules (synthetic messages modelled on public
advisories), so it is a *regression check* - it catches rules that break or start firing on genuine messages - and not
an independent accuracy benchmark. Report it that way.
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import Preferences, Settings
from .schemas import RiskLevel, ScamCategory

EVAL_FILE = Path(__file__).resolve().parents[1] / "data" / "eval" / "messages.jsonl"
FLAGGED = (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)


def load(path: Path = EVAL_FILE) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run(settings: Settings | None = None, prefs: Preferences | None = None, path: Path = EVAL_FILE) -> dict:
    import tempfile

    from .engine import TrustGuardEngine

    base = prefs or Preferences()
    # offline and without history, so the evaluation is reproducible and does not pollute the user's scan history
    p = base.model_copy(update={"network_checks": False, "intel_lookups": False, "factcheck_lookups": False, "openphish_feed": False,
                                "llm_explanations": False, "store_history": False})
    s = settings or Settings(_env_file=None, data_dir=Path(tempfile.mkdtemp(prefix="tg-eval-")))
    eng = TrustGuardEngine(s, p, store=False)
    rows = []
    for item in load(path):
        if "url" in item:                       # a link scanned on its own
            r = eng.scan_url(item["url"]).result
        else:
            r = eng.scan_message(item["text"], sender=item.get("sender")).result
        cats = {f.category for f in r.scam_findings if f.severity.value != "info"}
        lab = item["label"]
        if lab == "threat":
            ok = r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        elif lab == "hoax":
            ok = r.overall_risk in FLAGGED and ScamCategory.HOAX_MISINFORMATION in cats
        elif lab == "suspicious":
            ok = r.overall_risk != RiskLevel.LOW
        elif lab == "neutral":                  # an unknown but legitimate site: "not verified" is fine, a warning is not
            ok = r.overall_risk in (RiskLevel.LOW, RiskLevel.INCONCLUSIVE)
        else:
            ok = r.overall_risk == RiskLevel.LOW
        rows.append({"id": item["id"], "label": lab, "level": r.overall_risk.value, "score": r.risk_score, "ok": ok,
                     "verdict": r.verdict_title, "note": item.get("note", "")})

    def rate(label: str) -> float | None:
        sub = [x for x in rows if x["label"] == label]
        return round(sum(x["ok"] for x in sub) / len(sub), 3) if sub else None

    benign = [x for x in rows if x["label"] == "benign"]
    neutral = [x for x in rows if x["label"] == "neutral"]
    return {
        "samples": len(rows),
        "threat_detection_rate": rate("threat"),          # threats rated HIGH or CRITICAL
        "hoax_flag_rate": rate("hoax"),                   # hoaxes rated MEDIUM+ with a hoax indicator
        "suspicious_flag_rate": rate("suspicious"),       # unverifiable / generic phishing not rated LOW
        "benign_false_positive_rate": round(sum(not x["ok"] for x in benign) / len(benign), 3) if benign else None,
        "neutral_false_alarm_rate": round(sum(not x["ok"] for x in neutral) / len(neutral), 3) if neutral else None,
        "rows": rows,
        "note": "Regression set written alongside the rules - not an independent benchmark.",
    }


def main(argv: list[str] | None = None) -> int:
    """``python -m trustguard.evaluation [--min-detection 0.9] [--max-fp 0.1]`` - prints the rates; exit code 1 on regression."""
    import argparse

    ap = argparse.ArgumentParser(description="Run the labelled regression set offline.")
    ap.add_argument("--min-detection", type=float, default=0.9, help="minimum threat detection rate (default 0.9)")
    ap.add_argument("--max-fp", type=float, default=0.1, help="maximum benign false-positive rate (default 0.1)")
    ap.add_argument("--verbose", action="store_true", help="list every sample")
    args = ap.parse_args(argv)
    res = run()
    for row in res["rows"]:
        if args.verbose or not row["ok"]:
            print(f"{'ok  ' if row['ok'] else 'MISS'} {row['id']:<4} {row['label']:<10} {row['level']:<12} {row['score']:>3}  {row['verdict']}")
    print(f"samples: {res['samples']}")
    for k in ("threat_detection_rate", "hoax_flag_rate", "suspicious_flag_rate", "benign_false_positive_rate", "neutral_false_alarm_rate"):
        print(f"{k}: {res[k]}")
    print(res["note"])
    failed = (res["threat_detection_rate"] or 0) < args.min_detection or (res["benign_false_positive_rate"] or 0) > args.max_fp
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
