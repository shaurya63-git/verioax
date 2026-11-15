"""Report exporters: JSON, CSV, Markdown and PDF - per scan and for the whole history.

Everything here is built from ``ScanResult`` objects, which contain no raw PII by construction (placeholders, hashes,
redacted excerpts, defanged links). ``tests/test_reports.py`` checks every format against the raw values of a scan.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from ..pii import TYPE_LABELS
from ..schemas import CATEGORY_LABELS, ScanResult, Severity

DISCLAIMER = ("Verioax gives an automated assessment based on the evidence listed. A low score is not a guarantee of safety; "
              "verify important messages through official channels.")


# ----------------------------------------------------------------------------------------------- per scan
def to_json(r: ScanResult) -> str:
    return r.model_dump_json(indent=2)


def findings_csv(r: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["scan_id", "kind", "id", "type_or_category", "title", "severity", "strength", "confidence", "location_or_source",
                "placeholder", "value_hash", "excerpt_redacted", "needs_review"])
    for f in r.pii_findings:
        w.writerow([r.scan_id, "pii", f.id, f.entity_type, TYPE_LABELS.get(f.entity_type, f.entity_type), "", "", f.confidence, f.location,
                    f.placeholder, f.value_hash, "", f.needs_review])
    for f in r.scam_findings:
        w.writerow([r.scan_id, "threat", f.id, f.category.value, f.title, f.severity.value, f.strength.value, f.confidence, f.source,
                    "", "", f.matched_text, ""])
    for u in r.urls:
        for c in u.checks:
            w.writerow([r.scan_id, "url_check", u.url_id, c.key, f"{c.label}: {c.summary}", "", "", "", c.source, "", "", u.defanged, ""])
    return buf.getvalue()


STRENGTH_LABEL = {"confirmed": "Confirmed indicator", "strong": "Strong pattern", "weak": "Weak signal"}
DETECTED_BY_LABEL = {"local": "Verioax rules (on this device/server)", "live_check": "Live check of the page", "live_intel": "Threat intelligence (live)",
                     "cached_intel": "Threat intelligence (cached)", "local_list": "Verioax indicator list"}
CHECK_STATUS_LABEL = {"checked": "checked", "partly_checked": "partly checked (threat intelligence only)", "not_checked": "not checked live",
                      "not_visited": "not visited", "unreachable": "could not be reached"}


def to_markdown(r: ScanResult) -> str:
    L: list[str] = [f"# Verioax report - {r.scan_id}", "",
                    f"**{r.overall_risk.value} RISK** ({'privacy exposure' if r.risk_basis == 'privacy' else 'threat'} score {r.risk_score}/100, "
                    f"confidence {r.confidence_label.lower()} {r.model_confidence:.2f})", "",
                    f"**{r.verdict_title}** - {r.verdict_summary}", ""]
    if r.scam_type_label:
        L += [f"**Scam type:** {r.scam_type_label} - {r.scam_type_summary or ''}", ""]
    L += [f"- Scanned: {r.created_at:%Y-%m-%d %H:%M} UTC - input: {r.input_type.value} ({r.source_name}) - mode: {r.mode.value}",
                    f"- Modules: {', '.join(r.processing.modules)} - network mode: {r.processing.network_mode} - engine {r.processing.engine_version} "
                    f"- config {r.processing.config_hash}" + (" - DEMO DATA" if r.processing.demo else ""), ""]
    if r.recommended_actions:
        L += ["## Recommended actions", ""] + [f"{i}. **{a.title}** - {a.detail}" for i, a in enumerate(r.recommended_actions, 1)] + [""]
    sf = [f for f in r.scam_findings if f.severity != Severity.INFO]
    if sf:
        L += ["## Threat findings", "", "Confirmed = a malicious indicator confirmed by a source; strong / weak = a suspicious pattern, not proof.", "",
              "| ID | Category | Finding | Severity | Strength | Detected by | Conf. | Evidence (redacted) |", "|---|---|---|---|---|---|---|---|"]
        L += [f"| {f.id} | {CATEGORY_LABELS[f.category]} | {f.title} | {f.severity.value} | {STRENGTH_LABEL[f.strength.value]} | "
              f"{DETECTED_BY_LABEL.get(f.detected_by, f.detected_by)} | {f.confidence:.2f} | {_md(f.matched_text)} |" for f in sf]
        L += [""]
        ctx = [f for f in r.scam_findings if f.severity == Severity.INFO]
        if ctx:
            L += ["Context noted (not counted in the score): " + "; ".join(f.title for f in ctx), ""]
    for u in r.urls:
        L += [f"## Link {u.url_id}: `{u.defanged}`", "", f"Assessment: **{u.final_assessment.value}** - {u.assessment_summary}", "",
              f"Link check: **{CHECK_STATUS_LABEL.get(u.check_status, u.check_status)}** - {u.check_note}", "",
              "| Check | Status | Result |", "|---|---|---|"]
        L += [f"| {c.label} | {c.status} | {_md(c.summary)} |" for c in u.checks] + [""]
        if u.visit_note:
            L += [f"_{u.visit_note}_", ""]
    if r.app is not None:
        L += app_markdown(r.app)
    if r.scam and r.scam.claims:
        L += ["## Claims that need verification", ""] + [f"- \"{_md(c.text)}\" - {c.how_to_verify}" +
                                                         ("".join(f" [{x.publisher}: {x.rating}]({x.url})" for x in c.fact_checks)) for c in r.scam.claims] + [""]
    if r.pii:
        p = r.pii
        L += ["## Personal data (PII)", "", f"Redaction status: **{p.status}**" + (f" - {'; '.join(p.status_reasons)}" if p.status_reasons else ""),
              f"Privacy exposure: **{p.exposure.level}** ({p.exposure.score}/100). Leak sweep: {p.leak_sweep.caught} extra item(s) caught, "
              f"{p.leak_sweep.residual} residual.", ""]
        if p.findings:
            L += ["| ID | Type | Placeholder | Confidence | Location | Review |", "|---|---|---|---|---|---|"]
            L += [f"| {f.id} | {TYPE_LABELS.get(f.entity_type, f.entity_type)} | `{f.placeholder}` | {f.confidence:.2f} | {f.location} | "
                  f"{'yes' if f.needs_review else ''} |" for f in p.findings] + [""]
    if r.redacted_text:
        L += ["## Redacted content", "", "```", r.redacted_text[:6000], "```", ""]
    if r.warnings:
        L += ["## Processing notes", ""] + [f"- {w}" for w in r.warnings] + [""]
    L += ["---", "No raw personal data appears in this report; values are replaced by placeholders and hashes.", "", f"_{DISCLAIMER}_"]
    return "\n".join(L)


def app_facts(a) -> list[list[str]]:
    certs = "; ".join(f"{c.source}: {c.subject}" + (" (Android test key)" if c.test_key else " (debug certificate)" if c.debug else "")
                      for c in a.certificates[:3]) or "none found (unsigned)"
    return [["App name", a.label or "-"], ["Package", a.package or "-"], ["Version", f"{a.version_name or '-'} ({a.version_code or '-'})"],
            ["Android versions", f"min API {a.min_sdk or '-'}, target API {a.target_sdk or '-'}"],
            ["Size / SHA-256", f"{a.size_bytes:,} bytes / {a.sha256}"], ["Presents itself as", a.claimed_entity or "-"],
            ["Signing", f"{', '.join(a.signature_schemes) or 'no signature scheme found'}; certificates: {certs}. "
                        "Certificates were read, not cryptographically verified."],
            ["Components", ", ".join(f"{v} {k}" for k, v in a.component_counts.items()) or "-"],
            ["Native libraries / packers", f"{', '.join(a.native_libs[:8]) or 'none'} / {', '.join(a.packers) or 'none'}"]]


def app_markdown(a) -> list[str]:
    L = ["## Android app (static analysis)", "", "Nothing was installed or run, and links found inside the app were not visited.", "",
         "| Field | Value |", "|---|---|"] + [f"| {k} | {_md(v)} |" for k, v in app_facts(a)] + [""]
    if a.permissions:
        L += ["### Permissions", "", "| Permission | Risk | What it allows |", "|---|---|---|"]
        L += [f"| {x.short} | {x.risk} | {_md(x.meaning)} |" for x in a.permissions] + [""]
    comps = [c for c in a.components if c.exported or c.role]
    if comps:
        L += ["### Notable components", "", "| Kind | Name | Exported | Role |", "|---|---|---|---|"]
        L += [f"| {c.kind} | `{_md(c.name)}` | {'yes' if c.exported else 'no'} | {_md(c.role)} |" for c in comps[:30]] + [""]
    for title, items in (("Capabilities seen in the code", a.capabilities), ("Links inside the app (defanged, not visited)", a.urls),
                         ("Domains", a.domains), ("Embedded code", a.embedded_code), ("Archive problems", a.archive_issues),
                         ("Limits of this analysis", a.limitations)):
        if items:
            L += [f"### {title}", ""] + [f"- `{x}`" if title.startswith(("Links", "Domains")) else f"- {x}" for x in items] + [""]
    return L


def _md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")[:160]


# ----------------------------------------------------------------------------------------------- PDF
def _font() -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    for regular, bold in (("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
                          ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
                          ("/Library/Fonts/Arial Unicode.ttf", "/Library/Fonts/Arial Unicode.ttf")):
        if Path(regular).exists() and Path(bold).exists():
            try:
                pdfmetrics.registerFont(TTFont("TG", regular))
                pdfmetrics.registerFont(TTFont("TG-Bold", bold))
                return "TG", "TG-Bold"
            except Exception:
                continue
    return "Helvetica", "Helvetica-Bold"


def _safe(text: str, unicode_font: bool) -> str:
    from xml.sax.saxutils import escape
    t = escape(text or "")
    if not unicode_font:
        t = t.replace("₹", "Rs.").encode("latin-1", "replace").decode("latin-1")
    return t


_LEVEL_COLORS = {"LOW": "#1f9d62", "MEDIUM": "#c98a14", "HIGH": "#d4541c", "CRITICAL": "#c0262d", "INCONCLUSIVE": "#6b7685"}


def to_pdf(r: ScanResult) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    reg, bold = _font()
    uni = reg != "Helvetica"
    S = lambda size=9, b=False, color="#1d2433", lead=None: ParagraphStyle("s", fontName=bold if b else reg, fontSize=size,  # noqa: E731
                                                                            leading=lead or size * 1.35, textColor=colors.HexColor(color))
    P = lambda t, **k: Paragraph(_safe(t, uni), S(**k))  # noqa: E731
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title=f"Verioax report {r.scan_id}", author="Verioax")
    col = _LEVEL_COLORS.get(r.overall_risk.value, "#6b7685")
    story: list[Any] = [P("Verioax - security report", size=15, b=True),
                        P(f"{r.scan_id} · {r.created_at:%Y-%m-%d %H:%M} UTC · {r.input_type.value} · modules: {', '.join(r.processing.modules)}"
                          + (" · DEMO DATA" if r.processing.demo else ""), size=8, color="#5b6576"), Spacer(1, 6)]
    banner = Table([[P(f"{r.overall_risk.value} RISK", size=13, b=True, color="#ffffff"),
                     P(f"Score {r.risk_score}/100 · confidence {r.confidence_label} ({r.model_confidence:.2f})", size=9, color="#ffffff")],
                    [P(r.verdict_title, size=10, b=True, color="#ffffff"), ""]], colWidths=[70 * mm, None])
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(col)), ("SPAN", (0, 1), (1, 1)),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story += [banner, Spacer(1, 5), P(r.verdict_summary, size=9)]
    if r.scam_type_label:
        story += [Spacer(1, 3), Paragraph(f"<b>Scam type:</b> {_safe(r.scam_type_label, uni)} - {_safe(r.scam_type_summary or '', uni)}", S(size=8.5))]
    story += [Spacer(1, 8)]

    def table(head, rows, widths):
        data = [[P(h, size=8, b=True) for h in head]] + [[P(str(c), size=8) for c in row] for row in rows]
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf5")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c9d1de")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        return t

    if r.recommended_actions:
        story += [P("Recommended actions", size=11, b=True), Spacer(1, 3)]
        story += [Paragraph(f"{i}. <b>{_safe(a.title, uni)}</b> - {_safe(a.detail, uni)}", S(size=9)) for i, a in enumerate(r.recommended_actions, 1)]
        story += [Spacer(1, 8)]
    sf = [f for f in r.scam_findings if f.severity != Severity.INFO]
    if sf:
        story += [P("Threat findings", size=11, b=True), Spacer(1, 3),
                  table(["ID", "Finding", "Category", "Severity / strength / source", "Evidence (redacted)"],
                        [[f.id, f.title, CATEGORY_LABELS[f.category],
                          f"{f.severity.value} / {STRENGTH_LABEL[f.strength.value].lower()} / {DETECTED_BY_LABEL.get(f.detected_by, f.detected_by).lower()}",
                          f.matched_text[:90]] for f in sf], [12 * mm, 48 * mm, 28 * mm, 38 * mm, None]),
                  P("Confirmed = a malicious indicator confirmed by a source; strong / weak = a suspicious pattern, not proof.", size=7.5, color="#5b6576"),
                  Spacer(1, 8)]
    for u in r.urls:
        story += [P(f"Link {u.url_id}: {u.defanged}", size=10, b=True), P(f"{u.final_assessment.value} - {u.assessment_summary}", size=8.5),
                  P(f"Link check: {CHECK_STATUS_LABEL.get(u.check_status, u.check_status)} - {u.check_note}", size=8, color="#5b6576"),
                  Spacer(1, 3), table(["Check", "Status", "Result"], [[c.label, c.status, c.summary] for c in u.checks], [40 * mm, 20 * mm, None]),
                  Spacer(1, 8)]
    if r.app is not None:
        a = r.app
        story += [P("Android app (static analysis - nothing was installed or run)", size=11, b=True), Spacer(1, 3),
                  table(["Field", "Value"], app_facts(a), [42 * mm, None]), Spacer(1, 4)]
        if a.permissions:
            story += [table(["Permission", "Risk", "What it allows"], [[x.short, x.risk, x.meaning] for x in a.permissions[:40]],
                            [48 * mm, 16 * mm, None]), Spacer(1, 4)]
        for title, items in (("Capabilities seen in the code", a.capabilities), ("Links inside the app (defanged, not visited)", a.urls[:15]),
                             ("Archive problems", a.archive_issues), ("Limits of this analysis", a.limitations)):
            if items:
                story += [P(title, size=9, b=True)] + [P(f"- {x}", size=8) for x in items] + [Spacer(1, 3)]
        story += [Spacer(1, 6)]
    if r.pii:
        p = r.pii
        story += [P("Personal data (PII)", size=11, b=True),
                  P(f"Redaction status: {p.status}. Privacy exposure {p.exposure.level} ({p.exposure.score}/100). Leak sweep caught {p.leak_sweep.caught}, "
                    f"residual {p.leak_sweep.residual}.", size=9), Spacer(1, 3)]
        if p.findings:
            story += [table(["ID", "Type", "Placeholder", "Conf.", "Location"],
                            [[f.id, TYPE_LABELS.get(f.entity_type, f.entity_type), f.placeholder, f"{f.confidence:.2f}", f.location] for f in p.findings],
                            [14 * mm, 40 * mm, 40 * mm, 16 * mm, None])]
        story += [Spacer(1, 8)]
    if r.redacted_text:
        story += [P("Redacted content", size=11, b=True), P(r.redacted_text[:3000], size=8, color="#333c4d"), Spacer(1, 8)]
    story += [P("No raw personal data appears in this report. " + DISCLAIMER, size=7.5, color="#5b6576")]
    doc.build(story)
    return buf.getvalue()


# ----------------------------------------------------------------------------------------------- history / analytics
def history_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    cols = ["scan_id", "created_at", "input_type", "mode", "overall_risk", "risk_score", "confidence", "pii_count", "scam_count",
            "url_count", "suspicious_urls", "categories", "status", "demo", "verdict"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({**r, "categories": ";".join(r.get("categories", []))})
    return buf.getvalue()


def analytics_markdown(summary: dict) -> str:
    t = summary["totals"]
    L = ["# Verioax - analytics report", "", f"Generated {summary['generated_at']} over {t['scans']} scan(s)"
         + (f" ({t['demo_scans']} demo)" if t["demo_scans"] else "") + ".", "",
         "| Metric | Value |", "|---|---|"] + [f"| {k.replace('_', ' ')} | {v} |" for k, v in t.items()] + [""]
    for title, key in (("Risk distribution", "risk_distribution"), ("Detection categories", "categories"), ("PII types", "pii_types"),
                       ("Confidence", "confidence_distribution"), ("Link assessments", "url_assessments"), ("Top indicators", "top_indicators")):
        data = summary.get(key) or {}
        if data:
            L += [f"## {title}", "", "| | Count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in data.items()] + [""]
    sw = summary["leak_sweep"]
    L += ["## Redaction", "", f"Average redaction coverage: {summary['redaction_coverage']}. Leak sweep caught {sw['caught']} item(s); "
          f"{sw['residual']} residual; {sw['blocked_scans']} scan(s) blocked.", ""]
    if summary["review_queue"]:
        L += ["## Human review queue", "", "| Scan | Kind | Ref | Reason |", "|---|---|---|---|"]
        L += [f"| {x['scan_id']} | {x['kind']} | {x['ref']} | {_md(x['reason'])} |" for x in summary["review_queue"][:100]]
    return "\n".join(L)


def analytics_json(summary: dict) -> str:
    return json.dumps(summary, indent=2, default=str)


def analytics_pdf(summary: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    reg, bold = _font()
    uni = reg != "Helvetica"
    st = lambda size=9, b=False: ParagraphStyle("s", fontName=bold if b else reg, fontSize=size, leading=size * 1.35)  # noqa: E731
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title="Verioax analytics report")
    t = summary["totals"]
    story: list[Any] = [Paragraph("Verioax - analytics report", st(15, True)),
                        Paragraph(_safe(f"Generated {summary['generated_at']} · {t['scans']} scan(s)", uni), st(8)), Spacer(1, 8)]

    def block(title: str, data: dict):
        if not data:
            return []
        rows = [[Paragraph(_safe(str(k), uni), st(8)), Paragraph(str(v), st(8))] for k, v in data.items()]
        tb = Table([[Paragraph("Item", st(8, True)), Paragraph("Count", st(8, True))]] + rows, colWidths=[110 * mm, 30 * mm])
        tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf5")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c9d1de"))]))
        return [Paragraph(title, st(11, True)), Spacer(1, 3), tb, Spacer(1, 8)]

    story += block("Totals", {k.replace("_", " "): v for k, v in t.items()})
    for title, key in (("Risk distribution", "risk_distribution"), ("Detection categories", "categories"), ("PII types", "pii_types"),
                       ("Confidence", "confidence_distribution"), ("Link assessments", "url_assessments")):
        story += block(title, summary.get(key) or {})
    sw = summary["leak_sweep"]
    story += [Paragraph(_safe(f"Redaction coverage {summary['redaction_coverage']}; leak sweep caught {sw['caught']}, residual {sw['residual']}, "
                              f"blocked scans {sw['blocked_scans']}.", uni), st(9)), Spacer(1, 6),
              Paragraph(_safe("No raw personal data appears in this report. " + DISCLAIMER, uni), st(7.5))]
    doc.build(story)
    return buf.getvalue()
