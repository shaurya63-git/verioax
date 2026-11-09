"""The unified security report - one renderer for every scan (message, link, file, and scans reopened from history)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

import ui
from trustguard.pii import TYPE_LABELS
from trustguard.schemas import CATEGORY_LABELS, ScanResult

STRENGTH_WORD = {"confirmed": "Confirmed", "strong": "Strong signal", "weak": "Weak signal"}
SOURCE_WORD = {"message": "message text", "sender": "sender", "url": "link (static check)", "page": "link (live check)",
               "intel": "threat intelligence", "combination": "combination of signals", "file": "file"}


def render(r: ScanResult, original: str | None, *, key: str, client=None) -> None:
    st.html(ui.verdict_panel(r))
    if r.warnings:
        with st.expander(f"Processing notes ({len(r.warnings)})", icon=":material/info:"):
            for w in r.warnings:
                st.markdown(f"- {w}")

    left, right = st.columns([1.35, 1], gap="large")
    with left:
        st.subheader("What to do")
        st.html(ui.actions_list(r.recommended_actions))
        if r.ai_explanation:
            st.caption("Plain-language summary from the local AI model (it explains the findings; it does not decide the verdict):")
            st.info(r.ai_explanation)
    with right:
        st.subheader("Overview")
        c = r.counts()
        tiles = [("Scam signals", c["scam_indicators"]), ("Link signals", c["url_indicators"]), ("Personal data", c["pii_findings"]),
                 ("Critical", c["critical_warnings"]), ("Claims to check", c["claims"]), ("For review", c["review_items"])]
        for row in (tiles[:3], tiles[3:]):
            cols = st.columns(3)
            for col, (label, value) in zip(cols, row, strict=True):
                col.metric(label, value, border=True)

    is_link_scan = r.input_type.value == "url"
    tabs: list[tuple[str, object]] = []
    if is_link_scan:                                                 # the link report is the main content of a link scan
        tabs.append(("Link report", lambda: _links(r)))
    if r.scam is not None and not is_link_scan:
        tabs.append(("What we found", lambda: _findings(r, original, key)))
    if r.urls and not is_link_scan:
        tabs.append((f"Links ({len(r.urls)})", lambda: _links(r)))
    if r.pii is not None:
        tabs.append((f"Personal data ({len(r.pii.findings)})", lambda: _pii(r, original, key)))
    if r.redacted_text is not None or original:
        tabs.append(("Original vs redacted", lambda: _compare(r, original, key)))
    tabs.append(("Report", lambda: _report(r, key, client)))
    for tab, (_, fn) in zip(st.tabs([name for name, _ in tabs], key=f"{key}_tabs"), tabs, strict=True):
        with tab:
            fn()


# ---------------------------------------------------------------------------------------------- findings
def _threat_spans(r: ScanResult, redacted: bool):
    spans = []
    for f in r.scam_findings:
        for sp in [f, *f.more_spans]:                                # a repeated phrase is one finding with several places
            s, e = (sp.redacted_start, sp.redacted_end) if redacted else (sp.start, sp.end)
            if s is not None and e is not None:
                spans.append((s, e, f.id, f.severity.value, f.title))
    return spans


def _pii_spans(r: ScanResult):
    return [(f.start, f.end, f.placeholder, TYPE_LABELS.get(f.entity_type, f.entity_type)) for f in (r.pii.findings if r.pii else [])]


def _findings(r: ScanResult, original: str | None, key: str) -> None:
    findings = [f for f in r.scam_findings if f.severity.value != "info"]
    if original:
        st.markdown("**The message, with the parts that raised concern highlighted**")
        st.html(ui.highlight(original, _threat_spans(r, False), _pii_spans(r)))
        st.html(ui.legend(include_pii=bool(r.pii)))
        st.caption("This view shows your original text, including any personal data. It is kept in this browser session only and is never stored.")
    elif r.redacted_text:
        st.markdown("**The message (redacted), with the parts that raised concern highlighted**")
        st.html(ui.highlight(r.redacted_text, _threat_spans(r, True), mark_placeholders=True))
        st.html(ui.legend(include_pii=False))
    if not findings:
        st.success("No scam or hoax indicators were found in the text. That is not a guarantee that it is genuine.", icon=":material/check_circle:")
    else:
        st.markdown(f"**Findings ({len(findings)})** - open one to see why it was flagged")
        for f in findings:
            label = (f"{ui.sev_badge_md(f.severity.value)} :{'red' if f.strength.value == 'confirmed' else 'gray'}-badge[{STRENGTH_WORD[f.strength.value]}] "
                     f"**{f.id}** {f.title}")
            with st.expander(label):
                st.markdown(f.explanation)
                a, b, c = st.columns(3)
                a.markdown(f"**Category**  \n{CATEGORY_LABELS[f.category]}")
                b.markdown(f"**Confidence**  \n{f.confidence:.0%}")
                c.markdown(f"**Found in**  \n{SOURCE_WORD.get(f.source, f.source)}")
                if f.matched_text:
                    st.markdown("**Evidence**")
                    st.code(f.matched_text, language=None, wrap_lines=True)
                extra = [e for e in f.evidence if e != f.matched_text]
                if extra:
                    st.markdown("\n".join(f"- {e}" for e in extra))
                if f.recommended_action:
                    st.markdown(f"**What to do:** {f.recommended_action}")
    if r.scam and r.scam.sender:
        s = r.scam.sender
        st.markdown("**Sender**")
        kind = {"dlt_header": "Registered business SMS header", "mobile_number": "Personal mobile number", "foreign_number": "International number",
                "email": "Email address", "short_code": "Short code", "unknown": "Unrecognised format"}[s.kind]
        st.markdown(f"`{s.raw}` - {kind}" + (f" ({s.category} category)" if s.category else ""))
        for n in s.notes[1:]:
            st.caption(n)
    if r.scam and r.scam.mitigations:
        st.markdown("**Signals that point to a genuine message**")
        st.markdown("\n".join(f"- {m}" for m in r.scam.mitigations))
    if r.scam and r.scam.claims:
        st.markdown("**Claims to check before you act or forward**")
        for c in r.scam.claims:
            with st.container(border=True):
                st.markdown(f"> {c.text or '(claim text not stored)'}")
                st.markdown(f"**How to verify:** {c.how_to_verify}")
                if c.verification_status == "related_fact_checks_found":
                    st.markdown("Related fact-checks (they may cover a similar, not identical, claim):")
                    for x in c.fact_checks:
                        st.markdown(f"- [{x.publisher}: {x.rating or 'rated'}]({x.url}) {x.title}")
                elif c.verification_status == "no_fact_checks_found":
                    st.caption("No published fact-check matched this claim. That does not make it true or false.")
                else:
                    st.caption("Not independently verified - Verioax does not judge whether a claim is true from its wording alone.")


# ---------------------------------------------------------------------------------------------- links
def _links(r: ScanResult) -> None:
    for u in r.urls:
        with st.container(border=True):
            lvl = u.final_assessment.value
            st.html(f"<div style='display:flex;flex-wrap:wrap;gap:.5rem 1rem;align-items:center;justify-content:space-between'>"
                    f"<div class='tg-url'>{ui.esc(u.defanged)}</div>{ui.pill(ui.LEVEL_WORD[lvl], ui.STATUS[lvl])}</div>"
                    f"<div class='tg-note' style='margin-top:.35rem'>{ui.esc(u.assessment_summary)}</div>")
            meta = []
            if u.registrable_domain:
                meta.append(f"Domain **{u.registrable_domain}**")
            if u.official_entity:
                meta.append(f"verified owner **{u.official_entity}**")
            elif u.restricted_registry:
                meta.append(f"restricted registry **.{u.restricted_registry}**")
            if meta:
                st.markdown(", ".join(meta))
            st.html(ui.checks_table(u.checks))
            if u.redirect_chain and len(u.redirect_chain) > 1:
                st.markdown("**Redirect chain** (each hop was checked before it was requested)")
                st.html("<ol class='tg-chain'>" + "".join(f"<li><span class='tg-url'>{ui.esc(h.url)}</span>"
                                                            f"{' (' + str(h.status_code) + ')' if h.status_code else ''}{' - ' + ui.esc(h.note) if h.note else ''}</li>"
                                                            for h in u.redirect_chain) + "</ol>")
            if u.reputation:
                with st.expander("Threat-intelligence sources"):
                    mode_word = {"live": "Live API", "cache": "Cached", "local": "Local list", "none": "-"}
                    st.dataframe(pd.DataFrame([{"Source": x.provider, "Result": x.status.replace("_", " "), "How": mode_word.get(x.mode, x.mode),
                                                "Details": x.verdict} for x in u.reputation]), hide_index=True, width="stretch")
                    attributions = sorted({x.attribution for x in u.reputation if x.attribution and x.status in ("listed", "suspicious")})
                    for a in attributions:
                        st.caption(a)
            if u.page and u.page.fetched and (u.page.title or u.page.sensitive_fields):
                st.caption(f"Page title: {u.page.title or '-'}; sensitive fields on the page: {', '.join(u.page.sensitive_fields) or 'none'}")
            st.caption(u.visit_note or "")
    st.caption("Links are shown defanged (hxxps, [.]) so they cannot be opened by accident. Verioax never opens them in your browser; "
               "live checks run in the backend's guarded fetcher.")


# ---------------------------------------------------------------------------------------------- personal data
def _pii(r: ScanResult, original: str | None, key: str) -> None:
    p = r.pii
    status_word = {"clean": ("Redaction complete", "green"), "needs_review": ("Redaction needs a quick review", "orange"),
                   "blocked": ("Personal data may still be readable", "red")}[p.status]
    st.markdown(f":{status_word[1]}-badge[{status_word[0]}] :{ui.BADGE.get(p.exposure.level, 'gray')}-badge[Privacy exposure: {p.exposure.level.lower()}]")
    for reason in p.status_reasons:
        st.caption(reason)
    if not p.findings:
        st.success("No personal data was detected. Detection is not perfect - review before sharing widely.", icon=":material/check_circle:")
        return
    a, b, c, d = st.columns(4)
    a.metric("Items found", len(p.findings), border=True)
    b.metric("Distinct values", p.distinct_values, border=True)
    c.metric("Caught by leak sweep", p.leak_sweep.caught, border=True)
    d.metric("Still readable", p.leak_sweep.residual, border=True)
    if original:
        st.markdown("**Where it is**")
        st.html(ui.highlight(original, [], _pii_spans(r)))
    df = pd.DataFrame([{"ID": f.id, "Type": TYPE_LABELS.get(f.entity_type, f.entity_type), "Placeholder": f.placeholder, "Confidence": f.confidence,
                        "Location": f.location, "Detected by": ", ".join(f.detectors), "Found by": "leak sweep" if f.origin == "leak_sweep" else "detector",
                        "Review": "yes" if f.needs_review else ""} for f in p.findings])
    st.dataframe(df, hide_index=True, width="stretch",
                 column_config={"Confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="%.2f")})
    st.caption(f"Leak sweep: the redacted output was re-scanned {max(0, len(p.leak_sweep.rounds) - 1) or 'once'} "
               f"{'time(s)' if len(p.leak_sweep.rounds) > 1 else ''} with the detectors and with every removed value written in other formats.")
    if original:
        with st.expander("Restricted: placeholder to original value", icon=":material/lock:"):
            st.warning("This shows the personal data in clear text. It exists only in this browser session and is never written to the scan history or reports.")
            if st.checkbox("I understand - show the values", key=f"{key}_reveal"):
                rows = {}
                for f in p.findings:
                    rows.setdefault(f.placeholder, {"Placeholder": f.placeholder, "Type": TYPE_LABELS.get(f.entity_type, f.entity_type), "Values": set()})
                    rows[f.placeholder]["Values"].add(original[f.start:f.end])
                st.dataframe(pd.DataFrame([{**v, "Values": ", ".join(sorted(v["Values"]))} for v in rows.values()]), hide_index=True, width="stretch")


# ---------------------------------------------------------------------------------------------- compare
def _compare(r: ScanResult, original: str | None, key: str) -> None:
    view = st.segmented_control("Show", ["Side by side", "Original", "Highlighted analysis", "Redacted output"], default="Side by side",
                                key=f"{key}_view", label_visibility="collapsed") or "Side by side"
    red_html = ui.highlight(r.redacted_text, _threat_spans(r, True), mark_placeholders=True, mono=True) if r.redacted_text else None
    orig_note = "Contains the original text, including personal data. Session only."
    if view == "Side by side":
        a, b = st.columns(2, gap="medium")
        with a:
            st.markdown("**Original**")
            if original:
                st.html(ui.highlight(original, [], [], mono=True))
                st.caption(orig_note)
            else:
                st.info("The original text is not stored. Only the redacted version is kept in the history.")
        with b:
            st.markdown("**Redacted** (scam warnings stay marked)")
            if red_html:
                st.html(red_html)
    elif view == "Original":
        if original:
            st.warning(orig_note)
            st.html(ui.highlight(original, [], [], mono=True))
        else:
            st.info("The original text is not stored. Only the redacted version is kept in the history.")
    elif view == "Highlighted analysis":
        if original:
            st.html(ui.highlight(original, _threat_spans(r, False), _pii_spans(r), mono=True))
        elif red_html:
            st.html(red_html)
        st.html(ui.legend(include_pii=bool(original and r.pii)))
    else:
        if red_html:
            st.html(red_html)
    if r.redacted_text:
        st.markdown("**Copy or download the redacted text**")
        st.code(r.redacted_text, language=None, wrap_lines=True)
        st.download_button("Download redacted text", r.redacted_text.encode("utf-8"), file_name=f"{r.scan_id}-redacted.txt",
                           mime="text/plain", key=f"{key}_dl_red", on_click="ignore", icon=":material/download:")


# ---------------------------------------------------------------------------------------------- report
def _report(r: ScanResult, key: str, client) -> None:
    from trustguard import reports
    st.markdown("**Download this report** - no raw personal data is included in any format.")
    cols = st.columns(4)
    files = [("PDF", "pdf", "application/pdf", lambda: reports.to_pdf(r)), ("Markdown", "md", "text/markdown", lambda: reports.to_markdown(r).encode()),
             ("JSON", "json", "application/json", lambda: reports.to_json(r).encode()), ("CSV findings", "csv", "text/csv", lambda: reports.findings_csv(r).encode())]
    for col, (label, ext, mime, fn) in zip(cols, files, strict=True):
        col.download_button(label, fn(), file_name=f"verioax-{r.scan_id}.{ext}", mime=mime, key=f"{key}_dl_{ext}", on_click="ignore",
                            icon=":material/download:", width="stretch")
    st.markdown("**Technical details**")
    p = r.processing
    st.dataframe(pd.DataFrame([
        {"Field": "Scan ID", "Value": r.scan_id}, {"Field": "Created (UTC)", "Value": f"{r.created_at:%Y-%m-%d %H:%M:%S}"},
        {"Field": "Input", "Value": f"{r.input_type.value} - {r.source_name}"}, {"Field": "Analysis mode", "Value": r.mode.value},
        {"Field": "Language detected", "Value": r.language}, {"Field": "Engine version", "Value": p.engine_version},
        {"Field": "Network mode", "Value": p.network_mode}, {"Field": "Configuration fingerprint", "Value": p.config_hash},
        {"Field": "Risk basis", "Value": r.risk_basis}, {"Field": "Timings (ms)", "Value": ", ".join(f"{k}={v}" for k, v in p.timings_ms.items())},
    ]), hide_index=True, width="stretch")
    if p.rules_applied:
        st.markdown("**Scoring rules applied**")
        st.markdown("\n".join(f"- {x}" for x in p.rules_applied))
    if r.review_items:
        st.markdown("**Items for human review**")
        st.dataframe(pd.DataFrame([{"Kind": x.kind, "Reference": x.ref, "Reason": x.reason} for x in r.review_items]), hide_index=True, width="stretch")
    st.caption(reports.DISCLAIMER)
