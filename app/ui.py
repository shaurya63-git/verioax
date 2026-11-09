"""Design system for the Streamlit UI: tokens, global CSS and small HTML components.

Every dynamic string that reaches HTML goes through ``esc()`` - messages are attacker-controlled, so nothing they
contain may be interpreted as markup. Links from messages are only ever shown defanged and never made clickable.
"""
from __future__ import annotations

import html
from collections.abc import Iterable
from itertools import pairwise

import streamlit as st

# ---------------------------------------------------------------------------------------------- tokens
INK, INK2, INK3 = "#E6EDF7", "#A9B6CA", "#7C8BA3"
BG, PANEL, RAISED, LINE = "#0F1A2B", "#15233A", "#1B2C47", "#263A5C"
ACCENT = "#4C8DF6"
STATUS = {"LOW": "#2DBA6B", "MEDIUM": "#FAB219", "HIGH": "#EC835A", "CRITICAL": "#E05252", "INCONCLUSIVE": "#FAB219"}
LEVEL_WORD = {"LOW": "Low risk", "MEDIUM": "Medium risk", "HIGH": "High risk", "CRITICAL": "Critical risk", "INCONCLUSIVE": "Inconclusive"}
SEVERITY = {"critical": "#E05252", "high": "#EC835A", "medium": "#FAB219", "low": "#8090A8", "info": ACCENT}
CHECK = {"pass": ("#2DBA6B", "✓", "No issue"), "warn": ("#FAB219", "!", "Suspicious"), "fail": ("#E05252", "✕", "Threat indicator"),
         "info": (ACCENT, "i", "Note"), "unavailable": ("#6B7A92", "–", "Not checked")}
BADGE = {"LOW": "green", "MEDIUM": "orange", "HIGH": "orange", "CRITICAL": "red", "INCONCLUSIVE": "gray"}
SEV_BADGE = {"critical": "red", "high": "orange", "medium": "yellow", "low": "gray", "info": "blue"}


def esc(s: object) -> str:
    return html.escape("" if s is None else str(s), quote=True)


CSS = f"""
<style>
:root {{ --tg-ink:{INK}; --tg-ink2:{INK2}; --tg-ink3:{INK3}; --tg-panel:{PANEL}; --tg-raised:{RAISED}; --tg-line:{LINE}; --tg-accent:{ACCENT}; }}
.block-container {{ padding-top: 2.2rem; max-width: 1240px; }}
h1, h2, h3 {{ letter-spacing: -0.01em; }}
[data-testid="stMetric"] {{ background: var(--tg-panel); }}
[data-testid="stMetricLabel"] p {{ color: var(--tg-ink2); font-size: 0.86rem; }}
[data-testid="stSidebarNav"] a span {{ font-size: 0.95rem; }}
.tg-sub {{ color: var(--tg-ink2); margin: -0.6rem 0 1.2rem 0; font-size: 0.98rem; max-width: 70ch; }}

/* verdict panel - the one bold element */
.tg-verdict {{ display:grid; grid-template-columns: 6px 1fr; background: var(--tg-panel); border:1px solid var(--tg-line); border-radius: 10px; overflow:hidden; }}
.tg-verdict .rail {{ background: var(--lvl); }}
.tg-verdict .body {{ padding: 1.15rem 1.35rem 1.2rem 1.35rem; }}
.tg-verdict .top {{ display:flex; flex-wrap:wrap; gap: .6rem 1.4rem; align-items: baseline; justify-content: space-between; }}
.tg-verdict .level {{ font-size: 1.9rem; font-weight: 700; color: var(--lvl); line-height: 1.1; }}
.tg-verdict .score {{ color: var(--tg-ink2); font-size: .95rem; }}
.tg-verdict .score b {{ color: var(--tg-ink); font-size: 1.15rem; }}
.tg-verdict .title {{ font-size: 1.22rem; font-weight: 600; color: var(--tg-ink); margin: .55rem 0 .25rem 0; }}
.tg-verdict .summary {{ color: var(--tg-ink2); font-size: .95rem; max-width: 92ch; line-height: 1.5; }}
.tg-verdict .facts {{ display:flex; flex-wrap:wrap; gap: .35rem 1.6rem; margin-top: .9rem; font-size: .84rem; color: var(--tg-ink3); }}
.tg-verdict .facts span b {{ color: var(--tg-ink2); font-weight: 500; }}
.tg-inconclusive {{ border-style: dashed; border-color: {STATUS['INCONCLUSIVE']}; }}

.tg-scale {{ display:grid; grid-template-columns: 25fr 25fr 25fr 25fr; gap: 3px; margin-top: .95rem; position: relative; }}
.tg-scale .seg {{ height: 8px; border-radius: 2px; opacity: .25; }}
.tg-scale .seg.on {{ opacity: 1; }}
.tg-scale .lab {{ font-size: .74rem; color: var(--tg-ink3); margin-top: .3rem; }}
.tg-scale .lab.on {{ color: var(--tg-ink); font-weight: 600; }}
.tg-scale .marker {{ position:absolute; top:-5px; width: 3px; height: 18px; background: var(--tg-ink); border-radius: 2px; transform: translateX(-1px); }}
.tg-hatch {{ height: 8px; margin-top: .95rem; border-radius: 2px;
  background: repeating-linear-gradient(135deg, rgba(250,178,25,.55) 0 6px, rgba(250,178,25,.12) 6px 12px); }}

/* recommended actions: a real priority order, so it is numbered */
.tg-actions {{ counter-reset: act; list-style:none; padding:0; margin:.2rem 0 0 0; }}
.tg-actions li {{ counter-increment: act; display:grid; grid-template-columns: 1.9rem 1fr; gap:.2rem .6rem; padding:.55rem 0; border-bottom: 1px solid var(--tg-line); }}
.tg-actions li:last-child {{ border-bottom: 0; }}
.tg-actions li::before {{ content: counter(act); width:1.55rem; height:1.55rem; border-radius:50%; display:grid; place-items:center; font-size:.82rem; font-weight:600;
  background: var(--tg-raised); color: var(--tg-ink); border:1px solid var(--tg-line); }}
.tg-actions .t {{ font-weight:600; color: var(--tg-ink); }}
.tg-actions .d {{ color: var(--tg-ink2); font-size: .92rem; grid-column: 2; }}

/* highlighted message */
.tg-msg {{ background: #122036; border:1px solid var(--tg-line); border-radius: 8px; padding: .9rem 1rem; line-height: 1.85; white-space: pre-wrap; word-break: break-word; font-size: .97rem; color: var(--tg-ink); }}
.tg-msg.mono {{ font-family: "IBM Plex Mono", monospace; font-size: .88rem; line-height: 1.75; }}
.tg-msg mark {{ color: inherit; padding: 1px 2px; border-radius: 3px; }}
.tg-msg mark.pii {{ background: rgba(76,141,246,.16); border-bottom: 2px dotted {ACCENT}; }}
.tg-msg sup {{ font-size: .62rem; font-weight: 600; margin-left: 2px; color: var(--tg-ink2); }}
.tg-msg .ph {{ color: #9CC2FF; font-family: "IBM Plex Mono", monospace; font-size: .85em; }}
.tg-legend {{ display:flex; flex-wrap:wrap; gap:.4rem 1.1rem; font-size:.8rem; color: var(--tg-ink3); margin:.45rem 0 .2rem 0; }}
.tg-legend i {{ display:inline-block; width:.85rem; height:.6rem; border-radius:2px; margin-right:.35rem; vertical-align: middle; }}

/* checks */
.tg-checks {{ border:1px solid var(--tg-line); border-radius: 8px; overflow:hidden; }}
.tg-check {{ display:grid; grid-template-columns: 1.7rem 11.5rem 1fr; gap:.15rem .7rem; padding:.62rem .85rem; border-bottom:1px solid var(--tg-line); background: var(--tg-panel); }}
.tg-check:last-child {{ border-bottom: 0; }}
.tg-check .ic {{ width:1.35rem; height:1.35rem; border-radius: 50%; display:grid; place-items:center; font-size:.78rem; font-weight:700; color:#0F1A2B; margin-top:.1rem; }}
.tg-check .lb {{ color: var(--tg-ink2); font-size:.9rem; }}
.tg-check .sm {{ color: var(--tg-ink); font-size:.93rem; }}
.tg-check .ex {{ grid-column: 3; color: var(--tg-ink3); font-size:.83rem; line-height:1.45; }}
.tg-check .src {{ font-size:.72rem; color: var(--tg-ink3); border:1px solid var(--tg-line); border-radius: 4px; padding: 0 .3rem; margin-left:.4rem; }}
@media (max-width: 720px) {{ .tg-check {{ grid-template-columns: 1.7rem 1fr; }} .tg-check .sm, .tg-check .ex {{ grid-column: 2; }} }}

.tg-url {{ font-family: "IBM Plex Mono", monospace; font-size: .92rem; color: var(--tg-ink); word-break: break-all; }}
.tg-pill {{ display:inline-block; font-size:.78rem; font-weight:600; padding:.1rem .55rem; border-radius: 999px; border:1px solid currentColor; }}
.tg-chain {{ margin: .2rem 0 0 1.1rem; padding: 0; color: var(--tg-ink2); font-size: .88rem; }}
.tg-chain li {{ margin: .15rem 0; }}
.tg-note {{ color: var(--tg-ink3); font-size: .85rem; }}
.tg-empty {{ border: 1px dashed var(--tg-line); border-radius: 10px; padding: 1.6rem 1.5rem; background: rgba(21,35,58,.55); }}
.tg-empty h3 {{ margin: 0 0 .35rem 0; font-size: 1.15rem; }}
.tg-empty p {{ color: var(--tg-ink2); margin: 0; max-width: 64ch; }}

/* sidebar status */
.tg-status {{ font-size: .8rem; color: var(--tg-ink3); line-height: 1.55; padding-top: .2rem; }}
.tg-status .row {{ display:flex; gap:.45rem; align-items: baseline; }}
.tg-status .dot {{ width: .5rem; height: .5rem; border-radius: 50%; display:inline-block; flex: none; transform: translateY(-1px); }}
.tg-status b {{ color: var(--tg-ink2); font-weight: 500; }}
@media (prefers-reduced-motion: reduce) {{ * {{ transition: none !important; animation: none !important; }} }}
</style>
"""


def inject_css() -> None:
    st.html(CSS)


def page_header(title: str, subtitle: str = "") -> None:
    st.title(title)
    if subtitle:
        st.html(f"<p class='tg-sub'>{esc(subtitle)}</p>")


# ---------------------------------------------------------------------------------------------- verdict panel
def verdict_panel(r) -> str:
    lvl = r.overall_risk.value
    color = STATUS[lvl]
    basis = "Privacy exposure score" if r.risk_basis == "privacy" else "Risk score"
    ev = r.evidence_summary or {}
    facts = [("Scan", r.scan_id), ("When", f"{r.created_at:%d %b %Y, %H:%M} UTC"),
             ("Checked", ", ".join({"pii": "personal data", "scam": "scam & hoax", "url": "links", "intel": "threat intel", "llm": "local AI"}.get(m, m)
                                   for m in r.processing.modules) or "-")]
    if r.risk_basis == "threat" and any(ev.values()):
        facts.append(("Evidence", f"{ev.get('confirmed', 0)} confirmed, {ev.get('strong', 0)} strong, {ev.get('weak', 0)} weak"))
    if r.processing.demo:
        facts.append(("Data", "sample scan (demo)"))
    facts_html = "".join(f"<span>{esc(k)} <b>{esc(v)}</b></span>" for k, v in facts)

    if lvl == "INCONCLUSIVE":
        scale = "<div class='tg-hatch' title='Not enough evidence to place this on the scale'></div>"
    else:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        segs = "".join(f"<div><div class='seg{' on' if k == lvl else ''}' style='background:{STATUS[k]}'></div>"
                       f"<div class='lab{' on' if k == lvl else ''}'>{esc(LEVEL_WORD[k].replace(' risk', ''))}</div></div>" for k in order)
        pos = max(0.5, min(99.5, r.risk_score))
        scale = f"<div class='tg-scale'>{segs}<div class='marker' style='left:{pos}%' title='Score {r.risk_score}'></div></div>"
    conf = f"{r.confidence_label} confidence ({r.model_confidence:.2f})"
    return (f"<div class='tg-verdict{' tg-inconclusive' if lvl == 'INCONCLUSIVE' else ''}' style='--lvl:{color}'>"
            f"<div class='rail'></div><div class='body'>"
            f"<div class='top'><div class='level'>{esc(LEVEL_WORD[lvl])}</div>"
            f"<div class='score'>{esc(basis)} <b>{r.risk_score}</b>/100 &nbsp; {esc(conf)}</div></div>"
            f"{scale}<div class='title'>{esc(r.verdict_title)}</div><div class='summary'>{esc(r.verdict_summary)}</div>"
            f"<div class='facts'>{facts_html}</div></div></div>")


def actions_list(actions) -> str:
    items = "".join(f"<li><span class='t'>{esc(a.title)}</span><span class='d'>{esc(a.detail)}</span></li>" for a in actions)
    return f"<ol class='tg-actions'>{items}</ol>"


# ---------------------------------------------------------------------------------------------- highlighting
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def highlight(text: str, threat: Iterable[tuple[int, int, str, str, str]], pii: Iterable[tuple[int, int, str, str]] = (),
              mark_placeholders: bool = False, mono: bool = False) -> str:
    """Render text with threat spans (start, end, id, severity, title) and PII spans (start, end, placeholder, type).

    Overlaps are resolved per character segment: the most severe threat span sets the colour, PII adds a dotted
    underline, and every span covering a segment is listed in its tooltip.
    """
    threat = [t for t in threat if t[0] is not None and t[1] is not None and 0 <= t[0] < t[1] <= len(text)]
    pii = [p for p in pii if 0 <= p[0] < p[1] <= len(text)]
    cuts = sorted({0, len(text)} | {x for t in threat for x in t[:2]} | {x for p in pii for x in p[:2]})
    ends_at: dict[int, list[str]] = {}
    for _s, e, fid, sev, _ in threat:
        if sev != "info":
            ends_at.setdefault(e, []).append(fid)
    out: list[str] = []
    for a, b in pairwise(cuts):
        seg = text[a:b]
        ts = [t for t in threat if t[0] <= a and b <= t[1]]
        ps = [p for p in pii if p[0] <= a and b <= p[1]]
        body = _placeholders(seg) if mark_placeholders else esc(seg)
        if ts or ps:
            tips = [f"{t[2]}: {t[4]} ({t[3]})" for t in ts] + [f"{p[3]} -> {p[2]}" for p in ps]
            style = ""
            cls = ""
            if ts:
                top = max(ts, key=lambda t: _SEV_RANK.get(t[3], 0))
                c = SEVERITY.get(top[3], ACCENT)
                dotted = top[3] == "info"
                style = (f"background:{c}2e;border-bottom:2px {'dotted' if dotted else 'solid'} {c};")
            if ps and not ts:
                cls = " class='pii'"
            elif ps:
                style += f"box-shadow: inset 0 -5px 0 -3px {ACCENT};"
            body = f"<mark{cls} style='{style}' title='{esc(' | '.join(tips))}'>{body}</mark>"
        out.append(body)
        if b in ends_at:
            out.append(f"<sup>{esc(','.join(dict.fromkeys(ends_at[b])))}</sup>")
    return f"<div class='tg-msg{' mono' if mono else ''}'>{''.join(out)}</div>"


def _placeholders(seg: str) -> str:
    import re
    parts = re.split(r"(\[[A-Z_]+_\d{3}\])", seg)
    return "".join(f"<span class='ph'>{esc(p)}</span>" if re.fullmatch(r"\[[A-Z_]+_\d{3}\]", p) else esc(p) for p in parts)


def legend(include_pii: bool = True) -> str:
    items = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low / weak signal"), ("info", "Context (link, amount)")]
    html_ = "".join(f"<span><i style='background:{SEVERITY[k]}'></i>{esc(lbl)}</span>" for k, lbl in items)
    if include_pii:
        html_ += f"<span><i style='background:transparent;border-bottom:2px dotted {ACCENT};height:.4rem'></i>Personal data</span>"
    return f"<div class='tg-legend'>{html_}</div>"


# ---------------------------------------------------------------------------------------------- URL report pieces
def checks_table(checks) -> str:
    rows = []
    for c in checks:
        color, icon, word = CHECK.get(c.status, CHECK["info"])
        src = {"static": "from the link text", "live": "live check", "intel": "threat intel", "cache": "cached", "local": "local list"}.get(c.source, c.source)
        rows.append(f"<div class='tg-check'><div class='ic' style='background:{color}' title='{esc(word)}' aria-label='{esc(word)}'>{icon}</div>"
                    f"<div class='lb'>{esc(c.label)}</div><div class='sm'>{esc(c.summary)}<span class='src'>{esc(src)}</span></div>"
                    + (f"<div class='ex'>{esc(c.explanation)}</div>" if c.explanation and c.explanation.strip() != c.summary.strip() else "") + "</div>")
    return f"<div class='tg-checks'>{''.join(rows)}</div>"


def pill(text: str, color: str) -> str:
    return f"<span class='tg-pill' style='color:{color}'>{esc(text)}</span>"


def empty_state(title: str, body: str) -> None:
    st.html(f"<div class='tg-empty'><h3>{esc(title)}</h3><p>{esc(body)}</p></div>")


def risk_badge_md(level: str) -> str:
    return f":{BADGE.get(level, 'gray')}-badge[{LEVEL_WORD.get(level, level)}]"


def sev_badge_md(sev: str) -> str:
    return f":{SEV_BADGE.get(sev, 'gray')}-badge[{sev.capitalize()}]"
