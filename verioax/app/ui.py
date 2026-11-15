"""Design system for the Streamlit UI: tokens, global CSS and small HTML components.

Every dynamic string that reaches HTML goes through ``esc()`` - messages are attacker-controlled, so nothing they
contain may be interpreted as markup. Links from messages are only ever shown defanged and never made clickable.
"""
from __future__ import annotations

import html
from collections.abc import Iterable
from itertools import pairwise

import streamlit as st

# ---------------------------------------------------------------------------------------------- tokens (from theme.py)
import theme as T  # noqa: E402

INK, INK2, INK3 = T.COLORS["text"], T.COLORS["text_muted"], T.COLORS["text_muted"]
BG, PANEL, RAISED, LINE = T.COLORS["bg"], T.COLORS["surface"], T.COLORS["surface_2"], T.COLORS["border"]
ACCENT, ACCENT2 = T.COLORS["accent"], T.COLORS["accent_2"]
STATUS = T.RISK
STATUS_TEXT = T.RISK_TEXT
LEVEL_WORD = T.RISK_WORD
SEVERITY = T.SEVERITY
CHECK = T.CHECK
BADGE = T.BADGE
SEV_BADGE = T.SEV_BADGE


def esc(s: object) -> str:
    return html.escape("" if s is None else str(s), quote=True)


CSS = f"""
<style>
{T.css_variables()}
.block-container {{ padding-top: 2.1rem; max-width: 1240px; }}
h1, h2, h3 {{ letter-spacing: -0.012em; }}
h1 {{ font-weight: 650; }}
::selection {{ background: {T.rgba(T.COLORS["accent"], .32)}; }}

/* surfaces: one card language everywhere (metrics, bordered containers, expanders) */
[data-testid="stMetric"] {{ background: var(--vx-surface); box-shadow: var(--vx-shadow-card); border-radius: var(--vx-radius-md); }}
[data-testid="stMetricLabel"] p {{ color: var(--vx-text-muted); font-size: 0.86rem; }}
[data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) {{ border-radius: var(--vx-radius-md); }}
[data-testid="stExpander"] details {{ background: var(--vx-surface); border-radius: var(--vx-radius-md); }}
[data-testid="stExpander"] summary:hover {{ background: var(--vx-surface-2); }}
[data-testid="stSidebar"] {{ border-right: 1px solid var(--vx-border); }}
[data-testid="stSidebarNav"] a span {{ font-size: 0.95rem; }}
[data-testid="stSidebarNav"] a[aria-current="page"] {{ background: {T.rgba(T.COLORS["accent"], .12)}; }}
[data-testid="stSidebarNav"] a[aria-current="page"] span {{ color: var(--vx-text); font-weight: 600; }}
.tg-sub {{ color: var(--vx-text-muted); margin: -0.6rem 0 1.2rem 0; font-size: 0.98rem; max-width: 72ch; }}

/* buttons: teal primary with dark text (white on teal fails contrast), quiet secondary, visible focus */
[data-testid="stBaseButton-primary"], [data-testid="stBaseButton-primaryFormSubmit"] {{ color: var(--vx-on-accent) !important; font-weight: 600;
  background: linear-gradient(180deg, {T.rgba(T.COLORS["text"], .10)}, transparent), var(--vx-accent) !important; border-color: var(--vx-accent) !important; }}
[data-testid="stBaseButton-primary"] p, [data-testid="stBaseButton-primaryFormSubmit"] p {{ color: var(--vx-on-accent) !important; }}
[data-testid="stBaseButton-primary"]:hover, [data-testid="stBaseButton-primaryFormSubmit"]:hover {{ filter: brightness(1.08); }}
[data-testid="stBaseButton-secondary"], [data-testid="stBaseButton-secondaryFormSubmit"] {{ border-color: var(--vx-control) !important; }}
[data-testid="stBaseButton-secondary"]:hover {{ border-color: var(--vx-accent) !important; color: var(--vx-text) !important; }}
button, a, [role="tab"], input, textarea, [data-baseweb="select"] {{ transition: background-color var(--vx-motion), border-color var(--vx-motion),
  color var(--vx-motion), box-shadow var(--vx-motion), filter var(--vx-motion); }}
button:focus-visible, a:focus-visible, [role="tab"]:focus-visible, summary:focus-visible, [tabindex]:focus-visible {{
  outline: 2px solid var(--vx-accent) !important; outline-offset: 2px !important; box-shadow: none !important; }}
/* form controls get a 3:1 outline so they can be found; teal ring on focus */
[data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div, [data-testid="stFileUploaderDropzone"] {{ border-color: var(--vx-control) !important; }}
[data-baseweb="input"]:focus-within, [data-baseweb="textarea"]:focus-within, [data-baseweb="select"] > div:focus-within {{
  border-color: var(--vx-accent) !important; box-shadow: 0 0 0 3px {T.rgba(T.COLORS["accent"], .22)} !important; }}
[data-testid="stFileUploaderDropzone"] {{ background: {T.rgba(T.COLORS["surface"], .7)}; border-style: dashed !important; }}
[data-testid="stAlert"] {{ border-radius: var(--vx-radius-md); }}
[role="tablist"] button[aria-selected="true"] p {{ font-weight: 600; }}

/* verdict panel - the one bold element */
.tg-verdict {{ display:grid; grid-template-columns: 6px 1fr; border:1px solid var(--vx-border); border-radius: var(--vx-radius-lg); overflow:hidden;
  background: linear-gradient(115deg, color-mix(in srgb, var(--lvl) 9%, var(--vx-surface)) 0%, var(--vx-surface) 46%); box-shadow: var(--vx-shadow-raised); }}
.tg-verdict .rail {{ background: var(--lvl); }}
.tg-verdict .body {{ padding: 1.2rem 1.4rem 1.2rem 1.4rem; }}
.tg-verdict .top {{ display:flex; flex-wrap:wrap; gap: .7rem 1.6rem; align-items: center; justify-content: space-between; }}
.tg-verdict .level {{ display:flex; align-items:center; gap:.7rem; font-size: 1.9rem; font-weight: 700; color: var(--lvl); line-height: 1.1; }}
.tg-verdict .level .ico {{ width: 2.1rem; height: 2.1rem; border-radius: 50%; display:grid; place-items:center; font-size: 1.05rem; font-weight: 800;
  background: var(--lvl); color: var(--vx-bg); flex: none; }}
.tg-verdict .stats {{ display:flex; gap: .6rem; flex-wrap: wrap; }}
.tg-verdict .stat {{ background: {T.rgba(T.COLORS["bg"], .45)}; border: 1px solid var(--vx-border); border-radius: var(--vx-radius-md); padding: .45rem .8rem;
  min-width: 8.5rem; }}
.tg-verdict .stat .k {{ font-size: .74rem; color: var(--vx-text-muted); text-transform: uppercase; letter-spacing: .06em; }}
.tg-verdict .stat .v {{ font-size: 1.05rem; color: var(--vx-text); font-weight: 600; }}
.tg-verdict .stat .v b {{ font-size: 1.3rem; }}
.tg-verdict .stat .v small {{ color: var(--vx-text-muted); font-weight: 500; font-size: .85rem; }}
.tg-verdict .type {{ display:inline-flex; align-items:center; gap:.45rem; margin-top: .95rem; font-size: .82rem; font-weight: 600; color: var(--vx-text);
  background: {T.rgba(T.COLORS["bg"], .5)}; border: 1px solid var(--vx-border); border-radius: var(--vx-radius-pill); padding: .2rem .7rem .2rem .55rem; }}
.tg-verdict .type i {{ width:.55rem; height:.55rem; border-radius:50%; background: var(--lvl); display:inline-block; }}
.tg-verdict .title {{ font-size: 1.24rem; font-weight: 600; color: var(--vx-text); margin: .6rem 0 .3rem 0; }}
.tg-verdict .summary {{ color: var(--vx-text-muted); font-size: .96rem; max-width: 92ch; line-height: 1.55; }}
.tg-verdict .typesum {{ color: var(--vx-text-muted); font-size: .9rem; max-width: 92ch; line-height: 1.5; margin-top: .45rem;
  border-left: 2px solid var(--vx-border); padding-left: .7rem; }}
.tg-verdict .facts {{ display:flex; flex-wrap:wrap; gap: .35rem 1.6rem; margin-top: 1rem; font-size: .84rem; color: var(--vx-text-muted); }}
.tg-verdict .facts span b {{ color: var(--vx-text); font-weight: 500; }}
.tg-inconclusive {{ border-style: dashed; border-color: {T.RISK["INCONCLUSIVE"]}; }}
@media (max-width: 640px) {{ .tg-verdict .level {{ font-size: 1.5rem; }} .tg-verdict .stat {{ min-width: 0; flex: 1; }} }}

.tg-scale {{ display:grid; grid-template-columns: 25fr 25fr 25fr 25fr; gap: 3px; margin-top: 1rem; position: relative; }}
.tg-scale .seg {{ height: 8px; border-radius: 3px; opacity: .22; }}
.tg-scale .seg.on {{ opacity: 1; }}
.tg-scale .lab {{ font-size: .74rem; color: var(--vx-text-muted); margin-top: .3rem; }}
.tg-scale .lab.on {{ color: var(--vx-text); font-weight: 600; }}
.tg-scale .marker {{ position:absolute; top:-5px; width: 3px; height: 18px; background: var(--vx-text); border-radius: 2px; transform: translateX(-1px);
  box-shadow: 0 0 0 2px var(--vx-surface); }}
.tg-hatch {{ height: 8px; margin-top: 1rem; border-radius: 3px;
  background: repeating-linear-gradient(135deg, {T.rgba(T.RISK["INCONCLUSIVE"], .55)} 0 6px, {T.rgba(T.RISK["INCONCLUSIVE"], .12)} 6px 12px); }}

/* recommended actions: a real priority order, so it is numbered */
.tg-actions {{ counter-reset: act; list-style:none; padding:0; margin:.2rem 0 0 0; }}
.tg-actions li {{ counter-increment: act; display:grid; grid-template-columns: 1.9rem 1fr; gap:.2rem .6rem; padding:.6rem 0; border-bottom: 1px solid var(--vx-border); }}
.tg-actions li:last-child {{ border-bottom: 0; }}
.tg-actions li::before {{ content: counter(act); width:1.55rem; height:1.55rem; border-radius:50%; display:grid; place-items:center; font-size:.82rem; font-weight:700;
  background: {T.rgba(T.COLORS["accent"], .14)}; color: var(--vx-accent); border:1px solid {T.rgba(T.COLORS["accent"], .45)}; }}
.tg-actions li:first-child::before {{ background: var(--vx-accent); color: var(--vx-on-accent); }}
.tg-actions .t {{ font-weight:600; color: var(--vx-text); }}
.tg-actions .d {{ color: var(--vx-text-muted); font-size: .92rem; grid-column: 2; }}

/* highlighted message */
.tg-msg {{ background: var(--vx-surface); border:1px solid var(--vx-border); border-radius: var(--vx-radius-md); padding: .95rem 1.05rem; line-height: 1.85;
  white-space: pre-wrap; word-break: break-word; font-size: .97rem; color: var(--vx-text); }}
.tg-msg.mono {{ font-family: var(--vx-mono); font-size: .88rem; line-height: 1.75; }}
.tg-msg mark {{ color: inherit; padding: 1px 2px; border-radius: 3px; }}
.tg-msg mark.pii {{ background: {T.rgba(T.COLORS["accent_2"], .14)}; border-bottom: 2px dotted var(--vx-accent-2); }}
.tg-msg sup {{ font-size: .62rem; font-weight: 600; margin-left: 2px; color: var(--vx-text-muted); }}
.tg-msg .ph {{ color: {T.COLORS["placeholder"]}; font-family: var(--vx-mono); font-size: .85em; }}
.tg-legend {{ display:flex; flex-wrap:wrap; gap:.4rem 1.1rem; font-size:.8rem; color: var(--vx-text-muted); margin:.5rem 0 .2rem 0; }}
.tg-legend i {{ display:inline-block; width:.85rem; height:.6rem; border-radius:2px; margin-right:.35rem; vertical-align: middle; }}

/* quoted evidence inside a finding */
.tg-quote {{ font-family: var(--vx-mono); font-size: .86rem; color: var(--vx-text); background: var(--vx-surface-2); border-left: 3px solid var(--sev, var(--vx-border));
  border-radius: 0 var(--vx-radius-sm) var(--vx-radius-sm) 0; padding: .45rem .7rem; margin: .35rem 0; white-space: pre-wrap; word-break: break-word; }}
.tg-kv {{ display:flex; flex-wrap:wrap; gap:.4rem 1.4rem; font-size:.85rem; color: var(--vx-text-muted); margin: .5rem 0 .2rem 0; }}
.tg-kv b {{ color: var(--vx-text); font-weight: 500; }}

/* checks */
.tg-checks {{ border:1px solid var(--vx-border); border-radius: var(--vx-radius-md); overflow:hidden; }}
.tg-check {{ display:grid; grid-template-columns: 1.7rem 11.5rem 1fr; gap:.15rem .7rem; padding:.62rem .85rem; border-bottom:1px solid var(--vx-border);
  background: var(--vx-surface); }}
.tg-check:nth-child(even) {{ background: color-mix(in srgb, var(--vx-surface) 70%, var(--vx-surface-2)); }}
.tg-check:last-child {{ border-bottom: 0; }}
.tg-check .ic {{ width:1.35rem; height:1.35rem; border-radius: 50%; display:grid; place-items:center; font-size:.78rem; font-weight:800; color: var(--vx-bg);
  margin-top:.1rem; }}
.tg-check .lb {{ color: var(--vx-text-muted); font-size:.9rem; }}
.tg-check .sm {{ color: var(--vx-text); font-size:.93rem; }}
.tg-check .ex {{ grid-column: 3; color: var(--vx-text-muted); font-size:.83rem; line-height:1.45; }}
.tg-check .src {{ font-size:.72rem; color: var(--vx-text-muted); border:1px solid var(--vx-border); border-radius: 4px; padding: 0 .3rem; margin-left:.4rem; }}
@media (max-width: 720px) {{ .tg-check {{ grid-template-columns: 1.7rem 1fr; }} .tg-check .sm, .tg-check .ex {{ grid-column: 2; }} }}

.tg-url {{ font-family: var(--vx-mono); font-size: .92rem; color: var(--vx-text); word-break: break-all; }}
.tg-pill {{ display:inline-flex; align-items:center; gap:.3rem; font-size:.78rem; font-weight:600; padding:.12rem .6rem; border-radius: var(--vx-radius-pill);
  border:1px solid currentColor; background: color-mix(in srgb, currentColor 12%, transparent); white-space: nowrap; }}
.tg-pill .i {{ font-size: .72rem; }}
.tg-chain {{ margin: .2rem 0 0 1.1rem; padding: 0; color: var(--vx-text-muted); font-size: .88rem; }}
.tg-chain li {{ margin: .15rem 0; }}
.tg-note {{ color: var(--vx-text-muted); font-size: .85rem; }}
.tg-empty {{ display:grid; grid-template-columns: 2.6rem 1fr; gap: .2rem 1rem; border: 1px dashed var(--vx-control); border-radius: var(--vx-radius-lg);
  padding: 1.5rem 1.5rem; background: linear-gradient(135deg, {T.rgba(T.COLORS["accent"], .05)}, transparent 60%), var(--vx-surface); }}
.tg-empty .ico {{ width: 2.6rem; height: 2.6rem; border-radius: 50%; display:grid; place-items:center; background: {T.rgba(T.COLORS["accent"], .14)};
  color: var(--vx-accent); font-size: 1.2rem; grid-row: span 2; }}
.tg-empty h3 {{ margin: 0 0 .3rem 0; font-size: 1.12rem; padding: 0; }}
.tg-empty p {{ color: var(--vx-text-muted); margin: 0; max-width: 66ch; }}

/* tables written as HTML */
.tg-table {{ width:100%; border-collapse: separate; border-spacing: 0; font-size: .9rem; border: 1px solid var(--vx-border); border-radius: var(--vx-radius-md);
  overflow: hidden; }}
.tg-table th {{ text-align:left; font-weight:600; color: var(--vx-text-muted); background: var(--vx-surface-2); padding: .5rem .75rem; font-size: .78rem;
  text-transform: uppercase; letter-spacing: .05em; }}
.tg-table td {{ padding: .5rem .75rem; border-top: 1px solid var(--vx-border); color: var(--vx-text); vertical-align: top; overflow-wrap: break-word; }}
.tg-table tr:nth-child(even) td {{ background: color-mix(in srgb, var(--vx-surface) 70%, var(--vx-surface-2)); }}
.tg-table td.m {{ color: var(--vx-text-muted); }}
.tg-table code {{ font-family: var(--vx-mono); font-size: .84rem; }}
.tg-scroll {{ overflow-x: auto; }}

/* sidebar status */
.tg-status {{ font-size: .8rem; color: var(--vx-text-muted); line-height: 1.55; padding-top: .2rem; }}
.tg-status .row {{ display:flex; gap:.45rem; align-items: baseline; }}
.tg-status .dot {{ width: .5rem; height: .5rem; border-radius: 50%; display:inline-block; flex: none; transform: translateY(-1px); }}
.tg-status b {{ color: var(--vx-text); font-weight: 500; }}
.tg-founder {{ margin-top: .9rem; padding-top: .65rem; border-top: 1px solid var(--vx-border); font-size: .8rem; color: var(--vx-text-muted); }}
.tg-founder b {{ color: var(--vx-text); font-weight: 500; }}
.tg-user {{ font-size: .85rem; color: var(--vx-text-muted); line-height: 1.45; margin: .1rem 0 .35rem 0; }}
.tg-user b {{ color: var(--vx-text); font-weight: 600; }}
.tg-fb {{ white-space: pre-wrap; color: var(--vx-text); font-size: .95rem; line-height: 1.55; margin: .25rem 0 .4rem 0; max-width: 90ch; }}
.tg-reply {{ border-left: 3px solid var(--vx-accent); padding: .35rem 0 .35rem .8rem; color: var(--vx-text-muted); font-size: .92rem;
             white-space: pre-wrap; margin: .4rem 0; max-width: 90ch; }}
.tg-meta {{ color: var(--vx-text-muted); font-size: .82rem; }}
.tg-facts {{ width:100%; border-collapse: collapse; font-size: .92rem; margin: .2rem 0; }}
.tg-facts td {{ padding: .42rem 0; border-bottom: 1px solid var(--vx-border); vertical-align: top; color: var(--vx-text); overflow-wrap: anywhere; }}
.tg-facts td.k {{ color: var(--vx-text-muted); width: 9.5rem; padding-right: .8rem; }}
.tg-facts tr:last-child td {{ border-bottom: 0; }}
.tg-fbhead {{ display:flex; flex-wrap: wrap; gap: .5rem; align-items: center; font-size: 1rem; margin-bottom: .15rem; }}
.tg-fbhead b {{ color: var(--vx-text); font-weight: 600; margin-right: .2rem; }}

/* sign-in page */
.tg-hero h1 {{ font-size: 2.5rem; line-height: 1.12; margin: .4rem 0 .9rem 0; letter-spacing: -0.015em; font-weight: 650; }}
.tg-hero h1 em {{ font-style: normal; color: var(--vx-accent); }}
.tg-hero p {{ color: var(--vx-text-muted); font-size: 1.04rem; max-width: 50ch; margin: 0 0 .5rem 0; }}
.tg-sample {{ margin-top: 1.5rem; border: 1px solid var(--vx-border); border-left: 4px solid var(--vx-risk-critical); border-radius: var(--vx-radius-md);
              background: var(--vx-surface); box-shadow: var(--vx-shadow-card); padding: .95rem 1.1rem; max-width: 56ch; }}
.tg-sample .lbl {{ font-size: .78rem; color: var(--vx-text-muted); margin-bottom: .45rem; }}
.tg-sample .txt {{ font-family: var(--vx-mono); font-size: .84rem; color: var(--vx-text); line-height: 1.65; }}
.tg-sample .ph {{ color: {T.COLORS["placeholder"]}; }}
.tg-sample .bad {{ background: {T.rgba(T.RISK["CRITICAL"], .16)}; border-bottom: 2px solid var(--vx-risk-critical); padding: 0 .1rem; }}
.tg-sample .verdict {{ margin-top: .65rem; font-size: .86rem; color: {T.RISK_TEXT["CRITICAL"]}; font-weight: 600; }}
.tg-steps {{ margin: 1.3rem 0 0 0 !important; padding: 0 !important; list-style: none; color: var(--vx-text-muted); font-size: .95rem; max-width: 56ch; }}
.tg-steps li {{ margin: .3rem 0 !important; padding-left: 0 !important; }}
.tg-steps b {{ color: var(--vx-text); font-weight: 600; }}
@media (prefers-reduced-motion: reduce) {{ * {{ transition: none !important; animation: none !important; }} }}
</style>
"""


def inject_css() -> None:
    st.html(CSS)


FOUNDER = "Shaurya Shah"
# (hex colour, word) - colour is always paired with the word
STATE_PILL = {"online": (T.OK, "Online"), "active": (T.INFO, "Active"), "locked": (T.WARN, "Locked"), "suspended": (T.BAD, "Suspended")}
FEEDBACK_PILL = {"new": (T.INFO, "New"), "in_review": (T.WARN, "In review"), "resolved": (T.OK, "Resolved")}
NEUTRAL = T.NEUTRAL
CHECK_STATUS = {"checked": (T.OK, "✓", "Link checked"), "partly_checked": (T.WARN, "◐", "Partly checked"),
                "not_checked": (T.NEUTRAL, "–", "Not checked live"), "not_visited": (T.NEUTRAL, "–", "Not visited"),
                "unreachable": (T.NEUTRAL, "?", "Could not be reached")}


def local_time(iso: str | None, fmt: str = "%d %b %Y, %H:%M") -> str:
    """An ISO timestamp (UTC) in the viewer's own time zone, as reported by their browser."""
    if not iso:
        return "-"
    from datetime import datetime, timedelta, timezone
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        tz_name, offset = st.context.timezone, st.context.timezone_offset
    except Exception:                                   # no browser context (tests, scripts)
        tz_name, offset = None, None
    if tz_name:
        try:
            from zoneinfo import ZoneInfo
            return dt.astimezone(ZoneInfo(tz_name)).strftime(fmt)
        except Exception:                               # e.g. 'Asia/Calcutta' missing from a minimal time-zone database
            pass
    if offset is not None:                              # JavaScript convention: minutes *behind* UTC (India = -330)
        return dt.astimezone(timezone(timedelta(minutes=-offset))).strftime(fmt)
    return dt.astimezone(timezone.utc).strftime(fmt) + " UTC"


def facts_table(rows) -> str:
    """Label / value rows, every value escaped."""
    return "<table class='tg-facts'>" + "".join(f"<tr><td class='k'>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in rows) + "</table>"


def founder_html() -> str:
    return f"<div class='tg-founder'>Founded by: <b>{esc(FOUNDER)}</b></div>"


def page_header(title: str, subtitle: str = "") -> None:
    st.title(title)
    if subtitle:
        st.html(f"<p class='tg-sub'>{esc(subtitle)}</p>")


# ---------------------------------------------------------------------------------------------- verdict panel
def verdict_panel(r) -> str:
    lvl = r.overall_risk.value
    color = STATUS[lvl]
    basis = "Privacy exposure" if r.risk_basis == "privacy" else "Risk score"
    ev = r.evidence_summary or {}
    facts = [("Scan", r.scan_id), ("When", local_time(r.created_at.isoformat())),
             ("Checked", ", ".join({"pii": "personal data", "scam": "scam & hoax", "url": "links", "intel": "threat intel", "llm": "local AI",
                                    "app": "Android app (static)"}.get(m, m) for m in r.processing.modules) or "-")]
    if r.risk_basis == "threat" and any(ev.values()):
        facts.append(("Evidence", f"{ev.get('confirmed', 0)} confirmed, {ev.get('strong', 0)} strong, {ev.get('weak', 0)} weak"))
    if r.urls:
        st_ = [CHECK_STATUS.get(u.check_status, CHECK_STATUS["not_checked"])[2].lower() for u in r.urls]
        facts.append(("Links", ", ".join(f"{n} {w}" for w, n in _count(st_))))
    if r.processing.demo:
        facts.append(("Data", "sample scan (demo)"))
    facts_html = "".join(f"<span>{esc(k)} <b>{esc(v)}</b></span>" for k, v in facts)

    if lvl == "INCONCLUSIVE":
        scale = "<div class='tg-hatch' role='img' aria-label='Inconclusive: not enough evidence to place this on the scale'></div>"
    else:
        order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        segs = "".join(f"<div><div class='seg{' on' if k == lvl else ''}' style='background:{STATUS[k]}'></div>"
                       f"<div class='lab{' on' if k == lvl else ''}'>{esc(LEVEL_WORD[k].replace(' risk', ''))}</div></div>" for k in order)
        pos = max(0.5, min(99.5, r.risk_score))
        scale = (f"<div class='tg-scale' role='img' aria-label='{esc(LEVEL_WORD[lvl])}, score {r.risk_score} out of 100'>{segs}"
                 f"<div class='marker' style='left:{pos}%'></div></div>")
    conf_help = ("How sure Verioax is about this verdict, from how much of the evidence it could check. "
                 "It is not a probability and not a calibrated statistic.")
    stats = (f"<div class='stats'><div class='stat'><div class='k'>{esc(basis)}</div><div class='v'><b>{r.risk_score}</b><small> / 100</small></div></div>"
             f"<div class='stat' title='{esc(conf_help)}'><div class='k'>Confidence</div><div class='v'>{esc(r.confidence_label)}"
             f"<small> ({r.model_confidence:.2f})</small></div></div></div>")
    stype = ""
    if getattr(r, "scam_type_label", None):
        stype = f"<div class='type'><i></i>{esc(r.scam_type_label)}</div>"
    typesum = f"<div class='typesum'>{esc(r.scam_type_summary)}</div>" if getattr(r, "scam_type_summary", None) else ""
    return (f"<div class='tg-verdict{' tg-inconclusive' if lvl == 'INCONCLUSIVE' else ''}' style='--lvl:{color}' role='region' aria-label='Verdict'>"
            f"<div class='rail'></div><div class='body'>"
            f"<div class='top'><div class='level'><span class='ico' aria-hidden='true'>{T.RISK_ICON[lvl]}</span>{esc(LEVEL_WORD[lvl])}</div>{stats}</div>"
            f"{scale}{stype}<div class='title'>{esc(r.verdict_title)}</div><div class='summary'>{esc(r.verdict_summary)}</div>{typesum}"
            f"<div class='facts'>{facts_html}</div></div></div>")


def _count(items: list[str]) -> list[tuple[str, int]]:
    out: dict[str, int] = {}
    for x in items:
        out[x] = out.get(x, 0) + 1
    return list(out.items())


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
                c = SEVERITY.get(top[3], ACCENT2)
                dotted = top[3] == "info"
                style = (f"background:{c}2e;border-bottom:2px {'dotted' if dotted else 'solid'} {c};")
            if ps and not ts:
                cls = " class='pii'"
            elif ps:
                style += f"box-shadow: inset 0 -5px 0 -3px {ACCENT2};"
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
    items = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low / weak signal"), ("info", "Context (not scored)")]
    html_ = "".join(f"<span><i style='background:{SEVERITY[k]}'></i>{esc(lbl)}</span>" for k, lbl in items)
    if include_pii:
        html_ += f"<span><i style='background:transparent;border-bottom:2px dotted {ACCENT2};height:.4rem'></i>Personal data</span>"
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


def pill(text: str, color: str, icon: str = "") -> str:
    """A status label: always the word (and optionally an icon), never colour alone."""
    i = f"<span class='i' aria-hidden='true'>{esc(icon)}</span>" if icon else ""
    return f"<span class='tg-pill' style='color:{color}'>{i}{esc(text)}</span>"


def risk_pill(level: str) -> str:
    return pill(LEVEL_WORD.get(level, level), STATUS_TEXT.get(level, NEUTRAL), T.RISK_ICON.get(level, ""))


def sev_pill(sev: str) -> str:
    return pill(sev.capitalize(), T.SEVERITY_TEXT.get(sev, NEUTRAL), T.SEVERITY_ICON.get(sev, ""))


def check_status_pill(status: str) -> str:
    color, icon, word = CHECK_STATUS.get(status, CHECK_STATUS["not_checked"])
    return pill(word, color, icon)


def table(headers: list[str], rows: list[list[str]], *, raw_cols: tuple[int, ...] = (), muted_cols: tuple[int, ...] = ()) -> str:
    """A small HTML table; every cell is escaped unless its column is listed in ``raw_cols`` (pre-escaped HTML)."""
    head = "".join(f"<th scope='col'>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td{' class=m' if i in muted_cols else ''}>{c if i in raw_cols else esc(c)}</td>" for i, c in enumerate(row))
                   + "</tr>" for row in rows)
    return f"<div class='tg-scroll'><table class='tg-table'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def empty_state(title: str, body: str, icon: str = "◎") -> None:
    st.html(f"<div class='tg-empty' role='status'><div class='ico' aria-hidden='true'>{esc(icon)}</div><h3>{esc(title)}</h3><p>{esc(body)}</p></div>")


def risk_badge_md(level: str) -> str:
    return f":{BADGE.get(level, 'gray')}-badge[{T.RISK_ICON.get(level, '')} {LEVEL_WORD.get(level, level)}]"


def sev_badge_md(sev: str) -> str:
    return f":{SEV_BADGE.get(sev, 'gray')}-badge[{T.SEVERITY_ICON.get(sev, '')} {sev.capitalize()}]"
