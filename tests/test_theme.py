"""Design tokens: the requested palette, WCAG AA contrast for every text/background pair the UI uses, Streamlit's
config.toml generated from the tokens, no stray colour literals in the pages, and risk never shown by colour alone."""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT / "app"), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.append(p)

import theme as T  # noqa: E402

TEXT_BGS = ("bg", "surface", "surface_2")


def test_palette_is_the_requested_one():
    c = T.COLORS
    assert (c["bg"], c["surface"], c["surface_2"], c["border"]) == ("#0B1220", "#111C2E", "#17243A", "#29384F")
    assert (c["text"], c["text_muted"], c["accent"], c["accent_2"]) == ("#E6EDF7", "#94A3B8", "#20C9B5", "#38BDF8")
    assert T.RISK == {"LOW": "#22C55E", "MEDIUM": "#FBBF24", "HIGH": "#FB923C", "CRITICAL": "#F43F5E", "INCONCLUSIVE": "#94A3B8"}


@pytest.mark.parametrize("fg", ["text", "text_muted", "accent", "accent_2", "placeholder"])
@pytest.mark.parametrize("bg", TEXT_BGS)
def test_text_tokens_meet_wcag_aa(fg, bg):
    assert T.contrast(T.COLORS[fg], T.COLORS[bg]) >= 4.5


@pytest.mark.parametrize("level", list(T.RISK_TEXT))
@pytest.mark.parametrize("bg", TEXT_BGS)
def test_risk_text_colours_meet_wcag_aa(level, bg):
    assert T.contrast(T.RISK_TEXT[level], T.COLORS[bg]) >= 4.5


@pytest.mark.parametrize("sev", list(T.SEVERITY_TEXT))
@pytest.mark.parametrize("bg", TEXT_BGS)
def test_severity_text_colours_meet_wcag_aa(sev, bg):
    assert T.contrast(T.SEVERITY_TEXT[sev], T.COLORS[bg]) >= 4.5


def test_buttons_and_icons_on_colour_meet_wcag_aa():
    assert T.contrast(T.COLORS["on_accent"], T.COLORS["accent"]) >= 4.5            # teal primary button label
    for colour in T.RISK.values():                                                  # icon glyphs drawn on the risk colour
        assert T.contrast(T.COLORS["bg"], colour) >= 4.5
    assert T.contrast("#FFFFFF", T.COLORS["accent"]) < 4.5                          # why the button text is dark, not white


@pytest.mark.parametrize("bg", TEXT_BGS)
def test_form_control_outlines_and_risk_rails_meet_non_text_contrast(bg):
    assert T.contrast(T.COLORS["control"], T.COLORS[bg]) >= 3.0                   # WCAG 1.4.11
    for colour in T.RISK.values():
        assert T.contrast(colour, T.COLORS[bg]) >= 3.0


def test_streamlit_config_is_generated_from_the_tokens():
    import sync_theme
    current = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    assert sync_theme.render(current) == current, "run: python scripts/sync_theme.py"
    assert 'primaryColor = "#20C9B5"' in current and "maxUploadSize = 50" in current


def test_pages_use_tokens_not_colour_literals():
    stray = []
    for f in list((ROOT / "app").glob("*.py")) + list((ROOT / "app" / "views").glob("*.py")):
        if f.name == "theme.py":
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"#[0-9A-Fa-f]{6}\b", line):
                stray.append(f"{f.relative_to(ROOT)}:{n}")
    assert not stray, f"colour literals outside app/theme.py: {stray}"


def test_every_level_and_severity_has_a_word_and_an_icon():
    for level in T.RISK:
        assert T.RISK_WORD[level] and T.RISK_ICON[level]
    for sev in T.SEVERITY:
        assert T.SEVERITY_ICON[sev]
    css = T.css_variables()
    assert "--vx-accent: #20C9B5" in css and "--vx-risk-critical: #F43F5E" in css


def test_verdict_panel_shows_level_word_icon_score_confidence_and_type(engine):
    from conftest import ECHALLAN_SCAM

    import ui
    r = engine.scan_message(ECHALLAN_SCAM).result
    html = ui.verdict_panel(r)
    assert T.RISK_WORD[r.overall_risk.value] in html and T.RISK_ICON[r.overall_risk.value] in html
    assert f"<b>{r.risk_score}</b>" in html and "Confidence" in html and r.confidence_label in html
    assert r.scam_type_label and r.scam_type_label in html
    assert "not a probability" in html                                             # confidence is explained, not over-claimed
