"""Verioax design tokens - the one place where colours, type, radii, shadows and motion are defined.

* ``ui.py`` builds all custom CSS from these tokens (as CSS variables), and the pages use the named constants.
* Streamlit reads its own widget theme from ``.streamlit/config.toml``. That file is generated from these tokens:
  after changing a value here run ``python scripts/sync_theme.py``. ``tests/test_theme.py`` fails while the two
  disagree, and checks every text/background pair the UI uses against WCAG AA.

Colour is never the only carrier of meaning: every risk level and severity is shown with its word and an icon too.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------------------------- palette
COLORS: dict[str, str] = {
    "bg": "#0B1220",            # main background
    "surface": "#111C2E",       # cards, panels, sidebar
    "surface_2": "#17243A",     # raised: inputs, table headers, hover, code
    "border": "#29384F",        # dividers and card outlines (decorative)
    "control": "#64748B",       # outlines of form controls (WCAG 1.4.11: at least 3:1 against the background)
    "text": "#E6EDF7",          # primary text
    "text_muted": "#94A3B8",    # secondary text
    "accent": "#20C9B5",        # electric teal: primary actions, focus rings, active tab
    "accent_2": "#38BDF8",      # cyan: links, information, personal-data marks
    "on_accent": "#0B1220",     # text on teal buttons (white on teal fails contrast)
    "placeholder": "#7DD3FC",   # redaction placeholders such as [PHONE_1] in redacted text
}

# risk levels: the bar/rail colour, and a text-safe variant for small text on raised surfaces
RISK: dict[str, str] = {"LOW": "#22C55E", "MEDIUM": "#FBBF24", "HIGH": "#FB923C", "CRITICAL": "#F43F5E", "INCONCLUSIVE": "#94A3B8"}
RISK_TEXT: dict[str, str] = RISK | {"CRITICAL": "#F6657E"}
RISK_WORD: dict[str, str] = {"LOW": "Low risk", "MEDIUM": "Medium risk", "HIGH": "High risk", "CRITICAL": "Critical risk",
                             "INCONCLUSIVE": "Inconclusive"}
RISK_ICON: dict[str, str] = {"LOW": "✓", "MEDIUM": "!", "HIGH": "▲", "CRITICAL": "✕", "INCONCLUSIVE": "?"}

SEVERITY: dict[str, str] = {"critical": RISK["CRITICAL"], "high": RISK["HIGH"], "medium": RISK["MEDIUM"], "low": COLORS["text_muted"],
                            "info": COLORS["accent_2"]}
SEVERITY_TEXT: dict[str, str] = SEVERITY | {"critical": RISK_TEXT["CRITICAL"]}
SEVERITY_ICON: dict[str, str] = {"critical": "✕", "high": "▲", "medium": "!", "low": "•", "info": "i"}

# link checks / service states
CHECK: dict[str, tuple[str, str, str]] = {"pass": (RISK["LOW"], "✓", "No issue"), "warn": (RISK["MEDIUM"], "!", "Suspicious"),
                                          "fail": (RISK["CRITICAL"], "✕", "Threat indicator"), "info": (COLORS["accent_2"], "i", "Note"),
                                          "unavailable": (COLORS["text_muted"], "–", "Not checked")}
OK, WARN, BAD, NEUTRAL, INFO = RISK["LOW"], RISK["MEDIUM"], RISK_TEXT["CRITICAL"], COLORS["text_muted"], COLORS["accent_2"]

# Streamlit's built-in badge colours (st.badge / :color-badge[]) - mapped onto the palette in config.toml
BADGE: dict[str, str] = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "orange", "CRITICAL": "red", "INCONCLUSIVE": "gray"}
SEV_BADGE: dict[str, str] = {"critical": "red", "high": "orange", "medium": "yellow", "low": "gray", "info": "blue"}

# charts: categorical slots in a fixed order (teal, cyan, amber, orange, rose, green, muted) and a teal ramp
CHART_SERIES: list[str] = [COLORS["accent"], COLORS["accent_2"], RISK["MEDIUM"], RISK["HIGH"], RISK["CRITICAL"], RISK["LOW"], COLORS["text_muted"]]
CHART_SEQUENTIAL: list[str] = ["#0F3B3B", "#11504D", "#14665F", "#177C72", "#1A9284", "#1DA897", "#20C9B5", "#5AD6C7", "#93E4DA", "#C9F2EC"]

# ---------------------------------------------------------------------------------------------- type, shape, motion
FONT_SANS = "IBM Plex Sans"
FONT_MONO = "IBM Plex Mono"
RADIUS = {"sm": "6px", "md": "10px", "lg": "14px", "pill": "999px"}
SHADOW = {"card": "0 1px 2px rgba(2, 6, 15, .45), 0 10px 28px -16px rgba(2, 6, 15, .75)",
          "raised": "0 2px 6px rgba(2, 6, 15, .5), 0 16px 36px -18px rgba(2, 6, 15, .8)"}
MOTION = "140ms cubic-bezier(.2, .7, .3, 1)"


# ---------------------------------------------------------------------------------------------- helpers
def rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r}, {g}, {b}, {alpha})"


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")

    def ch(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(fg: str, bg: str) -> float:
    """WCAG 2.x contrast ratio between two colours (1 to 21)."""
    a, b = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


def css_variables() -> str:
    names = {f"--vx-{k.replace('_', '-')}": v for k, v in COLORS.items()}
    names |= {f"--vx-risk-{k.lower()}": v for k, v in RISK.items()}
    names |= {f"--vx-radius-{k}": v for k, v in RADIUS.items()}
    names |= {f"--vx-shadow-{k}": v for k, v in SHADOW.items()}
    names |= {"--vx-motion": MOTION, "--vx-font": f'"{FONT_SANS}", system-ui, sans-serif', "--vx-mono": f'"{FONT_MONO}", ui-monospace, monospace'}
    return ":root { " + " ".join(f"{k}: {v};" for k, v in names.items()) + " }"


def streamlit_theme() -> dict[str, dict[str, object]]:
    """The [theme] and [theme.sidebar] values of .streamlit/config.toml, derived from the tokens above."""
    c = COLORS
    return {
        "theme": {
            "base": "dark", "primaryColor": c["accent"], "backgroundColor": c["bg"], "secondaryBackgroundColor": c["surface_2"],
            "textColor": c["text"], "borderColor": c["border"], "linkColor": c["accent_2"], "codeBackgroundColor": c["surface_2"],
            "codeTextColor": "#BAE6FD", "dataframeBorderColor": c["border"], "dataframeHeaderBackgroundColor": c["surface_2"],
            "greenColor": RISK["LOW"], "yellowColor": RISK["MEDIUM"], "orangeColor": RISK["HIGH"], "redColor": RISK["CRITICAL"],
            "blueColor": c["accent_2"], "grayColor": c["text_muted"],
            "chartCategoricalColors": CHART_SERIES, "chartSequentialColors": CHART_SEQUENTIAL,
        },
        "theme.sidebar": {"backgroundColor": c["surface"], "secondaryBackgroundColor": c["surface_2"], "borderColor": c["border"]},
    }
