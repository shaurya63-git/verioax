"""Chart helpers (Altair). Thin bars, recessive axes, direct value labels, a tooltip on every mark.

Colour jobs: risk levels use the fixed status scale (always paired with the level name on the axis, so colour is never
the only cue); single-measure category charts use one hue (series slot 1, validated on the navy surface).
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from ui import INK2, INK3, LINE, STATUS

SERIES = "#3987e5"
_AXIS = dict(labelColor=INK2, titleColor=INK3, gridColor=LINE, domainColor=LINE, tickColor=LINE, labelFont="IBM Plex Sans",
             titleFont="IBM Plex Sans", labelFontSize=12, titleFontSize=11)


def _base(chart: alt.Chart, height: int) -> alt.Chart:
    return (chart.properties(height=height, background="transparent")
            .configure_view(stroke=None).configure_axis(**_AXIS).configure_legend(labelColor=INK2, titleColor=INK3))


def hbar(data: dict[str, int], *, height: int | None = None, color: str | dict[str, str] = SERIES, label: str = "Count",
         sort: bool = True, empty: str = "Nothing to show yet", keep_zero: bool = False) -> None:
    rows = [(k, v) for k, v in data.items() if v or keep_zero]
    if not rows or not any(v for _, v in rows):
        st.caption(empty)
        return
    df = pd.DataFrame(rows, columns=["item", "value"])
    order = df.sort_values("value", ascending=False)["item"].tolist() if sort else df["item"].tolist()
    h = height or max(90, 30 * len(df) + 20)
    if isinstance(color, dict):
        enc_color = alt.Color("item:N", scale=alt.Scale(domain=list(color), range=list(color.values())), legend=None)
    else:
        enc_color = alt.value(color)
    bars = alt.Chart(df).mark_bar(cornerRadiusEnd=4, height=14).encode(
        y=alt.Y("item:N", sort=order, title=None, axis=alt.Axis(labelLimit=220, ticks=False, domain=False)),
        x=alt.X("value:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d", grid=True, labels=False, ticks=False, domain=False)),
        color=enc_color, tooltip=[alt.Tooltip("item:N", title="Item"), alt.Tooltip("value:Q", title=label)])
    text = alt.Chart(df).mark_text(align="left", dx=5, color=INK2, font="IBM Plex Sans", fontSize=12).encode(
        y=alt.Y("item:N", sort=order), x="value:Q", text="value:Q")
    st.altair_chart(_base(bars + text, h), width="stretch", theme=None)


def risk_bars(dist: dict[str, int]) -> None:
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "INCONCLUSIVE"]
    names = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical", "INCONCLUSIVE": "Inconclusive"}
    data = {names[k]: dist.get(k, 0) for k in order}
    colors = {names[k]: (STATUS[k] if k != "INCONCLUSIVE" else "#8090A8") for k in order}
    hbar(data, color=colors, sort=False, label="Scans", empty="No scans yet", keep_zero=True)


def timeline(per_day: dict[str, int]) -> None:
    if len(per_day) < 2:
        st.caption("The timeline appears after scans on at least two different days.")
        return
    df = pd.DataFrame(sorted(per_day.items()), columns=["day", "scans"])
    df["day"] = pd.to_datetime(df["day"])
    line = alt.Chart(df).mark_line(strokeWidth=2, color=SERIES).encode(
        x=alt.X("day:T", title=None, axis=alt.Axis(format="%d %b", grid=False)), y=alt.Y("scans:Q", title=None, axis=alt.Axis(tickMinStep=1)))
    pts = alt.Chart(df).mark_point(filled=True, size=70, color=SERIES).encode(
        x="day:T", y="scans:Q", tooltip=[alt.Tooltip("day:T", title="Day", format="%d %b %Y"), alt.Tooltip("scans:Q", title="Scans")])
    st.altair_chart(_base(line + pts, 200), width="stretch", theme=None)
