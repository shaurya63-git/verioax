"""Shared, cached objects for all pages."""
from __future__ import annotations

import streamlit as st

from client import make_client


@st.cache_resource(show_spinner=False)
def client():
    return make_client()


def ocr_available() -> bool:
    from trustguard.extract import ocr_available as _ocr
    return _ocr()
