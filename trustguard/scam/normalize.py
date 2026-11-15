"""Evasion-resistant view of a message, used only for indicator matching.

Scam texts dodge keyword filters with tricks that a person reads straight through: letters spaced out ("g i v i n g"),
look-alike symbols inside words ("withdr@w", "fr33"), invisible characters inside words ("fr<zero-width space>ee"),
look-alike letters from other alphabets (a Cyrillic "о" in "bоnus"), styled Unicode letters (bold or full-width "FREE")
and spelled-out dots ("nyxwin dot com").

``normalize`` returns a cleaned copy of the text plus, for every character of the copy, the position of the character
in the original it came from. A phrase found in the copy is therefore highlighted at the right place in the original.
Indicators run on the original *and* on the copy, so the copy can only add matches, never remove one.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

ZERO_WIDTH = frozenset("​‌‍⁠﻿­᠎")
# Letters from other scripts that look like Latin letters (Cyrillic, Greek). Hindi (Devanagari) is not affected.
_CONFUSABLE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ԛ": "q", "ԝ": "w", "ɡ": "g", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "ο": "o", "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ν": "v",
}
_LEET = {"@": "a", "4": "a", "3": "e", "1": "i", "0": "o", "$": "s", "5": "s", "7": "t"}
_TOKEN = re.compile(r"[A-Za-z0-9@$]+")
# single letters separated by single spaces/dots/dashes ("g i v i n g", "c a s h r o y a l e . c o m")
_SPACED = re.compile(r"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?: \. |[ ._*·•\-])){2,}[A-Za-z0-9](?![A-Za-z0-9])")
_DOT_WORD = re.compile(r"(?i)(?<=[a-z0-9])\s*(?:\s+dot\s+|\(dot\)|\[dot\]|\{dot\}|\(\.\)|\[\.\]|\{\.\})\s*(?=[a-z]{2,10}\b)")
_REPEAT = re.compile(r"([A-Za-z])\1{2,}")


@dataclass
class NormText:
    text: str
    src: list[int]                  # src[i] = index in the original text of character i of ``text``

    def span(self, start: int, end: int) -> tuple[int, int]:
        """Original-text span of the copy's [start, end)."""
        if not self.src:
            return 0, 0
        start = min(max(start, 0), len(self.src) - 1)
        end = min(max(end, start + 1), len(self.src))
        return self.src[start], self.src[end - 1] + 1


def _replace(chars: list[str], src: list[int], rx: re.Pattern, repl) -> tuple[list[str], list[int]]:
    """Apply a regex substitution to the character list while keeping the source map.

    ``repl(match)`` returns the replacement as (character, offset inside the match) pairs, so every output character
    points at the input character it stands for."""
    text = "".join(chars)
    out_c: list[str] = []
    out_s: list[int] = []
    pos = 0
    for m in rx.finditer(text):
        if m.end() == m.start():
            continue
        out_c.extend(chars[pos:m.start()])
        out_s.extend(src[pos:m.start()])
        for ch, off in repl(m):
            out_c.append(ch)
            out_s.append(src[m.start() + min(max(off, 0), m.end() - m.start() - 1)])
        pos = m.end()
    out_c.extend(chars[pos:])
    out_s.extend(src[pos:])
    return out_c, out_s


def _dot(m: re.Match) -> list[tuple[str, int]]:
    return [(".", 0)]


def _collapse_spaced(m: re.Match) -> list[tuple[str, int]]:
    g = m.group()
    out: list[tuple[str, int]] = []
    i = 0
    while i < len(g):
        if g.startswith(" . ", i):
            out.append((".", i + 1))
            i += 3
            continue
        if g[i].isalnum():
            out.append((g[i], i))
        i += 1
    return out


def _deleet(m: re.Match) -> list[tuple[str, int]]:
    tok = m.group()
    letters = sum(c.isalpha() for c in tok)
    leet = [c for c in tok if c in _LEET]
    other_digits = sum(c.isdigit() and c not in _LEET for c in tok)
    keep = letters < 2 or not leet or len(leet) > 2 or other_digits or (tok[0] in "$0123456789" and letters < 3)
    return [(c if keep else _LEET.get(c, c), i) for i, c in enumerate(tok)]


def _squeeze(m: re.Match) -> list[tuple[str, int]]:
    return [(m.group(1), 0), (m.group(1), len(m.group()) - 1)]


def normalize(text: str) -> NormText:
    chars: list[str] = []
    src: list[int] = []
    for i, c in enumerate(text):
        if c in ZERO_WIDTH:
            continue
        s = unicodedata.normalize("NFKC", c) if ord(c) > 127 else c
        for ch in s:
            chars.append(_CONFUSABLE.get(ch, ch))
            src.append(i)
    chars, src = _replace(chars, src, _DOT_WORD, _dot)
    chars, src = _replace(chars, src, _SPACED, _collapse_spaced)
    chars, src = _replace(chars, src, _TOKEN, _deleet)
    chars, src = _replace(chars, src, _REPEAT, _squeeze)
    return NormText("".join(chars), src)
