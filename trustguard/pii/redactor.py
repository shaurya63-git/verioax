"""Redaction: typed placeholders, a separate (restricted) value map, a leak sweep and an offset map.

* Placeholders are typed, numbered and stable within a scan: the same value always becomes the same ``[PHONE_001]``,
  so a reader (or an LLM) can still follow who-did-what without seeing who. Phone numbers are compared as digits
  (``+91 98765 43210`` == ``9876543210``); a bare first or last name reuses the placeholder of the one detected person
  who has it.
* The value map is returned separately and is the only structure that holds raw values.
* The leak sweep tries to break the redacted output: it re-runs the detectors on it and searches for every removed value
  written differently (up to three separator characters between characters). Hits are added and the text is rebuilt
  from the original; anything still found after the last round marks the result ``blocked``.
* ``OffsetMap`` converts positions between the original and the redacted text, so scam findings can be highlighted on
  the redacted version too.
"""
from __future__ import annotations

import bisect
import hashlib
import hmac
import re
import secrets
from collections import defaultdict
from dataclasses import dataclass, field

from .detector import Detection, detect
from .validators import indian_mobile_digits

PLACEHOLDER_RX = re.compile(r"\[[A-Z_]+_\d{3}\]")


def normalise(entity_type: str, value: str) -> str:
    if entity_type == "PHONE":
        d = indian_mobile_digits(value)
        return d or re.sub(r"\D", "", value)
    if entity_type in ("EMAIL", "UPI_ID"):
        return value.strip().lower()
    if entity_type == "PERSON":
        return " ".join(re.findall(r"[a-z]+", value.lower()))
    return re.sub(r"[^0-9A-Za-z]", "", value).upper()


_PROCESS_KEY = secrets.token_bytes(32)        # used when no installation key is passed: fingerprints then match only within this process


def value_hash(entity_type: str, value: str, key: bytes | None = None) -> str:
    """Keyed fingerprint of a value (HMAC-SHA256 with the installation secret, 16 hex characters).

    A plain hash would be reversible here: there are only 10^10 ten-digit phone numbers, and every candidate can be hashed
    in minutes. With a secret key, a stored report or history row cannot be turned back into the value, while the same
    value still gets the same fingerprint across scans on one installation.
    """
    msg = f"{entity_type}:{normalise(entity_type, value)}".encode()
    return hmac.new(key or _PROCESS_KEY, msg, hashlib.sha256).hexdigest()[:16]


class PlaceholderRegistry:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], str] = {}
        self._counter: dict[str, int] = defaultdict(int)
        self.entries: dict[str, dict] = {}              # placeholder -> {type, values, occurrences}

    def get(self, entity_type: str, value: str) -> str:
        key = (entity_type, normalise(entity_type, value))
        ph = self._by_key.get(key)
        if ph is None and entity_type == "PERSON" and len(value.split()) == 1:
            ph = self._person_alias(key[1])
        if ph is None:
            self._counter[entity_type] += 1
            ph = f"[{entity_type}_{self._counter[entity_type]:03d}]"
            self.entries[ph] = {"placeholder": ph, "type": entity_type, "values": [], "occurrences": 0}
        self._by_key[key] = ph
        entry = self.entries[ph]
        entry["occurrences"] += 1
        if value not in entry["values"]:
            entry["values"].append(value)
        return ph

    def _person_alias(self, token: str) -> str | None:
        owners = {ph for ph, e in self.entries.items() if e["type"] == "PERSON"
                  for v in e["values"] if token in normalise("PERSON", v).split() and len(v.split()) > 1}
        return owners.pop() if len(owners) == 1 else None

    def value_map(self) -> list[dict]:
        """RESTRICTED: placeholder -> raw values. Never put this in a report or the scan history."""
        return [dict(e) for e in sorted(self.entries.values(), key=lambda e: (e["type"], e["placeholder"]))]


@dataclass
class OffsetMap:
    """Original <-> redacted positions for one replacement pass (non-overlapping, sorted replacements)."""
    spans: list[tuple[int, int, int, int]] = field(default_factory=list)   # (orig_start, orig_end, red_start, red_end)

    def to_redacted(self, pos: int, *, end: bool = False) -> int:
        starts = [s[0] for s in self.spans]
        i = bisect.bisect_right(starts, pos) - 1
        if i < 0:
            return pos
        os_, oe, rs, re_ = self.spans[i]
        if pos < oe and pos >= os_:
            return re_ if end else rs                    # inside a replaced value -> snap to the placeholder
        return pos + (re_ - oe)

    def to_original(self, pos: int, *, end: bool = False) -> int:
        starts = [s[2] for s in self.spans]
        i = bisect.bisect_right(starts, pos) - 1
        if i < 0:
            return pos
        os_, oe, rs, re_ = self.spans[i]
        if rs <= pos < re_:
            return oe if end else os_
        return pos - (re_ - oe)


def _apply(text: str, items: list[tuple[int, int, str]]) -> tuple[str, OffsetMap]:
    """Replace (start, end, placeholder) items; overlapping items are merged under the longer span's placeholder."""
    merged: list[list] = []
    for s, e, ph in sorted(items, key=lambda x: (x[0], -x[1])):
        if merged and s < merged[-1][1]:
            prev = merged[-1]
            if (e - s) > (prev[1] - prev[0]):
                prev[2] = ph
            prev[1] = max(prev[1], e)
        else:
            merged.append([s, e, ph])
    out, spans, pos, shift = [], [], 0, 0
    for s, e, ph in merged:
        out.append(text[pos:s])
        rs = s + shift
        out.append(ph)
        spans.append((s, e, rs, rs + len(ph)))
        shift += len(ph) - (e - s)
        pos = e
    out.append(text[pos:])
    return "".join(out), OffsetMap(spans)


def _tolerant_pattern(value: str) -> re.Pattern | None:
    chars = [c for c in value if c.isalnum() or c == "@"]
    if len(chars) < 5:
        return None
    return re.compile(r"[^A-Za-z0-9@]{0,3}".join(re.escape(c) for c in chars), re.I)


@dataclass
class Redaction:
    redacted_text: str
    detections: list[Detection]                          # final set, incl. sweep catches
    origins: list[str]                                   # "detector" | "leak_sweep" per detection
    placeholders: list[str]                              # placeholder per detection
    registry: PlaceholderRegistry
    offset_map: OffsetMap
    sweep_rounds: list[dict[str, int]]
    caught_by_sweep: int
    residual: int
    residual_types: list[str]


def redact(text: str, detections: list[Detection], *, min_confidence: float = 0.5, sweep_rounds: int = 2,
           use_ner: bool = True) -> Redaction:
    reg = PlaceholderRegistry()
    dets = list(detections)
    origins = ["detector"] * len(dets)
    phs = [reg.get(d.type, d.text) for d in dets]
    redacted, omap = _apply(text, [(d.start, d.end, ph) for d, ph in zip(dets, phs, strict=True)])

    rounds: list[dict[str, int]] = []
    residual: list[Detection] = []
    for r in range(sweep_rounds + 1):
        hits = _sweep(redacted, omap, text, reg, dets, min_confidence, use_ner)
        rounds.append({"round": r, "hits": len(hits)})
        residual = hits
        if not hits or r == sweep_rounds:
            break
        for h in hits:
            dets.append(h)
            origins.append("leak_sweep")
            phs.append(reg.get(h.type, h.text))
        redacted, omap = _apply(text, [(d.start, d.end, ph) for d, ph in zip(dets, phs, strict=True)])
    caught = origins.count("leak_sweep")
    return Redaction(redacted, dets, origins, phs, reg, omap, rounds, caught, len(residual), sorted({h.type for h in residual}))


def _sweep(redacted: str, omap: OffsetMap, original: str, reg: PlaceholderRegistry, known: list[Detection],
           min_confidence: float, use_ner: bool) -> list[Detection]:
    """Find PII still readable in `redacted`; return it as detections in ORIGINAL coordinates."""
    hits: list[Detection] = []
    taken = [(d.start, d.end) for d in known]

    def add(rs: int, re_: int, typ: str, conf: float, det: str) -> None:
        if PLACEHOLDER_RX.fullmatch(redacted[rs:re_].strip()):
            return
        os_, oe = omap.to_original(rs), omap.to_original(re_, end=True)
        if oe <= os_ or any(os_ < e and s < oe for s, e in taken):
            return
        taken.append((os_, oe))
        hits.append(Detection(typ, os_, oe, original[os_:oe], conf, [det]))

    # (a) the detectors themselves, run on the output (placeholders hidden so they are not read as names)
    masked = PLACEHOLDER_RX.sub(lambda m: "#" * len(m.group()), redacted)
    for d in detect(masked, min_confidence=min_confidence, use_ner=use_ner):
        if "#" not in d.text:
            add(d.start, d.end, d.type, d.confidence, "sweep:" + d.detectors[0])
    # (b) every removed value, written with different separators ('98765-43210' after '9876543210' was removed)
    for entry in reg.entries.values():
        for v in entry["values"]:
            rx = _tolerant_pattern(v)
            if rx:
                for m in rx.finditer(redacted):
                    add(m.start(), m.end(), entry["type"], 0.99, "sweep:known-value")
    return hits
