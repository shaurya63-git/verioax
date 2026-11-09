"""Internal finding record shared by the scam, sender, URL and combination analysers before final numbering.

``RawFinding`` keeps original-text offsets; ``trustguard.engine`` converts it into the public, redaction-safe
``ScamFinding`` (adds the id, the excerpt from the redacted text and the redacted offsets).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .schemas import ScamCategory, Severity, Strength

SEV_ORDER = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
STR_ORDER = {Strength.WEAK: 0, Strength.STRONG: 1, Strength.CONFIRMED: 2}


@dataclass
class RawFinding:
    indicator: str
    category: ScamCategory
    title: str
    severity: Severity
    strength: Strength
    confidence: float
    explanation: str
    action: str = ""
    source: str = "message"            # message | sender | url | page | intel | combination | file
    start: int | None = None
    end: int | None = None
    evidence: list[str] = field(default_factory=list)
    url_id: str | None = None
    more_spans: list[tuple[int, int]] = field(default_factory=list)   # other places the same indicator matched (scored once)

    def rank(self) -> tuple[int, int, float]:
        return (SEV_ORDER[self.severity], STR_ORDER[self.strength], self.confidence)
