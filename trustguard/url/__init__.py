"""Engine 2b: URL integrity (static checks, guarded live inspection, threat intelligence)."""
from .parse import FoundURL, defang, extract_urls, parse, refang

__all__ = ["URLAnalyzer", "URLAnalysis", "extract_urls", "parse", "defang", "refang", "FoundURL"]


def __getattr__(name: str):
    # The analyzer depends on trustguard.intel, which itself uses url.parse: import it lazily to avoid a cycle.
    if name in ("URLAnalyzer", "URLAnalysis"):
        from . import analyzer
        return getattr(analyzer, name)
    raise AttributeError(name)
