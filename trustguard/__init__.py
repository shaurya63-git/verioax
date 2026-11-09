"""Verioax: message, link and privacy protection (engine package ``trustguard``).

Two independent engines behind one orchestrator:

* ``trustguard.pii``  - finds personal data and replaces it with typed placeholders, then re-scans its own output.
* ``trustguard.scam`` + ``trustguard.url`` - explainable scam, hoax and link-integrity analysis.

``trustguard.engine.TrustGuardEngine`` runs them; ``trustguard.risk`` turns their findings into one documented score.
"""

__version__ = "0.1.0"
__all__ = ["TrustGuardEngine", "ScanOutcome", "__version__"]


def __getattr__(name: str):
    # Imported lazily so that `import trustguard.pii` stays light (no network or UI dependencies).
    if name in ("TrustGuardEngine", "ScanOutcome"):
        from . import engine
        return getattr(engine, name)
    raise AttributeError(name)
