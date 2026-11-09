"""Threat-intelligence hub: one place that knows which providers exist, which are configured, and whether each one has
actually been tested from this installation (an API key that was never exercised is reported as 'configured, untested')."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from ..cache import TTLCache
from ..config import Preferences, Settings
from ..schemas import IntelResult
from .providers import FactCheck, LocalIOC, OpenPhish, PhishTank, SafeBrowsing, URLhaus, VirusTotal

ROOT = Path(__file__).resolve().parents[2]
SEED_IOCS = ROOT / "data" / "iocs"

# URLs used by the "Test connection" button. Google publishes a test URL that its lists always flag.
TEST_URLS = {"google_safe_browsing": "http://malware.testing.google.test/testing/malware/", "default": "https://www.google.com/"}


def _secret(v) -> str | None:
    return v.get_secret_value() if v is not None else None


class IntelHub:
    def __init__(self, settings: Settings, prefs: Preferences, cache: TTLCache | None = None, transport: httpx.BaseTransport | None = None):
        self.settings, self.prefs, self.cache = settings, prefs, cache
        data_dir = Path(settings.data_dir)
        self.user_ioc_file = data_dir / "iocs_user.txt"
        self.status_file = data_dir / "intel_status.json"
        kw = {"cache": cache, "transport": transport, "timeout_s": settings.fetch_timeout_s}
        self.local = LocalIOC(sorted(SEED_IOCS.glob("*.txt")) + [self.user_ioc_file])
        self.url_providers = [
            self.local,
            SafeBrowsing(_secret(settings.google_safe_browsing_key), **kw),
            VirusTotal(_secret(settings.virustotal_key), **kw),
            URLhaus(_secret(settings.urlhaus_key), **kw),
            PhishTank(_secret(settings.phishtank_app_key), settings.phishtank_username, **kw),
            OpenPhish(settings.openphish_feed_url, prefs.openphish_feed, **kw),
        ]
        self.factcheck = FactCheck(_secret(settings.factcheck_key), cache=cache, transport=transport, timeout_s=settings.fetch_timeout_s)

    # ------------------------------------------------------------------ lookups
    def lookup(self, url: str, *, network: bool) -> list[IntelResult]:
        out = []
        for p in self.url_providers:
            if p is self.local:
                out.append(p.lookup(url))
            elif not network or not self.prefs.intel_lookups:
                out.append(IntelResult(provider=p.name, status="disabled" if p.configured() else "not_configured", mode="none",
                                       verdict="Local processing mode: online lookups are off" if p.configured() else ""))
            else:
                out.append(p.lookup(url))
        return out

    # ------------------------------------------------------------------ status for the UI
    def status_of(self, name: str) -> bool:
        """True when the provider is configured (and, for feeds, enabled)."""
        p = next((x for x in self.url_providers if x.name == name), None)
        return bool(p and p.configured())

    def _tests(self) -> dict:
        try:
            return json.loads(self.status_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def status(self) -> list[dict]:
        tests = self._tests()
        rows = []
        for p in self.url_providers + [self.factcheck]:
            configured = p.configured()
            t = tests.get(p.name, {})
            if p is self.local:
                state = f"active ({len(self.local.entries)} indicators)"
            elif not configured and p.name == "openphish":
                state = "turned off"
            elif not configured:
                state = "not configured"
            elif t.get("ok"):
                state = "working (tested)"
            elif t:
                state = "error on last test"
            else:
                state = "configured, not tested yet"
            rows.append({"provider": p.name, "label": p.label, "configured": configured, "state": state,
                         "mode": "local" if p is self.local else ("feed (cached)" if p.name == "openphish" else "live API"),
                         "last_test": t.get("at"), "last_result": t.get("result", ""), "signup": getattr(p, "signup_url", "")})
        return rows

    def test(self, name: str) -> dict:
        p = next((x for x in self.url_providers + [self.factcheck] if x.name == name), None)
        if p is None:
            raise KeyError(name)
        if not p.configured():
            return {"ok": False, "result": "not configured"}
        if p is self.factcheck:
            refs = p.search("fake e-challan message", limit=1)
            ok = refs is not None
            result = f"OK - {len(refs)} result(s)" if ok else "request failed"
        else:
            if self.cache is not None:
                self.cache.clear(f"intel:{p.name}:")
            res = p.lookup(TEST_URLS.get(p.name, TEST_URLS["default"]))
            ok = res.status not in ("error", "not_configured", "unavailable")
            result = f"{res.status}: {res.verdict}"[:200]
        tests = self._tests()
        tests[p.name] = {"ok": ok, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "result": result}
        self.status_file.parent.mkdir(parents=True, exist_ok=True)
        self.status_file.write_text(json.dumps(tests, indent=1), encoding="utf-8")
        return tests[p.name]

    # ------------------------------------------------------------------ local IOC management
    def add_ioc(self, indicator: str, note: str = "added by user") -> None:
        self.user_ioc_file.parent.mkdir(parents=True, exist_ok=True)
        with self.user_ioc_file.open("a", encoding="utf-8") as f:
            f.write(f"{indicator.strip()}  # {note}\n")
        self.local.reload()

    def remove_ioc(self, indicator: str) -> bool:
        if not self.user_ioc_file.exists():
            return False
        lines = self.user_ioc_file.read_text(encoding="utf-8").splitlines()
        keep = [ln for ln in lines if ln.split("#")[0].strip().lower() != indicator.strip().lower()]
        self.user_ioc_file.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
        self.local.reload()
        return len(keep) != len(lines)

    def user_iocs(self) -> list[str]:
        if not self.user_ioc_file.exists():
            return []
        return [ln.split("#")[0].strip() for ln in self.user_ioc_file.read_text(encoding="utf-8").splitlines() if ln.split("#")[0].strip()]
