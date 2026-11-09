"""Adapters between the UI and the engines. The UI never imports detection code directly - it talks to a client.

* ``LocalClient`` runs the engine in the same process (default; nothing leaves the machine except the live link checks
  and API lookups you enable).
* ``APIClient`` talks to the FastAPI backend (set TRUSTGUARD_API_URL, as docker-compose does).

Both return ``ClientScan(result, original_text)``. ``original_text`` is the content the user submitted (or the text
extracted from their file) and is kept in the browser session only, for the highlighted "original" views.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from trustguard.config import Preferences, get_settings, save_preferences
from trustguard.schemas import AnalysisMode, ScanResult


class ClientError(Exception):
    """A user-facing error (bad input, backend unavailable)."""


@dataclass
class ClientScan:
    result: ScanResult
    original_text: str | None


class Client(Protocol):
    kind: str
    def scan_message(self, text: str, sender: str | None, mode: AnalysisMode, demo: bool = False) -> ClientScan: ...
    def scan_url(self, url: str) -> ClientScan: ...
    def scan_file(self, name: str, data: bytes, mode: AnalysisMode) -> ClientScan: ...
    def list_scans(self, **filters) -> list[dict]: ...
    def get_scan(self, scan_id: str) -> ScanResult | None: ...
    def delete_scan(self, scan_id: str) -> bool: ...
    def results(self, limit: int = 1000) -> list[ScanResult]: ...
    def report(self, scan_id: str, fmt: str) -> bytes: ...
    def intel_status(self) -> list[dict]: ...
    def test_provider(self, name: str) -> dict: ...
    def get_prefs(self) -> Preferences: ...
    def save_prefs(self, prefs: Preferences) -> None: ...


class LocalClient:
    kind = "local"

    def __init__(self):
        from trustguard.engine import TrustGuardEngine
        self.engine = TrustGuardEngine()

    def _wrap(self, fn, *a, **k) -> ClientScan:
        from trustguard.engine import InputError
        try:
            out = fn(*a, **k)
        except InputError as exc:
            raise ClientError(str(exc)) from None
        return ClientScan(out.result, out.restricted.original_text)

    def scan_message(self, text, sender, mode, demo=False):
        return self._wrap(self.engine.scan_message, text, sender=sender or None, mode=mode, demo=demo)

    def scan_url(self, url):
        return self._wrap(self.engine.scan_url, url)

    def scan_file(self, name, data, mode):
        return self._wrap(self.engine.scan_file, name, data, mode=mode)

    def list_scans(self, **filters):
        return self.engine.store.list(**filters) if self.engine.store else []

    def get_scan(self, scan_id):
        return self.engine.store.get(scan_id) if self.engine.store else None

    def delete_scan(self, scan_id):
        return bool(self.engine.store and self.engine.store.delete(scan_id))

    def results(self, limit=1000):
        return self.engine.store.results(limit) if self.engine.store else []

    def report(self, scan_id, fmt):
        from trustguard import reports
        r = self.get_scan(scan_id)
        if r is None:
            raise ClientError("Scan not found.")
        return _report_bytes(r, fmt, reports)

    def intel_status(self):
        return self.engine.hub.status()

    def test_provider(self, name):
        return self.engine.hub.test(name)

    def get_prefs(self):
        return self.engine.prefs

    def save_prefs(self, prefs):
        save_preferences(prefs, self.engine.settings)
        self.engine.update_preferences(prefs)

    # local-only extras (the IOC list lives with the engine)
    def add_ioc(self, indicator: str) -> None:
        self.engine.hub.add_ioc(indicator)

    def remove_ioc(self, indicator: str) -> bool:
        return self.engine.hub.remove_ioc(indicator)

    def user_iocs(self) -> list[str]:
        return self.engine.hub.user_iocs()

    def seed_ioc_count(self) -> int:
        return len(self.engine.hub.local.entries) - len(self.user_iocs())

    def clear_history(self, demo_only: bool = False) -> int:
        return self.engine.store.clear(demo_only=demo_only) if self.engine.store else 0

    def clear_cache(self) -> int:
        return self.engine.cache.clear()


def _report_bytes(r: ScanResult, fmt: str, reports) -> bytes:
    if fmt == "pdf":
        return reports.to_pdf(r)
    return {"json": reports.to_json, "csv": reports.findings_csv, "md": reports.to_markdown}[fmt](r).encode("utf-8")


class APIClient:
    kind = "api"

    def __init__(self, base_url: str, token: str | None = None):
        self.base = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.http = httpx.Client(base_url=self.base, headers=self.headers, timeout=90)

    def _call(self, method: str, path: str, **kw):
        try:
            r = self.http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise ClientError(f"The TrustGuard API at {self.base} is not reachable ({type(exc).__name__}).") from None
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except ValueError:
                detail = r.text[:200]
            if isinstance(detail, list):                       # FastAPI validation errors
                detail = "; ".join(d.get("msg", "") for d in detail)
            raise ClientError(str(detail or f"HTTP {r.status_code}"))
        return r

    def scan_message(self, text, sender, mode, demo=False):
        r = self._call("POST", "/v1/scan/message", json={"text": text, "sender": sender or None, "mode": mode.value, "demo": demo})
        return ClientScan(ScanResult.model_validate(r.json()), text)

    def scan_url(self, url):
        r = self._call("POST", "/v1/scan/url", json={"url": url})
        return ClientScan(ScanResult.model_validate(r.json()), url)

    def scan_file(self, name, data, mode):
        r = self._call("POST", "/v1/scan/file", files={"file": (name, data)}, data={"mode": mode.value})
        return ClientScan(ScanResult.model_validate(r.json()), None)       # the extracted text stays on the server

    def list_scans(self, **filters):
        params = {k: v for k, v in filters.items() if v not in (None, [], "")}
        for k in ("since", "until"):
            if k in params:
                params[k] = params[k].isoformat()
        return self._call("GET", "/v1/scans", params=params).json()

    def get_scan(self, scan_id):
        try:
            return ScanResult.model_validate(self._call("GET", f"/v1/scans/{scan_id}").json())
        except ClientError:
            return None

    def delete_scan(self, scan_id):
        try:
            self._call("DELETE", f"/v1/scans/{scan_id}")
            return True
        except ClientError:
            return False

    def results(self, limit=1000):
        rows = self.list_scans(limit=limit)
        return [r for r in (self.get_scan(x["scan_id"]) for x in rows) if r]

    def report(self, scan_id, fmt):
        return self._call("GET", f"/v1/scans/{scan_id}/report.{fmt}").content

    def intel_status(self):
        return self._call("GET", "/v1/intel/status").json()

    def test_provider(self, name):
        return self._call("POST", f"/v1/intel/test/{name}").json()

    def get_prefs(self):
        return Preferences.model_validate(self._call("GET", "/v1/preferences").json())

    def save_prefs(self, prefs):
        self._call("PUT", "/v1/preferences", json=prefs.model_dump())


def make_client() -> Client:
    s = get_settings()
    if s.api_url:
        return APIClient(s.api_url, s.api_token.get_secret_value() if s.api_token else None)
    return LocalClient()
