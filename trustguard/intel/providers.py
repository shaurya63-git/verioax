"""Threat-intelligence and verification providers.

Every provider reports *how* it knows something (``mode``): ``live`` (API call made now), ``cache`` (an earlier live
answer still within its TTL, or a downloaded feed), ``local`` (Verioax's own IOC list). A provider without a key says
``not_configured``; a failed call says ``error`` - it never pretends a URL is clean.

Privacy: lookups send the URL to the provider. ``trustguard.url.analyzer`` strips query parameters that carry personal
data before any lookup.

Resilience (``resilience.py``): every outside call goes through the provider's guard - a shared connection pool, a cap
on parallel calls, a circuit breaker and one retry for connection failures. A provider that is down or overloaded is
reported as ``unavailable``; it is never treated as "not listed".
"""
from __future__ import annotations

import base64
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import httpx

from ..cache import TTLCache
from ..schemas import FactCheckRef, IntelResult
from ..url.parse import refang
from .resilience import Resilience, call_with_retry, outcome_of

USER_AGENT = "Verioax/0.1 (+https://github.com/)"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class URLProvider(Protocol):
    name: str
    label: str
    signup_url: str

    def configured(self) -> bool: ...
    def lookup(self, url: str) -> IntelResult: ...


class _Base:
    name = "base"
    label = "Base"
    signup_url = ""
    attribution = ""
    ttl_s = 3600

    def __init__(self, cache: TTLCache | None = None, transport: httpx.BaseTransport | None = None, timeout_s: float = 8.0,
                 res: Resilience | None = None):
        self.cache = cache
        self.transport = transport
        self.timeout_s = timeout_s
        self.res = res or Resilience()

    def configured(self) -> bool:
        return True

    def _client(self) -> httpx.Client:
        """The provider's shared connection pool (thread-safe; never closed per call)."""
        return self.res.client((self.name, self.timeout_s, id(self.transport)), lambda: httpx.Client(
            timeout=self.timeout_s, transport=self.transport, headers={"User-Agent": USER_AGENT},
            limits=httpx.Limits(max_connections=self.res.max_parallel * 2, max_keepalive_connections=self.res.max_parallel)))

    def lookup(self, url: str) -> IntelResult:
        if not self.configured():
            return IntelResult(provider=self.name, status="not_configured", mode="none", attribution=self.attribution)
        key = f"intel:{self.name}:{url}"
        if self.cache is not None:
            hit = self.cache.get(key)
            if hit:
                res = IntelResult.model_validate(hit)
                res.mode = "cache"
                return res
        res, failed = guarded(self.res, self.name, self.timeout_s, lambda: self._lookup(url))
        if failed is not None:
            return failed.model_copy(update={"attribution": self.attribution})
        if res.status == "error":
            return res
        if self.cache is not None and res.status in ("listed", "suspicious", "clean", "not_found"):
            self.cache.set(key, res.model_dump(mode="json"), self.ttl_s)
        return res

    def _lookup(self, url: str) -> IntelResult:  # pragma: no cover - abstract
        raise NotImplementedError


SKIPPED = {"circuit_open": "Skipped for now: this service failed several times in a row. Verioax tries it again automatically "
                           "within a minute. Not being checked here is not evidence that the link is safe.",
           "busy": "Skipped: too many lookups to this service are already in progress. Not being checked here is not evidence "
                   "that the link is safe."}


def guarded(res: Resilience, name: str, timeout_s: float, fn):
    """Run one outside call under the provider's guard. Returns (value, None), or (None, IntelResult) when the call was
    skipped or failed - the IntelResult says which, without any URL, key or exception message in it."""
    g = res.guard(name)
    skipped = g.begin(wait_s=min(2.0, timeout_s))
    if skipped:
        return None, IntelResult(provider=name, status="unavailable", mode="none", verdict=SKIPPED[skipped], checked_at=_now())
    t = time.perf_counter()
    try:
        value = call_with_retry(fn)
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        g.end(outcome_of(exc), time.perf_counter() - t, type(exc).__name__)
        return None, IntelResult(provider=name, status="error", mode="live", verdict=_err(exc), checked_at=_now())
    bad = isinstance(value, IntelResult) and value.status == "error"
    g.end("error" if bad else "ok", time.perf_counter() - t, "bad_answer" if bad else "")
    return value, None


_URLISH = re.compile(r"(?i)\b(?:https?://|www\.)\S+|\b[\w-]+(?:\.[\w-]+)+(?:/\S*)?")
_SECRETISH = re.compile(r"(?i)\b(key|token|app_key|apikey|auth)=\S+")


def _err(exc: Exception) -> str:
    """A short reason for the user and the logs: an HTTP status, or the kind of failure - never the request URL (which
    holds the looked-up link and, for some providers, the API key) and never the server's own error text."""
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return {401: "API key rejected (401)", 403: "access denied (403)", 429: "rate limit reached (429)"}.get(code, f"HTTP {code}")
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.ConnectError):
        return "could not connect"
    if isinstance(exc, (ValueError, KeyError, TypeError)):
        return "unexpected answer from the service"
    msg = _SECRETISH.sub(r"\1=[redacted]", (str(exc) or type(exc).__name__).splitlines()[0])
    return _URLISH.sub("[address]", msg)[:140]


# ----------------------------------------------------------------------------------------------- Google Safe Browsing (v4 Lookup API)
class SafeBrowsing(_Base):
    name, label = "google_safe_browsing", "Google Safe Browsing"
    signup_url = "https://developers.google.com/safe-browsing/v4/get-started"
    attribution = "Advisory provided by Google (https://developers.google.com/safe-browsing/v4/advisory)"
    THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

    def __init__(self, api_key: str | None, **kw):
        super().__init__(**kw)
        self.api_key = api_key

    def configured(self) -> bool:
        return bool(self.api_key)

    def _lookup(self, url: str) -> IntelResult:
        body = {"client": {"clientId": "verioax", "clientVersion": "0.1.0"},
                "threatInfo": {"threatTypes": self.THREATS, "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}}
        r = self._client().post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": self.api_key}, json=body)
        r.raise_for_status()
        data = r.json()
        matches = data.get("matches", [])
        if matches:
            types = sorted({m.get("threatType", "") for m in matches})
            return IntelResult(provider=self.name, status="listed", mode="live", checked_at=_now(), attribution=self.attribution,
                               verdict="Suspected " + ", ".join(t.lower().replace("_", " ") for t in types), details={"threat_types": types})
        return IntelResult(provider=self.name, status="not_found", mode="live", verdict="Not on Google's unsafe lists", checked_at=_now(),
                           attribution=self.attribution)


# ----------------------------------------------------------------------------------------------- VirusTotal (API v3, lookup only)
class VirusTotal(_Base):
    name, label = "virustotal", "VirusTotal"
    signup_url = "https://www.virustotal.com/gui/join-us"
    attribution = "Results from VirusTotal"

    def __init__(self, api_key: str | None, **kw):
        super().__init__(**kw)
        self.api_key = api_key

    def configured(self) -> bool:
        return bool(self.api_key)

    def _lookup(self, url: str) -> IntelResult:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = self._client().get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": self.api_key})
        if r.status_code == 404:
            return IntelResult(provider=self.name, status="not_found", mode="live", verdict="Never analysed by VirusTotal", checked_at=_now(),
                               attribution=self.attribution)
        r.raise_for_status()
        stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        status = "listed" if mal >= 2 else "suspicious" if (mal == 1 or sus >= 2) else "clean"
        return IntelResult(provider=self.name, status=status, mode="live", checked_at=_now(), attribution=self.attribution,
                           verdict=f"{mal} of {total} engines flag it as malicious, {sus} as suspicious", details=stats)


# ----------------------------------------------------------------------------------------------- URLhaus (abuse.ch)
class URLhaus(_Base):
    name, label = "urlhaus", "URLhaus (abuse.ch)"
    signup_url = "https://auth.abuse.ch/"
    attribution = "Data from URLhaus by abuse.ch"

    def __init__(self, auth_key: str | None, **kw):
        super().__init__(**kw)
        self.auth_key = auth_key

    def configured(self) -> bool:
        return bool(self.auth_key)

    def _lookup(self, url: str) -> IntelResult:
        r = self._client().post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": self.auth_key})
        r.raise_for_status()
        data = r.json()
        qs = data.get("query_status")
        if qs == "ok":
            tags = data.get("tags") or []
            return IntelResult(provider=self.name, status="listed", mode="live", checked_at=_now(), attribution=self.attribution,
                               verdict=f"Listed as {data.get('threat', 'malicious')} ({data.get('url_status', 'unknown')})",
                               details={"threat": data.get("threat"), "url_status": data.get("url_status"), "tags": tags[:8],
                                        "reference": data.get("urlhaus_reference")})
        if qs == "no_results":
            return IntelResult(provider=self.name, status="not_found", mode="live", verdict="Not in URLhaus", checked_at=_now(), attribution=self.attribution)
        return IntelResult(provider=self.name, status="error", mode="live", verdict=f"URLhaus answered '{qs}'", checked_at=_now(), attribution=self.attribution)


# ----------------------------------------------------------------------------------------------- PhishTank
class PhishTank(_Base):
    name, label = "phishtank", "PhishTank"
    signup_url = "https://phishtank.org/api_info.php"
    attribution = "Data from PhishTank"

    def __init__(self, app_key: str | None, username: str | None = None, **kw):
        super().__init__(**kw)
        self.app_key, self.username = app_key, username

    def configured(self) -> bool:
        return bool(self.app_key)

    def _lookup(self, url: str) -> IntelResult:
        ua = f"phishtank/{self.username}" if self.username else "phishtank/verioax"
        r = self._client().post("https://checkurl.phishtank.com/checkurl/", data={"url": url, "format": "json", "app_key": self.app_key},
                                headers={"User-Agent": ua})
        r.raise_for_status()
        res = r.json().get("results", {})
        if str(res.get("in_database")).lower() in ("true", "y", "1"):
            verified = str(res.get("verified")).lower() in ("true", "y", "1")
            valid = str(res.get("valid")).lower() in ("true", "y", "1")
            status = "listed" if verified and valid else "suspicious"
            return IntelResult(provider=self.name, status=status, mode="live", checked_at=_now(), attribution=self.attribution,
                               verdict="Verified phish" if status == "listed" else "Reported, not yet verified",
                               details={"phish_id": res.get("phish_id"), "detail": res.get("phish_detail_page")})
        return IntelResult(provider=self.name, status="not_found", mode="live", verdict="Not in PhishTank", checked_at=_now(), attribution=self.attribution)


# ----------------------------------------------------------------------------------------------- OpenPhish community feed (downloaded, cached)
class OpenPhish(_Base):
    name, label = "openphish", "OpenPhish community feed"
    signup_url = "https://openphish.com/phishing_feeds.html"
    attribution = "OpenPhish community feed"

    def __init__(self, feed_url: str, enabled: bool, **kw):
        super().__init__(**kw)
        self.feed_url, self.enabled = feed_url, enabled
        self._urls: set[str] | None = None
        self._hosts: set[str] | None = None
        self._load_lock = threading.Lock()

    def configured(self) -> bool:
        return self.enabled

    def _load(self) -> None:
        cached = self.cache.get("feed:openphish") if self.cache else None
        if cached is None:
            r = self._client().get(self.feed_url)
            r.raise_for_status()
            cached = [line.strip() for line in r.text.splitlines() if line.strip().startswith("http")]
            if self.cache:
                self.cache.set("feed:openphish", cached, 12 * 3600)          # the community feed updates every 12 hours
        self._urls = {u.rstrip("/").lower() for u in cached}
        self._hosts = {(re.sub(r"^https?://", "", u).split("/")[0]).lower() for u in self._urls}

    def lookup(self, url: str) -> IntelResult:
        if not self.configured():
            return IntelResult(provider=self.name, status="disabled", mode="none", attribution=self.attribution)
        if self._urls is None:
            with self._load_lock:                       # one download, however many scans arrive at once
                if self._urls is None:
                    _, failed = guarded(self.res, self.name, self.timeout_s, self._load)
                    if failed is not None:
                        return failed.model_copy(update={"mode": "none" if failed.status == "unavailable" else "cache"})
        u = url.rstrip("/").lower()
        host = re.sub(r"^https?://", "", u).split("/")[0]
        if u in self._urls:
            return IntelResult(provider=self.name, status="listed", mode="cache", verdict="URL is in the phishing feed", checked_at=_now(), attribution=self.attribution)
        if host in self._hosts:
            return IntelResult(provider=self.name, status="suspicious", mode="cache", verdict="Other phishing URLs on this host are in the feed",
                               checked_at=_now(), attribution=self.attribution)
        return IntelResult(provider=self.name, status="not_found", mode="cache", verdict=f"Not in the feed ({len(self._urls)} entries)",
                           checked_at=_now(), attribution=self.attribution)


# ----------------------------------------------------------------------------------------------- local IOC list (shipped seed + user additions)
class LocalIOC:
    name, label, signup_url = "local_ioc", "Verioax IOC list", ""
    attribution = "Verioax local indicator list"

    def __init__(self, files: list[Path]):
        self.files = files
        self.entries: dict[str, str] = {}          # indicator -> source note
        self.reload()

    def reload(self) -> None:
        self.entries.clear()
        for f in self.files:
            if not f.exists():
                continue
            source = f.name
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    if line.startswith("# source:"):
                        source = line.split(":", 1)[1].strip()
                    continue
                ind = refang(line.split()[0]).lower().rstrip("/")
                ind = re.sub(r"^https?://", "", ind)
                self.entries[ind] = source

    def configured(self) -> bool:
        return True

    def lookup(self, url: str) -> IntelResult:
        u = re.sub(r"^https?://", "", refang(url).lower()).rstrip("/")
        host = u.split("/")[0].split(":")[0]
        parts = host.split(".")
        candidates = [u, host] + [".".join(parts[i:]) for i in range(1, len(parts) - 1)]
        for c in candidates:
            if c in self.entries:
                return IntelResult(provider=self.name, status="listed", mode="local", checked_at=_now(), attribution=self.attribution,
                                   verdict=f"Known malicious indicator ({self.entries[c]})", details={"indicator": c})
        return IntelResult(provider=self.name, status="not_found", mode="local", verdict=f"Not in the local list ({len(self.entries)} indicators)",
                           checked_at=_now(), attribution=self.attribution)


# ----------------------------------------------------------------------------------------------- Google Fact Check Tools (claims)
class FactCheck:
    name, label = "google_factcheck", "Google Fact Check Tools"
    signup_url = "https://developers.google.com/fact-check/tools/api"

    def __init__(self, api_key: str | None, cache: TTLCache | None = None, transport: httpx.BaseTransport | None = None, timeout_s: float = 8.0,
                 res: Resilience | None = None):
        self.api_key, self.cache, self.transport, self.timeout_s = api_key, cache, transport, timeout_s
        self.res = res or Resilience()

    def configured(self) -> bool:
        return bool(self.api_key)

    def search(self, claim: str, language: str = "en", limit: int = 3) -> list[FactCheckRef] | None:
        """Related fact-checks, or None when the service is unavailable. Results are 'related', not a verdict."""
        if not self.configured():
            return None
        query = re.sub(r"\[[A-Z_]+_\d{3}\]", " ", claim)          # never send placeholders (or PII) - the claim text is already redacted
        query = " ".join(query.split())[:200]
        key = f"factcheck:{language}:{query.lower()}"
        if self.cache is not None and (hit := self.cache.get(key)) is not None:
            return [FactCheckRef.model_validate(x) for x in hit]
        def call():
            c = self.res.client((self.name, self.timeout_s, id(self.transport)),
                                lambda: httpx.Client(timeout=self.timeout_s, transport=self.transport, headers={"User-Agent": USER_AGENT}))
            r = c.get("https://factchecktools.googleapis.com/v1alpha1/claims:search",
                      params={"query": query, "languageCode": language, "pageSize": limit, "key": self.api_key})
            r.raise_for_status()
            return r.json()
        data, failed = guarded(self.res, self.name, self.timeout_s, call)
        if failed is not None:
            return None
        refs: list[FactCheckRef] = []
        for cl in data.get("claims", []):
            for rv in cl.get("claimReview", [])[:1]:
                refs.append(FactCheckRef(publisher=(rv.get("publisher") or {}).get("name") or (rv.get("publisher") or {}).get("site", ""),
                                         title=rv.get("title", "") or cl.get("text", "")[:120], url=rv.get("url", ""),
                                         rating=rv.get("textualRating", ""), review_date=rv.get("reviewDate")))
        refs = [r for r in refs if r.url][:limit]
        if self.cache is not None:
            self.cache.set(key, [r.model_dump() for r in refs], 24 * 3600)
        return refs
