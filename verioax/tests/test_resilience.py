"""Threat-intelligence resilience: circuit breakers, retries, parallel lookups with a deadline, shared clients - and
that an outage can never make a link look safer or leak a URL or API key into errors and health data."""
import json
import threading
import time

import httpx
import pytest
from pydantic import SecretStr

from trustguard.config import Preferences, Settings
from trustguard.intel import IntelHub
from trustguard.intel.providers import SafeBrowsing, URLhaus, VirusTotal, _err
from trustguard.intel.resilience import CircuitBreaker, Resilience


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_breaker_opens_after_repeated_failures_and_recovers_after_one_trial():
    clock = Clock()
    b = CircuitBreaker(threshold=3, cooldown_s=60, clock=clock)
    for _ in range(3):
        assert b.allow()
        b.failure()
    assert b.state == "open" and b.allow() is None
    clock.t += 61
    assert b.allow() == "trial" and b.allow() is None           # exactly one trial call while half-open
    b.failure()                                                 # the trial failed: open again, for a full cool-down
    assert b.state == "open" and b.allow() is None
    clock.t += 61
    assert b.allow() == "trial"
    b.success()
    assert b.state == "closed" and b.allow() == "closed" and b.failures == 0


def test_open_circuit_skips_calls_and_reports_unavailable_not_clean():
    calls = {"n": 0}

    def down(req):
        calls["n"] += 1
        return httpx.Response(500)
    clock = Clock()
    res = Resilience(threshold=3, cooldown_s=60, clock=clock)
    vt = VirusTotal("k", transport=httpx.MockTransport(down), res=res)
    for _ in range(3):
        assert vt.lookup("https://x.example/").status == "error"
    assert calls["n"] == 3
    r = vt.lookup("https://x.example/")
    assert r.status == "unavailable" and calls["n"] == 3 and "not evidence that the link is safe" in r.verdict
    health = res.health()["virustotal"]
    assert health["circuit"] == "open" and health["errors"] == 3 and health["skipped"] == 1 and health["consecutive_failures"] == 3
    clock.t += 61                                               # cool-down over: one trial call goes out
    vt.lookup("https://x.example/")
    assert calls["n"] == 4


def test_connection_failures_are_retried_once_but_read_timeouts_are_not():
    attempts = {"connect": 0, "slow": 0}

    def flaky(req):
        attempts["connect"] += 1
        if attempts["connect"] == 1:
            raise httpx.ConnectError("connection refused", request=req)
        return httpx.Response(200, json={})
    assert SafeBrowsing("k", transport=httpx.MockTransport(flaky)).lookup("https://x.example/").status == "not_found"
    assert attempts["connect"] == 2

    def slow(req):
        attempts["slow"] += 1
        raise httpx.ReadTimeout("timed out", request=req)
    r = SafeBrowsing("k", transport=httpx.MockTransport(slow)).lookup("https://x.example/")
    assert r.status == "error" and r.verdict == "timed out" and attempts["slow"] == 1


def test_http_503_is_retried_and_401_is_not():
    seen = {"503": 0, "401": 0}

    def busy(req):
        seen["503"] += 1
        return httpx.Response(503 if seen["503"] == 1 else 200, json={"query_status": "no_results"})
    assert URLhaus("k", transport=httpx.MockTransport(busy)).lookup("https://x.example/").status == "not_found" and seen["503"] == 2

    def denied(req):
        seen["401"] += 1
        return httpx.Response(401)
    assert URLhaus("k", transport=httpx.MockTransport(denied)).lookup("https://x.example/").status == "error" and seen["401"] == 1


def test_error_text_never_contains_the_link_or_the_api_key():
    req = httpx.Request("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=SECRET123")
    for exc in (httpx.ConnectError("failed for https://evil-login.example/pay?key=SECRET123", request=req),
                httpx.ReadError("peer closed connection: evil-login.example key=SECRET123", request=req),
                httpx.HTTPStatusError("bad", request=req, response=httpx.Response(500, request=req))):
        text = _err(exc)
        assert "SECRET123" not in text and "evil-login" not in text and "googleapis" not in text, text


def _settings(tmp_path, **kw):
    return Settings(_env_file=None, data_dir=tmp_path, google_safe_browsing_key=SecretStr("k1"), virustotal_key=SecretStr("k2"),
                    urlhaus_key=SecretStr("k3"), fetch_timeout_s=1, **kw)


def test_online_providers_are_asked_in_parallel(tmp_path):
    def slow_ok(req):
        time.sleep(0.4)
        if "virustotal" in req.url.host:
            return httpx.Response(404)
        if "urlhaus" in req.url.host:
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={})
    hub = IntelHub(_settings(tmp_path), Preferences(intel_lookups=True, openphish_feed=False), transport=httpx.MockTransport(slow_ok))
    t = time.perf_counter()
    out = {r.provider: r.status for r in hub.lookup("https://x.example/", network=True)}
    took = time.perf_counter() - t
    assert out["google_safe_browsing"] == out["virustotal"] == out["urlhaus"] == "not_found"
    assert took < 1.0, f"three 0.4 s lookups took {took:.2f} s - they ran one after another"
    assert [r.provider for r in hub.lookup("https://x.example/", network=True)][0] == "local_ioc"     # order is stable


def test_a_hung_provider_costs_at_most_the_deadline_and_is_reported_as_not_checked(tmp_path):
    release = threading.Event()

    def hang(req):
        if "virustotal" in req.url.host:
            release.wait(10)
            return httpx.Response(404)
        if "urlhaus" in req.url.host:
            return httpx.Response(200, json={"query_status": "no_results"})
        return httpx.Response(200, json={})
    hub = IntelHub(_settings(tmp_path), Preferences(intel_lookups=True, openphish_feed=False), transport=httpx.MockTransport(hang))
    hub.deadline_s = 0.5
    t = time.perf_counter()
    out = {r.provider: r for r in hub.lookup("https://x.example/", network=True)}
    took = time.perf_counter() - t
    release.set()
    assert took < 2.0
    assert out["virustotal"].status == "error" and "not checked" in out["virustotal"].verdict
    assert out["google_safe_browsing"].status == "not_found"


def test_health_has_counts_but_no_links_keys_or_messages(tmp_path):
    hub = IntelHub(_settings(tmp_path), Preferences(intel_lookups=True, openphish_feed=False),
                   transport=httpx.MockTransport(lambda req: httpx.Response(500)))
    for _ in range(4):
        hub.lookup("https://evil-login.example/pay?acct=12345", network=True)
    rows = {r["provider"]: r for r in hub.health()}
    assert rows["google_safe_browsing"]["circuit"] == "open" and rows["google_safe_browsing"]["errors"] == 3
    assert rows["local_ioc"]["configured"] and "circuit" not in rows["local_ioc"]
    blob = json.dumps(hub.health())
    for secret in ("evil-login", "12345", "k1", "k2", "k3", "acct"):
        assert secret not in blob


def test_one_connection_pool_per_provider(tmp_path):
    hub = IntelHub(_settings(tmp_path), Preferences(intel_lookups=True, openphish_feed=False),
                   transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"query_status": "no_results"})))
    for _ in range(5):
        hub.lookup("https://x.example/", network=True)
    assert len(hub.res._clients) == 3


@pytest.mark.parametrize("status", [500, "timeout"])
def test_engine_never_lowers_risk_when_intel_is_down(settings, prefs, status):
    """The same scam scores the same whether the threat-intel services answer 'not listed' or are down."""
    from trustguard.engine import TrustGuardEngine
    msg = ("Your SBI account will be blocked today. Update PAN KYC now: https://sbi-kyc-update.top/login "
           "or call 9876543210. Share the OTP to verify.")

    def handler(req):
        if status == "timeout":
            raise httpx.ReadTimeout("timed out", request=req)
        return httpx.Response(status)
    s = settings.model_copy(update={"google_safe_browsing_key": SecretStr("k")})
    on = prefs.model_copy(update={"intel_lookups": True})
    down = TrustGuardEngine(s, on, store=False, hub=IntelHub(s, on, transport=httpx.MockTransport(handler))).scan_message(msg).result
    clean = TrustGuardEngine(s, on, store=False, hub=IntelHub(s, on, transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={})))).scan_message(msg).result
    assert down.risk_score >= clean.risk_score and down.overall_risk.value in ("HIGH", "CRITICAL")
    rep = down.urls[0]
    assert any(r.status in ("error", "unavailable") for r in rep.reputation)
    assert "could not be reached" in rep.check_note
