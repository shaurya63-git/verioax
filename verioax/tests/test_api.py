"""API security boundary and operational behaviour: who may call it, who may act for which account, limits, retries
(Idempotency-Key), busy/too-large answers, and metrics that never contain submitted content."""
import sys
import threading
from pathlib import Path

import httpx
import pytest
from conftest import ECHALLAN_SCAM
from fastapi.testclient import TestClient
from pydantic import SecretStr

from trustguard import config
from trustguard.config import resolve_api_token
from trustguard.engine import TrustGuardEngine
from trustguard.metrics import REGISTRY
from trustguard.storage import ScanStore

APP_DIR = str(Path(__file__).resolve().parents[1] / "app")
if APP_DIR not in sys.path:
    sys.path.append(APP_DIR)                # the web app's modules (client.py) import as top-level modules

REMOTE = ("203.0.113.9", 50000)            # documentation address: "another machine"
URL = {"url": "https://example.org/"}


def _app(engine, monkeypatch, **overrides):
    from api.main import create_app
    s = config.Settings(_env_file=None, data_dir=engine.settings.data_dir, **overrides)
    monkeypatch.setattr("api.main.get_settings", lambda: s)
    return create_app(engine), s


def _bearer(s) -> dict:
    return {"Authorization": f"Bearer {resolve_api_token(s)}"}


def test_remote_callers_always_need_the_token(engine, monkeypatch):
    app, s = _app(engine, monkeypatch)
    remote = TestClient(app, client=REMOTE)
    assert remote.post("/v1/scan/url", json=URL).status_code == 401
    assert remote.post("/v1/scan/url", json=URL, headers={"Authorization": "Bearer wrong-token"}).status_code == 401
    assert remote.post("/v1/scan/url", json=URL, headers=_bearer(s)).status_code == 200
    assert len(resolve_api_token(s)) >= 32                                     # generated, not a default
    assert remote.get("/health").status_code == 200                            # liveness stays open (no data in it)


def test_proxied_requests_get_no_local_exemption(engine, monkeypatch):
    app, s = _app(engine, monkeypatch)
    local = TestClient(app)                                                    # loopback peer
    assert local.post("/v1/scan/url", json=URL).status_code == 200            # local development: no token needed
    for h in ({"X-Forwarded-For": "198.51.100.7"}, {"Forwarded": "for=198.51.100.7"}, {"X-Real-IP": "198.51.100.7"}):
        assert local.post("/v1/scan/url", json=URL, headers=h).status_code == 401, h


def test_configured_token_removes_the_local_exemption(engine, monkeypatch):
    app, s = _app(engine, monkeypatch, api_token=SecretStr("a-configured-token-for-tests-0000"))
    local = TestClient(app)
    assert local.post("/v1/scan/url", json=URL).status_code == 401
    assert local.post("/v1/scan/url", json=URL, headers={"Authorization": "Bearer a-configured-token-for-tests-0000"}).status_code == 200


def test_owner_header_cannot_be_spoofed_and_accounts_are_isolated(engine, monkeypatch):
    app, s = _app(engine, monkeypatch)
    remote = TestClient(app, client=REMOTE)
    assert remote.get("/v1/scans", headers={"X-Verioax-Owner": "1"}).status_code == 401      # no token, no owner
    auth = _bearer(s)
    sid = remote.post("/v1/scan/message", json={"text": ECHALLAN_SCAM}, headers=auth | {"X-Verioax-Owner": "1"}).json()["scan_id"]
    as1, as2 = auth | {"X-Verioax-Owner": "1"}, auth | {"X-Verioax-Owner": "2"}
    assert remote.get(f"/v1/scans/{sid}", headers=as1).status_code == 200
    assert remote.get(f"/v1/scans/{sid}", headers=as2).status_code == 404
    assert remote.get(f"/v1/scans/{sid}/report.md", headers=as2).status_code == 404
    assert remote.delete(f"/v1/scans/{sid}", headers=as2).status_code == 404
    assert [r["scan_id"] for r in remote.get("/v1/scans", headers=as1).json()] == [sid]
    assert remote.get("/v1/scans", headers=as2).json() == []
    assert remote.get("/v1/scans", headers=auth | {"X-Verioax-Owner": "0"}).status_code == 422    # ids start at 1


def test_idempotency_key_replays_the_first_result(engine, monkeypatch):
    app, s = _app(engine, monkeypatch)
    c = TestClient(app)
    h = {"Idempotency-Key": "retry-0001-abcdef"}
    first = c.post("/v1/scan/message", json={"text": ECHALLAN_SCAM}, headers=h).json()
    again = c.post("/v1/scan/message", json={"text": ECHALLAN_SCAM}, headers=h).json()
    assert first["scan_id"] == again["scan_id"] and len(c.get("/v1/scans").json()) == 1
    other = c.post("/v1/scan/message", json={"text": ECHALLAN_SCAM}, headers=h | {"X-Verioax-Owner": "5"}).json()
    assert other["scan_id"] != first["scan_id"]                     # keys are per account
    assert c.post("/v1/scan/message", json={"text": ECHALLAN_SCAM}, headers={"Idempotency-Key": "x"}).status_code == 422


def test_busy_engine_answers_503_with_retry_after(settings, prefs, monkeypatch):
    s = settings.model_copy(update={"max_concurrent_scans": 1, "scan_queue_timeout_s": 0.5})
    eng = TrustGuardEngine(s, prefs, store=False)
    app, _ = _app(eng, monkeypatch)
    c = TestClient(app)
    assert eng._slots.acquire(timeout=1)                            # another scan holds the only slot
    try:
        r = c.post("/v1/scan/url", json=URL)
    finally:
        eng._slots.release()
    assert r.status_code == 503 and r.headers["Retry-After"] == "5" and "busy" in r.json()["detail"]
    assert c.post("/v1/scan/url", json=URL).status_code == 200


def test_too_large_files_get_413_before_parsing(engine, monkeypatch):
    app, _ = _app(engine, monkeypatch)
    monkeypatch.setattr("trustguard.engine.MAX_FILE_BYTES", 1000)
    called = []
    monkeypatch.setattr("trustguard.engine.extract", lambda *a, **k: called.append(1))
    r = TestClient(app).post("/v1/scan/file", files={"file": ("big.txt", b"a" * 2000, "text/plain")})
    assert r.status_code == 413 and not called


def test_validation_errors_do_not_echo_the_submitted_text(engine, monkeypatch):
    app, _ = _app(engine, monkeypatch)
    secret = "Ravi Kumar 9876543210 " * 1000                       # over the 20,000-character limit
    r = TestClient(app).post("/v1/scan/message", json={"text": secret})
    assert r.status_code == 422 and "Ravi" not in r.text and "9876543210" not in r.text


def test_metrics_need_the_token_and_contain_no_content(engine, monkeypatch):
    REGISTRY.reset()
    app, s = _app(engine, monkeypatch)
    local = TestClient(app)
    local.post("/v1/scan/message", json={"text": ECHALLAN_SCAM, "sender": "+91 98765 43210"})
    local.post("/v1/scan/url", json={"url": "https://sbi-kyc-update.top/login?acct=12345"})
    remote = TestClient(app, client=REMOTE)
    assert remote.get("/metrics").status_code == 401 and remote.get("/v1/ops/stats").status_code == 401
    text = remote.get("/metrics", headers=_bearer(s)).text
    stats = remote.get("/v1/ops/stats", headers=_bearer(s))
    assert "verioax_requests_total" in text and stats.status_code == 200
    body = stats.json()
    assert body["scans_total"] >= 2 and {"providers", "latency", "limits", "process"} <= set(body)
    for leaked in ("Ravi", "MH12AB1234", "98765", "echallan", "sbi-kyc", "12345", resolve_api_token(s)):
        assert leaked not in text and leaked not in stats.text, leaked


def test_ready_and_security_headers(engine, monkeypatch):
    app, _ = _app(engine, monkeypatch)
    r = TestClient(app).get("/ready")
    assert r.json()["status"] == "ok" and r.json()["database"] == "sqlite"
    for h, v in (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"), ("Cache-Control", "no-store")):
        assert r.headers[h] == v


def test_api_wide_limit_applies_to_every_v1_route(engine, monkeypatch):
    app, _ = _app(engine, monkeypatch, rate_limit_api="5/60")
    c = TestClient(app)
    codes = [c.get("/v1/intel/status").status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429
    assert c.get("/health").status_code == 200                      # liveness is never rate limited


def test_parallel_requests_are_all_answered(engine, monkeypatch):
    """A quick concurrency check in-process (the real load test is tests/load/)."""
    app, _ = _app(engine, monkeypatch)
    c = TestClient(app)
    out: list[int] = []

    def one(i):
        out.append(c.post("/v1/scan/message", json={"text": f"{ECHALLAN_SCAM} ref {i}"}).status_code)
    threads = [threading.Thread(target=one, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert out.count(200) == 12


# ---------------------------------------------------------------------------------------------- the web app's API client
@pytest.fixture
def api_client(engine, monkeypatch):
    from client import APIClient
    app, s = _app(engine, monkeypatch)
    tc = TestClient(app)
    seen: list[httpx.Request] = []
    fail_first = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if fail_first["n"] > 0:
            fail_first["n"] -= 1
            return httpx.Response(503, headers={"Retry-After": "0"}, json={"detail": "busy"})
        r = tc.request(req.method, req.url.raw_path.decode(), headers=dict(req.headers), content=req.content)
        return httpx.Response(r.status_code, headers=r.headers, content=r.content)
    return APIClient("http://api.local", resolve_api_token(s), transport=httpx.MockTransport(handler)), seen, fail_first


def test_api_client_retries_busy_with_the_same_idempotency_key(api_client):
    from trustguard.schemas import AnalysisMode
    cl, seen, fail_first = api_client
    fail_first["n"] = 1
    scan = cl.scan_message(ECHALLAN_SCAM, None, AnalysisMode.FULL, owner_id=3)
    keys = {r.headers.get("idempotency-key") for r in seen}
    assert scan.result.overall_risk.value in ("HIGH", "CRITICAL") and len(seen) == 2 and len(keys) == 1 and None not in keys
    assert len(cl.list_scans(owner_id=3)) == 1


def test_api_client_gives_a_clear_error_when_the_api_is_down():
    from client import APIClient, ClientError
    from trustguard.schemas import AnalysisMode

    def down(req):
        raise httpx.ConnectError("refused", request=req)
    cl = APIClient("http://api.local", "t" * 40, transport=httpx.MockTransport(down))
    with pytest.raises(ClientError, match="not reachable"):
        cl.scan_url("https://example.org/")
    with pytest.raises(ClientError):
        cl.scan_message("hello", None, AnalysisMode.FULL)


def test_local_client_maps_busy_to_a_user_message(settings, prefs, monkeypatch):
    from client import ClientError, LocalClient
    s = settings.model_copy(update={"max_concurrent_scans": 1, "scan_queue_timeout_s": 0.5})
    lc = LocalClient.__new__(LocalClient)
    lc.engine = TrustGuardEngine(s, prefs, store=ScanStore(s.data_dir / "h.sqlite"))
    lc.engine._slots.acquire()
    try:
        with pytest.raises(ClientError, match="busy"):
            lc.scan_url("https://example.org/")
    finally:
        lc.engine._slots.release()
    assert lc.scan_url("https://example.org/").result.input_type.value == "url"
