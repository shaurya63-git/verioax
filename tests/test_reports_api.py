from pathlib import Path

import pytest
from conftest import ECHALLAN_SCAM
from fastapi.testclient import TestClient

from trustguard import analytics, reports
from trustguard.llm import OllamaExplainer, validate


def test_every_export_is_free_of_raw_pii(engine):
    r = engine.scan_message(ECHALLAN_SCAM + " Call 9876543210.", sender="+91 98765 43210").result
    texts = [reports.to_json(r), reports.findings_csv(r), reports.to_markdown(r)]
    for raw in ("Ravi Kumar", "MH12AB1234", "9876543210"):
        assert all(raw not in t for t in texts)
    pdf = reports.to_pdf(r)
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000
    s = analytics.summarize(engine.store.results())
    assert s["totals"]["scans"] == 1 and reports.analytics_pdf(s).startswith(b"%PDF")
    assert "Ravi" not in reports.analytics_markdown(s)


@pytest.fixture
def client(engine, monkeypatch):
    from api.main import create_app
    return TestClient(create_app(engine))


def test_api_scan_history_and_reports(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.post("/v1/scan/message", json={"text": ECHALLAN_SCAM, "sender": "+91 98765 43210"})
    assert r.status_code == 200
    body = r.json()
    assert body["overall_risk"] in ("HIGH", "CRITICAL") and "Ravi Kumar" not in r.text
    sid = body["scan_id"]
    assert client.get(f"/v1/scans/{sid}").json()["scan_id"] == sid
    assert client.get("/v1/scans", params={"risk": ["HIGH", "CRITICAL"]}).json()
    pdf = client.get(f"/v1/scans/{sid}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert client.get(f"/v1/scans/{sid}/report.md").text.startswith("# Verioax report")
    assert client.get("/v1/analytics").json()["totals"]["scans"] == 1
    assert client.delete(f"/v1/scans/{sid}").status_code == 200 and client.get(f"/v1/scans/{sid}").status_code == 404


def test_api_validation_and_files(client):
    assert client.post("/v1/scan/message", json={"text": ""}).status_code == 422
    assert client.post("/v1/scan/url", json={"url": "not a link"}).status_code == 422
    r = client.post("/v1/scan/file", files={"file": ("m.txt", ECHALLAN_SCAM.encode(), "text/plain")}, data={"mode": "full"})
    assert r.status_code == 200 and r.json()["input_type"] == "file"
    assert client.post("/v1/scan/file", files={"file": ("x.bin", b"\x00\x01", "application/octet-stream")}).status_code == 422


def test_api_token(engine, monkeypatch):
    from pydantic import SecretStr

    from api.main import create_app
    from trustguard import config
    s = config.Settings(_env_file=None, data_dir=engine.settings.data_dir, api_token=SecretStr("s3cret"))
    monkeypatch.setattr("api.main.get_settings", lambda: s)
    c = TestClient(create_app(engine))
    assert c.post("/v1/scan/url", json={"url": "https://example.org/"}).status_code == 401
    ok = c.post("/v1/scan/url", json={"url": "https://example.org/"}, headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code == 200


def test_rate_limit(client, monkeypatch):
    import api.main as m
    statuses = [client.post("/v1/scan/url", json={"url": "https://example.org/"}).status_code for _ in range(m.SCANS_PER_MINUTE + 2)]
    assert 429 in statuses


def test_llm_output_is_validated():
    assert validate("This message is safe, nothing to worry about.", "CRITICAL") is None
    out = validate("It pretends to be the traffic police. Visit https://evil.example or call 98765 43210.", "HIGH")
    assert "evil.example" not in out and "98765" not in out


def test_ollama_explainer_with_mock():
    import httpx
    t = httpx.MockTransport(lambda req: httpx.Response(200, json={"message": {"content": "The message pretends to be the transport department."}}))
    ex = OllamaExplainer("http://localhost:11434", "llama3.1:8b", transport=t)
    assert "transport" in ex.explain("redacted", "Likely scam", "HIGH", ["Asks you to pay"])


def test_blank_values_copied_from_env_example_mean_not_set(tmp_path, monkeypatch):
    """Copying .env.example unchanged must not turn blank keys into 'configured' services or an empty API token."""
    from trustguard.config import Settings
    env = tmp_path / ".env"
    env.write_text((Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    for var in ("TRUSTGUARD_API_URL", "TRUSTGUARD_API_TOKEN", "VIRUSTOTAL_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY", "TRUSTGUARD_DATA_DIR"):
        monkeypatch.delenv(var, raising=False)
    s = Settings(_env_file=env)
    assert s.api_url is None and s.api_token is None
    assert not any(s.configured_services().values())
    assert s.fetch_timeout_s == 8 and s.max_redirects == 5
