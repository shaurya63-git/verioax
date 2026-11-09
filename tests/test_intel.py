import json

import httpx
from pydantic import SecretStr

from trustguard.cache import TTLCache
from trustguard.config import Preferences, Settings
from trustguard.intel import IntelHub
from trustguard.intel.providers import FactCheck, LocalIOC, OpenPhish, PhishTank, SafeBrowsing, URLhaus, VirusTotal


def mock(handler):
    return httpx.MockTransport(handler)


def test_unconfigured_providers_say_so():
    for p in (SafeBrowsing(None), VirusTotal(None), URLhaus(None), PhishTank(None)):
        assert p.lookup("https://x.example/").status == "not_configured"


def test_safe_browsing_listed_and_clean():
    seen = {}

    def h(req):
        seen["key"] = req.url.params.get("key")
        body = json.loads(req.content)
        if "bad" in body["threatInfo"]["threatEntries"][0]["url"]:
            return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "x"}}]})
        return httpx.Response(200, json={})
    sb = SafeBrowsing("k1", transport=mock(h))
    r = sb.lookup("https://bad.example/")
    assert r.status == "listed" and "social engineering" in r.verdict and seen["key"] == "k1" and "Google" in r.attribution
    assert sb.lookup("https://good.example/").status == "not_found"


def test_errors_are_errors_not_clean():
    r = SafeBrowsing("k", transport=mock(lambda req: httpx.Response(401))).lookup("https://x.example/")
    assert r.status == "error" and "401" in r.verdict


def test_virustotal_states():
    def h(req):
        if req.url.path.endswith("aHR0cHM6Ly9uZXcuZXhhbXBsZS8"):          # base64url("https://new.example/")
            return httpx.Response(404)
        stats = {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 20}
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})
    vt = VirusTotal("k", transport=mock(h))
    assert vt.lookup("https://new.example/").status == "not_found"
    assert vt.lookup("https://bad.example/").status == "listed"


def test_urlhaus_sends_auth_key():
    got = {}

    def h(req):
        got["auth"] = req.headers.get("Auth-Key")
        return httpx.Response(200, json={"query_status": "ok", "threat": "malware_download", "url_status": "online", "tags": ["apk"]})
    r = URLhaus("abc", transport=mock(h)).lookup("https://x.example/a.apk")
    assert got["auth"] == "abc" and r.status == "listed"


def test_phishtank_verified():
    h = lambda req: httpx.Response(200, json={"results": {"in_database": True, "verified": True, "valid": True, "phish_id": 1}})  # noqa: E731
    assert PhishTank("k", "me", transport=mock(h)).lookup("https://x.example/").status == "listed"


def test_openphish_feed_cached(tmp_path):
    calls = {"n": 0}

    def h(req):
        calls["n"] += 1
        return httpx.Response(200, text="https://phish.example/login\nhttps://other.example/a\n")
    cache = TTLCache(tmp_path / "c.sqlite")
    op = OpenPhish("https://feed.example/feed.txt", True, cache=cache, transport=mock(h))
    assert op.lookup("https://phish.example/login").status == "listed"
    assert op.lookup("https://phish.example/other").status == "suspicious"
    op2 = OpenPhish("https://feed.example/feed.txt", True, cache=cache, transport=mock(h))
    assert op2.lookup("https://clean.example/").status == "not_found" and calls["n"] == 1


def test_local_ioc_matches_host_subdomain_and_ip(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text("# source: test\nbad[.]vip\n101[.]33[.]78[.]145\n", encoding="utf-8")
    ioc = LocalIOC([f])
    assert ioc.lookup("https://bad.vip/pay").status == "listed"
    assert ioc.lookup("https://www.bad.vip/").status == "listed"
    assert ioc.lookup("http://101.33.78.145/").status == "listed"
    assert ioc.lookup("https://good.vip/").status == "not_found"


def test_seed_iocs_load(settings, prefs):
    hub = IntelHub(settings, prefs)
    assert hub.local.lookup("https://echallx.vip/pay").status == "listed"


def test_factcheck_parses_results():
    def h(req):
        assert "[" not in req.url.params["query"]                                 # placeholders are stripped from the query
        return httpx.Response(200, json={"claims": [{"text": "x", "claimReview": [{"publisher": {"name": "PIB Fact Check"}, "url": "https://pib.gov.in/x",
                                                                                     "title": "Fake", "textualRating": "False"}]}]})
    refs = FactCheck("k", transport=mock(h)).search("Lok Adalat waives [VEHICLE_REG_001] challans")
    assert refs[0].publisher == "PIB Fact Check" and refs[0].rating == "False"


def test_hub_status_and_test_records_result(tmp_path, monkeypatch):
    s = Settings(_env_file=None, data_dir=tmp_path, google_safe_browsing_key=SecretStr("k"))
    hub = IntelHub(s, Preferences(), transport=mock(lambda req: httpx.Response(200, json={"matches": [{"threatType": "MALWARE"}]})))
    rows = {r["provider"]: r for r in hub.status()}
    assert rows["google_safe_browsing"]["state"] == "configured, not tested yet" and rows["virustotal"]["state"] == "not configured"
    res = hub.test("google_safe_browsing")
    assert res["ok"] and {r["provider"]: r for r in hub.status()}["google_safe_browsing"]["state"] == "working (tested)"


def test_user_iocs_add_remove(settings, prefs):
    hub = IntelHub(settings, prefs)
    hub.add_ioc("new-scam.example")
    assert hub.local.lookup("https://new-scam.example/").status == "listed"
    assert hub.remove_ioc("new-scam.example") and hub.local.lookup("https://new-scam.example/").status == "not_found"
