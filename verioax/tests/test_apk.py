"""Static Android-app (APK) analysis: what it finds, and the safety rules - the file is never installed, run, written to
disk or sent anywhere; hostile archives (ZIP bombs, path traversal, duplicate entries, malformed manifests) are refused or
reported, and an app that can't be analysed is INCONCLUSIVE, never "safe"."""
import io
import json
import os
import zipfile

import apkfactory as F
import pytest
from fastapi.testclient import TestClient

from trustguard.engine import InputError, TrustGuardEngine
from trustguard.extract.apk import APKError, analyze_apk, dex_strings, looks_like_apk, parse_axml


def _scan(engine, name, blob):
    return engine.scan_file(name, blob).result


# ---------------------------------------------------------------------------------------------- what it finds
def test_sms_stealer_posing_as_a_bank_is_high_risk(engine):
    r = _scan(engine, "SBI_Rewardz.apk", F.sms_stealer())
    assert r.overall_risk.value in ("HIGH", "CRITICAL") and r.scam_type == "malicious_app"
    keys = {f.indicator for f in r.scam.findings}
    assert {"apk_otp_theft", "apk_impersonation", "apk_test_key"} <= keys
    app = r.app
    assert app.package == "com.sbi.rewardz.points" and app.label == "SBI Rewardz" and app.claimed_entity == "State Bank of India"
    perms = {p.name: p for p in app.permissions}
    assert "android.permission.RECEIVE_SMS" in perms and perms["android.permission.READ_SMS"].risk in ("high", "critical")
    rx = next(c for c in app.components if c.kind == "receiver")
    assert rx.exported and "android.provider.Telephony.SMS_RECEIVED" in rx.actions and "999" in rx.role
    assert any(c.test_key for c in app.certificates) and app.signature_verified is False
    assert app.urls and all("http" not in u and "[.]" in u for u in app.urls)       # links found inside the app are defanged
    assert "not run" in r.verdict_summary or "static analysis" in r.verdict_summary.lower()
    assert [a.title for a in r.recommended_actions][0] == "Don't install this app"


def test_ordinary_app_is_low_with_honest_wording_and_capped_confidence(engine):
    r = _scan(engine, "notes.apk", F.harmless_app())
    assert r.overall_risk.value == "LOW" and r.scam_type is None
    assert r.model_confidence <= 0.6 and r.confidence_label != "High"
    assert "not proof the app is safe" in r.verdict_summary


def test_file_type_comes_from_the_content_not_the_name(engine):
    assert looks_like_apk("invoice.pdf", F.sms_stealer())                      # an APK renamed to .pdf is still analysed as an app
    assert _scan(engine, "invoice.pdf", F.sms_stealer()).app is not None
    pdf = b"%PDF-1.4\n" + b"0" * 100
    assert not looks_like_apk("bank.apk", pdf)                                  # a PDF renamed to .apk is not an app


def test_binary_manifest_and_dex_parsers(engine):
    m = F.manifest("org.x", "X", ["android.permission.CAMERA"], [])
    node = parse_axml(m)
    assert node.tag == "manifest" and any(c.tag == "uses-permission" for c in node.children)
    assert dex_strings(F.dex(["Lcom/x/A;", "héllo"]), 100) == ["Lcom/x/A;", "héllo"]
    with pytest.raises(APKError):
        dex_strings(b"not a dex file", 10)


# ---------------------------------------------------------------------------------------------- hostile archives
def _zip(entries: list[tuple[str, bytes]]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, blob in entries:
            z.writestr(zipfile.ZipInfo(name), blob, compress_type=zipfile.ZIP_DEFLATED)
    return out.getvalue()


def test_zip_bomb_members_are_not_inflated(engine):
    man = F.manifest("org.bomb", "Bomb", [], [])
    blob = _zip([("AndroidManifest.xml", man), ("classes.dex", b"\0" * 3_000_000)])     # ~1000:1 compression ratio
    info = analyze_apk(blob)
    assert any("compression ratio" in x for x in info.archive_issues) and info.dex_files == 0
    r = _scan(engine, "bomb.apk", blob)
    assert r.app.archive_issues and r.overall_risk.value != "LOW" or "apk_archive_tricks" in {f.indicator for f in r.scam.findings}


def test_declared_size_over_the_archive_limit_is_refused(engine, monkeypatch):
    import trustguard.extract.apk as apk
    monkeypatch.setattr(apk, "MAX_TOTAL_UNCOMPRESSED", 50_000)
    blob = _zip([("AndroidManifest.xml", F.manifest("org.big", "Big", [], [])), ("assets/pad.bin", b"\0" * 60_000)])
    with pytest.raises(APKError, match="ZIP bomb"):
        analyze_apk(blob)
    r = _scan(engine, "big.apk", blob)
    assert r.overall_risk.value == "INCONCLUSIVE" and "ZIP bomb" in r.verdict_summary


def test_path_traversal_and_duplicate_entries_are_reported_and_nothing_is_written(engine, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    man = F.manifest("org.trick", "Trick", ["android.permission.INTERNET"], [])
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("AndroidManifest.xml", man)
        z.writestr("classes.dex", F.dex(["La;"]))
        z.writestr("../../evil.so", b"\x7fELF" + b"\0" * 60)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            z.writestr("classes.dex", F.dex(["Lhidden/Payload;"]))           # the 'Master Key' duplicate-entry trick
    r = _scan(engine, "trick.apk", out.getvalue())
    issues = " ".join(r.app.archive_issues)
    assert "path traversal" in issues and "duplicate entry" in issues
    assert "apk_archive_tricks" in {f.indicator for f in r.scam.findings}
    assert list(work.iterdir()) == [] and not list(tmp_path.rglob("evil.so")) and not (tmp_path.parent / "evil.so").exists()


@pytest.mark.parametrize("manifest, why", [
    (b"\x03\x00\x08\x00" + os.urandom(64), "malformed"),
    (b"<?xml version='1.0'?><manifest package='x'/>", "plain text"),
    (b"", "empty"),
])
def test_unreadable_manifest_is_inconclusive_never_safe(engine, manifest, why):
    blob = _zip([("AndroidManifest.xml", manifest), ("classes.dex", F.dex(["La;"]))])
    r = _scan(engine, "broken.apk", blob)
    assert r.overall_risk.value == "INCONCLUSIVE" and r.risk_score == 0 and r.app.parsed is False
    assert "not a sign that it is safe" in r.verdict_summary
    assert r.model_confidence <= 0.3


def test_apk_without_a_manifest_and_plain_zip_files(engine):
    r = _scan(engine, "game.apk", _zip([("readme.txt", b"hello")]))
    assert r.overall_risk.value == "INCONCLUSIVE" and "not an Android app" in r.verdict_summary
    with pytest.raises(InputError):
        engine.scan_file("photos.zip", _zip([("a.txt", b"hello")]))          # other archives are not unpacked at all
    r = _scan(engine, "corrupt.apk", b"PK\x03\x04garbage")                     # analysis failed: said plainly, never "safe"
    assert r.overall_risk.value == "INCONCLUSIVE" and "not a readable" in r.verdict_summary


def test_time_budget_stops_analysis_with_a_stated_limitation():
    info = analyze_apk(F.sms_stealer(), time_budget_s=0)
    assert info.manifest_ok is False or any("analysis stopped" in x for x in info.limitations)


# ---------------------------------------------------------------------------------------------- never run, never sent
def test_apk_is_never_executed_installed_or_uploaded(settings, prefs, monkeypatch):
    import subprocess

    import httpx

    def forbidden(*a, **k):
        raise AssertionError("the APK scan tried to run a program or make a network call")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(httpx.Client, "send", forbidden)
    online = prefs.model_copy(update={"network_checks": True, "intel_lookups": True})     # even with live checks on
    eng = TrustGuardEngine(settings, online, store=False)
    r = eng.scan_file("SBI_Rewardz.apk", F.sms_stealer()).result
    assert r.overall_risk.value in ("HIGH", "CRITICAL") and r.processing.network_mode == "local"


def test_stored_scan_and_reports_hold_no_app_binary(engine):
    from trustguard import reports
    blob = F.sms_stealer()
    r = _scan(engine, "SBI_Rewardz.apk", blob)
    stored = engine.store.get(r.scan_id)
    assert stored is not None and stored.app.sha256 == r.app.sha256
    dumped = json.dumps(stored.model_dump(mode="json"))
    assert len(dumped) < 60_000 and "UEsDB" not in dumped                    # no base64 ZIP content
    md = reports.to_markdown(r)
    assert "com.sbi.rewardz.points" in md and "RECEIVE_SMS" in md


def test_api_refuses_oversized_apks_with_413(engine, monkeypatch):
    from api.main import create_app
    monkeypatch.setattr("trustguard.engine.MAX_APK_BYTES", 2_000)
    called = []
    monkeypatch.setattr("trustguard.extract.apk.analyze_apk", lambda *a, **k: called.append(1))
    r = TestClient(create_app(engine)).post("/v1/scan/file", files={"file": ("big.apk", F.sms_stealer(), "application/vnd.android.package-archive")})
    assert r.status_code == 413 and not called


def test_api_scans_an_apk(engine):
    from api.main import create_app
    r = TestClient(create_app(engine)).post("/v1/scan/file", files={"file": ("SBI_Rewardz.apk", F.sms_stealer(), "application/octet-stream")})
    assert r.status_code == 200 and r.json()["app"]["package"] == "com.sbi.rewardz.points"
