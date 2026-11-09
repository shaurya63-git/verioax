import io
import json

import pytest
from conftest import ECHALLAN_SCAM

from trustguard.engine import InputError
from trustguard.schemas import AnalysisMode, RiskLevel

RAW_VALUES = ["Ravi Kumar", "MH12AB1234"]


def test_empty_and_oversized_input(engine):
    with pytest.raises(InputError):
        engine.scan_message("   ")
    with pytest.raises(InputError):
        engine.scan_message("x" * 20_001)
    with pytest.raises(InputError):
        engine.scan_url("not a url at all")
    with pytest.raises(InputError):
        engine.scan_url("javascript:alert(1) x")


def test_fake_echallan_is_high_risk_and_explained(engine):
    r = engine.scan_message(ECHALLAN_SCAM, sender="+91 98765 43210").result
    assert r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    cats = {f.category.value for f in r.scam_findings}
    assert "government_impersonation" in cats
    assert any(a.id == "verify_challan" for a in r.recommended_actions)
    assert r.urls and r.urls[0].final_assessment in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert r.verdict_title.startswith("Likely scam")


def test_genuine_messages_stay_low(engine):
    for text, sender in [("Urgent: team meeting moved to 3pm today, please join immediately.", None),
                         ("123456 is your OTP for login. Do not share it with anyone. -HDFC Bank", "VM-HDFCBK-T"),
                         ("Check your challan at https://echallan.parivahan.gov.in/ - Transport Dept", "VM-PARIVA-G")]:
        r = engine.scan_message(text, sender=sender).result
        assert r.overall_risk == RiskLevel.LOW, (text, r.processing.rules_applied)


def test_results_are_deterministic(engine):
    a = engine.scan_message(ECHALLAN_SCAM).result
    b = engine.scan_message(ECHALLAN_SCAM).result
    assert (a.risk_score, a.overall_risk, a.model_confidence) == (b.risk_score, b.overall_risk, b.model_confidence)
    assert a.processing.config_hash == b.processing.config_hash


def test_no_raw_pii_in_result_or_history(engine):
    out = engine.scan_message(ECHALLAN_SCAM, sender="+91 98765 43210")
    blob = out.result.model_dump_json()
    stored = engine.store.get(out.result.scan_id).model_dump_json()
    for raw in RAW_VALUES + ["98765 43210"]:
        assert raw not in blob and raw not in stored
    assert "Ravi Kumar" in out.restricted.original_text                    # raw content stays in memory only


def test_redacted_highlights_line_up(engine):
    r = engine.scan_message(ECHALLAN_SCAM).result
    f = next(x for x in r.scam_findings if x.indicator == "payment_request")
    assert f.matched_text.startswith(r.redacted_text[f.redacted_start:f.redacted_end])
    # "pending e-challan" and "Pay immediately" are one finding with two highlighted places, scored once
    assert len(f.more_spans) == 1 and [x.indicator for x in r.scam_findings].count("payment_request") == 1
    sp = f.more_spans[0]
    assert r.redacted_text[sp.redacted_start:sp.redacted_end] == ECHALLAN_SCAM[sp.start:sp.end] == "Pay immediately"


def test_pii_only_mode(engine):
    r = engine.scan_message("Name: Arjun Mehta, PAN ABCPE1234F", mode=AnalysisMode.PII).result
    assert r.risk_basis == "privacy" and r.scam is None and r.overall_risk == RiskLevel.MEDIUM and r.pii.findings


def test_scam_only_mode_still_redacts_for_storage(engine):
    r = engine.scan_message(ECHALLAN_SCAM, mode=AnalysisMode.SCAM).result
    assert r.pii is None and "Ravi Kumar" not in (r.redacted_text or "")


def test_url_scan(engine):
    r = engine.scan_url("https://parivahan-gov.in/pay").result
    assert r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) and r.urls[0].checks
    assert engine.scan_url("https://example.org/").result.overall_risk == RiskLevel.INCONCLUSIVE


def test_link_scan_actions_talk_about_the_link_not_a_message(engine):
    acts = {a.id: a for a in engine.scan_url("https://parivahan-gov.in/pay").result.recommended_actions}
    assert acts["report"].title == "Report the link" and "sender" not in acts["verify_official"].title.lower()
    msg = {a.id: a for a in engine.scan_message("Your e-challan of Rs 500 is pending, pay now: https://parivahan-gov.in/pay").result.recommended_actions}
    assert msg["report"].title == "Report it"


def test_file_scans(engine):
    import docx
    from reportlab.pdfgen import canvas

    r = engine.scan_file("msg.txt", ECHALLAN_SCAM.encode()).result
    assert r.input_type.value == "file" and r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    csv_bytes = b"name,phone\nArjun Mehta,9876543210\n"
    r = engine.scan_file("people.csv", csv_bytes, mode=AnalysisMode.PII).result
    assert {f.location for f in r.pii.findings} >= {"row 2"}

    d = docx.Document()
    d.add_paragraph("Dear Ravi Kumar, your SBI account will be blocked. Update KYC at http://sbi-kyc-update.com/")
    buf = io.BytesIO()
    d.save(buf)
    r = engine.scan_file("notice.docx", buf.getvalue()).result
    assert r.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    pbuf = io.BytesIO()
    c = canvas.Canvas(pbuf)
    c.drawString(72, 750, "Your e-challan of Rs 500 is pending. Pay now at https://echallan-pay.vip/")
    c.showPage()
    c.drawString(72, 750, "Contact: arjun@example.com")
    c.save()
    r = engine.scan_file("challan.pdf", pbuf.getvalue()).result
    assert any(f.location == "page 2" for f in r.pii.findings)

    with pytest.raises(InputError):
        engine.scan_file("x.exe", b"MZ\x90\x00")


def test_history_filters(engine):
    engine.scan_message(ECHALLAN_SCAM)
    engine.scan_message("Lunch at 1?")
    rows = engine.store.list(risk=["HIGH", "CRITICAL"])
    assert rows and all(r["overall_risk"] in ("HIGH", "CRITICAL") for r in rows)
    assert engine.store.list(category="government_impersonation")
    assert json.loads(engine.store.get(rows[0]["scan_id"]).model_dump_json())["scan_id"] == rows[0]["scan_id"]
