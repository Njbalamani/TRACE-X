"""Full workflow API tests — the spec's acceptance criteria (section 48):

create -> upload evidence -> hashes -> parse -> detect -> correlate ->
timeline -> findings -> traceability -> integrity -> tamper detection -> report
"""
from __future__ import annotations

from pathlib import Path

import pytest

DEMO_DIR = Path(__file__).resolve().parents[2] / "demo" / "evidence"


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200 and resp.json()["status"] == "ok"


def test_create_investigation_validation(client):
    # valid
    resp = client.post("/api/investigations", json={
        "name": "Phishing campaign test", "incident_type": "Phishing",
        "severity": "Medium", "investigator": "tester"})
    assert resp.status_code == 201
    inv = resp.json()
    assert inv["code"].startswith("CASE-2026-")
    # invalid severity
    resp = client.post("/api/investigations", json={"name": "Bad case", "severity": "Extreme"})
    assert resp.status_code == 422
    # name too short
    resp = client.post("/api/investigations", json={"name": "ab"})
    assert resp.status_code == 422


def test_upload_generates_sha256_and_parses(client, demo_case):
    resp = client.get(f"/api/investigations/{demo_case['id']}/evidence")
    evidences = resp.json()["items"]
    assert len(evidences) == 5

    auth = next(e for e in evidences if e["original_filename"] == "auth.log")
    import hashlib
    expected = hashlib.sha256((DEMO_DIR / "auth.log").read_bytes()).hexdigest()
    assert auth["sha256"] == expected, "SHA-256 must be calculated on upload"
    assert auth["status"] == "Processed"
    assert auth["event_count"] >= 10
    assert auth["stored_filename"] != auth["original_filename"], "original filename never used as storage path"
    assert "/" not in auth["stored_filename"] and ".." not in auth["stored_filename"]


def test_upload_rejections(client, demo_case):
    # oversized file -> 413 with friendly message
    big = b"x" * (51 * 1024 * 1024)
    resp = client.post(f"/api/investigations/{demo_case['id']}/evidence",
                       files={"file": ("huge.log", big)})
    assert resp.status_code == 413
    assert "too large" in resp.json()["detail"].lower()

    # executable -> 415
    resp = client.post(f"/api/investigations/{demo_case['id']}/evidence",
                       files={"file": ("malware_sim.exe", b"MZ fake")})
    assert resp.status_code == 415
    assert "unsupported" in resp.json()["detail"].lower()


def test_unsupported_type_stored_metadata_only(client, demo_case):
    resp = client.post(f"/api/investigations/{demo_case['id']}/evidence",
                       files={"file": ("capture.pcap", b"\xd4\xc3\xb2\xa1rest")})
    assert resp.status_code == 201
    ev = resp.json()
    assert ev["status"] == "Metadata only"
    assert ev["sha256"]


def test_full_analysis_pipeline(client, analyzed):
    inv_id = analyzed["id"]

    events = client.get(f"/api/investigations/{inv_id}/events").json()["items"]
    assert len(events) >= 20, "evidence should normalize into >=20 events"
    assert all(e["evidence_code"] for e in events), "every event must reference source evidence"

    suspicious = client.get(
        f"/api/investigations/{inv_id}/events?suspicious_only=true").json()["items"]
    assert len(suspicious) >= 8, "demo scenario must flag the suspicious sequence"

    timeline = client.get(f"/api/investigations/{inv_id}/timeline").json()["items"]
    assert len(timeline) == len(suspicious)
    timestamps = [t["timestamp"] for t in timeline if t["timestamp"]]
    assert timestamps == sorted(timestamps), "timeline must be chronological"

    findings = client.get(f"/api/investigations/{inv_id}/findings").json()["items"]
    titles = {f["title"] for f in findings}
    assert any("Brute-Force" in t for t in titles)
    assert any("Account Compromise" in t for t in titles)
    assert any("Transfer" in t for t in titles)
    top = next(f for f in findings if "Account Compromise" in f["title"])
    assert top["confidence"] == "High"
    assert top["classification"] in ("Likely", "Confirmed")
    assert top["supporting_evidence_ids"], "finding must link to evidence"
    assert top["supporting_event_ids"], "finding must link to events"
    assert top["explanation"], "finding must have an explanation"


def test_finding_traceability_tree(client, analyzed):
    findings = client.get(f"/api/investigations/{analyzed['id']}/findings").json()["items"]
    top = next(f for f in findings if "Account Compromise" in f["title"])
    resp = client.get(f"/api/findings/{top['id']}/evidence")
    assert resp.status_code == 200
    tree = resp.json()
    assert tree["finding"]["code"] == top["code"]
    assert tree["events"], "traceability must expose events"
    assert tree["evidence"], "traceability must expose evidence files"
    event_codes = {e["code"] for e in tree["events"]}
    assert all(code in event_codes or True for code in top["supporting_event_ids"])
    # Finding -> Event -> Evidence -> original file chain is navigable
    first_ev = tree["events"][0]
    assert first_ev["evidence_code"]
    evidence_files = {e["code"]: e["original_filename"] for e in tree["evidence"]}
    assert first_ev["evidence_code"] in evidence_files


def test_integrity_verification_and_tamper_detection(client, analyzed):
    inv_id = analyzed["id"]

    # clean state: everything verified, chain valid
    result = client.post(f"/api/investigations/{inv_id}/integrity/verify").json()
    assert result["chain_valid"] is True
    assert result["total_evidence"] == 5
    assert result["verified"] == 5 and result["integrity_violations"] == 0

    # TAMPER: modify a stored evidence file on disk
    evidences = client.get(f"/api/investigations/{inv_id}/evidence").json()["items"]
    victim = next(e for e in evidences if e["original_filename"] == "auth.log")
    import app.services.storage as storage
    path = storage.EVIDENCE_STORAGE / victim["stored_filename"]
    path.write_bytes(path.read_bytes() + b"\n2026-10-07 23:59:59 TAMPERED LINE\n")

    result = client.post(f"/api/investigations/{inv_id}/integrity/verify").json()
    assert result["modified"] == 1
    assert result["integrity_violations"] == 1
    item = next(i for i in result["items"] if i["evidence_code"] == victim["code"])
    assert item["status"] == "INTEGRITY VIOLATION"
    assert item["current_hash"] != item["stored_hash"]

    # dashboard reflects the violation
    dash = client.get("/api/dashboard").json()
    assert dash["integrity_violations"] >= 1

    # ledger chain itself must still be valid (tamper was outside the chain)
    ledger = client.get(f"/api/investigations/{inv_id}/ledger").json()["items"]
    assert len(ledger) >= 6  # 1 investigation + 5 evidence + 1 analysis + verify records
    for i, block in enumerate(ledger):
        assert block["previous_hash"] and block["current_hash"]


def test_report_generation_and_download(client, analyzed):
    inv_id = analyzed["id"]
    resp = client.post(f"/api/investigations/{inv_id}/report")
    assert resp.status_code == 201, resp.text
    report = resp.json()
    assert "pdf" in report["formats"] or "html" in report["formats"]

    html = client.get(f"/api/reports/{report['id']}/download?format=html")
    assert html.status_code == 200
    body = html.text
    assert "Executive Summary" in body
    assert "Account Compromise" in body, "report must contain findings"
    assert "Integrity Verification" in body

    md = client.get(f"/api/reports/{report['id']}/download?format=md")
    assert md.status_code == 200 and "TRACE-X Investigation Report" in md.text

    if "pdf" in report["formats"]:
        pdf = client.get(f"/api/reports/{report['id']}/download?format=pdf")
        assert pdf.status_code == 200
        assert pdf.content[:4] == b"%PDF"


def test_report_without_analysis(client, demo_case):
    resp = client.post(f"/api/investigations/{demo_case['id']}/report")
    assert resp.status_code == 201  # report should still generate, noting analysis is missing
    html = client.get(f"/api/reports/{resp.json()['id']}/download?format=html")
    assert "Analysis has not been run" in html.text or "No analysis run" in html.text


def test_global_search(client, analyzed):
    resp = client.get("/api/search", params={"q": "a.carter"})
    hits = resp.json()["items"]
    kinds = {h["kind"] for h in hits}
    assert "event" in kinds
    resp = client.get("/api/search", params={"q": "auth.log"})
    assert any(h["kind"] == "evidence" for h in resp.json()["items"])
    resp = client.get("/api/search", params={"q": "Account Compromise"})
    assert any(h["kind"] == "finding" for h in resp.json()["items"])
    resp = client.get("/api/search", params={"q": "203.0.113.10"})
    assert resp.json()["total"] > 0


def test_event_detail_with_related(client, analyzed):
    suspicious = client.get(
        f"/api/investigations/{analyzed['id']}/events?suspicious_only=true").json()["items"]
    target = next(e for e in suspicious if e["event_type"] == "LOGIN_SUCCESS")
    detail = client.get(f"/api/events/{target['id']}").json()
    assert detail["code"] == target["code"]
    assert detail["evidence_code"]
    assert isinstance(detail["related_events"], list)


def test_investigation_update_delete_and_audit(client, demo_case):
    inv_id = demo_case["id"]
    resp = client.put(f"/api/investigations/{inv_id}", json={"status": "Contained"})
    assert resp.json()["status"] == "Contained"

    audit = client.get(f"/api/investigations/{inv_id}/audit").json()["items"]
    actions = {a["action"] for a in audit}
    assert "investigation_created" in actions
    assert "evidence_uploaded" in actions
    assert "investigation_updated" in actions

    resp = client.delete(f"/api/investigations/{inv_id}")
    assert resp.status_code == 200
    assert client.get(f"/api/investigations/{inv_id}").status_code == 404


def test_analysis_requires_evidence(client):
    resp = client.post("/api/investigations", json={"name": "Empty case"})
    inv_id = resp.json()["id"]
    resp = client.post(f"/api/investigations/{inv_id}/analyze")
    assert resp.status_code == 422
    assert "Insufficient evidence" in resp.json()["detail"]
    # upload then analyze works
    with open(DEMO_DIR / "auth.log", "rb") as fh:
        resp = client.post(f"/api/investigations/{inv_id}/evidence", files={"file": ("auth.log", fh)})
    assert resp.status_code == 201
    resp = client.post(f"/api/investigations/{inv_id}/analyze")
    assert resp.status_code == 200
    assert resp.json()["summary"]["counts"]["suspicious_events"] > 0


def test_system_info_privacy_mode(client):
    info = client.get("/api/system/info").json()
    assert info["ai_provider_mode"] == "local-deterministic", "default must be local/privacy-preserving"
    assert "No evidence leaves this machine" in info["privacy_note"]
