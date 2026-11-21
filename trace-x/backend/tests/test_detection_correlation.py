"""Deterministic detection rules + correlation engine tests (db-level)."""
from __future__ import annotations

from datetime import datetime


def _mk_event(i, **kw):
    """Build a lightweight event stub (attributes only; rules never touch db)."""
    class E:
        id = i
        code = kw.get("code", f"EVT-{i:04d}")
        evidence = None

    e = E()
    defaults = dict(timestamp=None, event_type="GENERIC", username=None, source_ip=None,
                    destination_ip=None, hostname=None, action=None, status=None,
                    file_path=None, byte_count=None, domain=None, url=None,
                    file_hash=None, session_id=None, process_id=None, message=None,
                    raw_line=None, is_suspicious=False, severity=None)
    defaults.update(kw)
    for k, v in defaults.items():
        setattr(e, k, v)
    return e


def test_brute_force_rule():
    from app.analyzers.detection import run_detections
    events = [_mk_event(i, event_type="LOGIN_FAILURE", username="a.carter",
                        source_ip="203.0.113.10",
                        timestamp=f"2026-10-07 10:0{i}:00")
              for i in range(1, 8)]  # 7 failures within 3 minutes
    detections = run_detections(events)
    bf = [d for d in detections if d["rule_id"] == "BRUTE_FORCE"]
    assert len(bf) == 1
    assert bf[0]["severity"] in ("Medium", "High")
    assert all(c.startswith("EVT-") for c in bf[0]["event_ids"])


def test_account_compromise_rule():
    from app.analyzers.detection import run_detections
    events = [
        _mk_event(1, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:01:00"),
        _mk_event(2, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:02:00"),
        _mk_event(3, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:03:00"),
        _mk_event(4, event_type="LOGIN_SUCCESS", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:04:00"),
    ]
    detections = run_detections(events)
    comp = [d for d in detections if d["rule_id"] == "ACCOUNT_COMPROMISE"]
    assert len(comp) == 1
    assert comp[0]["classification"] == "Likely"
    assert comp[0]["confidence"] == "High"
    assert "EVT-0004" in comp[0]["event_ids"]


def test_no_false_compromise_different_ip():
    from app.analyzers.detection import run_detections
    events = [
        _mk_event(1, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:01:00"),
        _mk_event(2, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:02:00"),
        _mk_event(3, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:03:00"),
        _mk_event(4, event_type="LOGIN_SUCCESS", username="a.carter",
                  source_ip="192.0.2.31", timestamp="2026-10-07 10:04:00"),
    ]
    detections = run_detections(events)
    assert not [d for d in detections if d["rule_id"] == "ACCOUNT_COMPROMISE"]


def test_large_transfer_rule():
    from app.analyzers.detection import run_detections
    events = [_mk_event(1, event_type="DATA_TRANSFER", username="a.carter",
                        source_ip="192.0.2.50", destination_ip="198.51.100.23",
                        byte_count=851_968_000, timestamp="2026-10-07 10:18:04")]
    detections = run_detections(events)
    lt = [d for d in detections if d["rule_id"] == "LARGE_TRANSFER"]
    assert len(lt) == 1 and lt[0]["attack_stage"] == "Exfiltration"


def test_sensitive_file_access_rule():
    from app.analyzers.detection import run_detections
    events = [_mk_event(1, event_type="FILE_ACCESS", username="a.carter",
                        file_path="/etc/shadow", timestamp="2026-10-07 10:07:20")]
    detections = run_detections(events)
    assert any(d["rule_id"] == "SENSITIVE_FILE_ACCESS" for d in detections)


def test_normal_activity_not_flagged():
    from app.analyzers.detection import run_detections
    events = [
        _mk_event(1, event_type="LOGIN_SUCCESS", username="m.lee",
                  source_ip="192.0.2.31", timestamp="2026-10-07 09:59:00"),
        _mk_event(2, event_type="FILE_ACCESS", username="m.lee",
                  file_path="/home/m.lee/notes.txt", timestamp="2026-10-07 09:59:30"),
    ]
    for e in events:
        e.is_suspicious = True  # suspicious_ip rule requires pre-flagged events
    detections = run_detections(events)
    rule_ids = {d["rule_id"] for d in detections}
    assert not rule_ids & {"BRUTE_FORCE", "ACCOUNT_COMPROMISE", "LARGE_TRANSFER", "SUSPICIOUS_IP"}


def test_correlation_links_by_ip_and_user():
    from app.services.correlation_service import build_correlation
    events = [
        _mk_event(1, event_type="LOGIN_FAILURE", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:01:00", is_suspicious=True),
        _mk_event(2, event_type="LOGIN_SUCCESS", username="a.carter",
                  source_ip="203.0.113.10", timestamp="2026-10-07 10:04:00", is_suspicious=True),
        _mk_event(3, event_type="PRIVILEGE_ESCALATION", username="a.carter",
                  hostname="WEB-SRV-01", timestamp="2026-10-07 10:07:00", is_suspicious=True),
        _mk_event(4, event_type="LOGIN_SUCCESS", username="m.lee",
                  source_ip="192.0.2.31", timestamp="2026-10-07 09:59:00", is_suspicious=False),
    ]
    result = build_correlation(events)
    assert len(result["chains"]) == 1
    chain = result["chains"][0]
    assert chain["suspicious_count"] == 3
    assert set(chain["shared_attributes"]["username"]) == {"a.carter"}
    assert set(chain["shared_attributes"]["source_ip"]) == {"203.0.113.10"}
    # benign event m.lee must not be inside the attack chain
    assert all("m.lee" not in str(s) for s in chain["sequence"])


def test_stage_classification_only_with_evidence():
    from app.analyzers.stages import build_stages
    events = [
        _mk_event(1, event_type="LOGIN_FAILURE", username="a.carter",
                  timestamp="2026-10-07 10:01:00", is_suspicious=True),
        _mk_event(2, event_type="DATA_TRANSFER", username="a.carter",
                  timestamp="2026-10-07 10:18:00", is_suspicious=True),
        _mk_event(3, event_type="LOGIN_SUCCESS", username="m.lee",
                  timestamp="2026-10-07 09:59:00", is_suspicious=False),
    ]
    stages = build_stages(events)
    names = [s["stage"] for s in stages]
    assert "Credential Access" in names and "Exfiltration" in names
    assert "Impact" not in names and "Discovery" not in names  # no evidence for those
    for stage in stages:
        assert stage["event_ids"], "every reported stage must have supporting events"
