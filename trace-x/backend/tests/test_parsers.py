"""Hashing, file validation and parser tests."""
from __future__ import annotations

import hashlib

import pytest

from app.parsers import dispatch, log_parser
from app.services import storage


def test_sha256_of_known_content():
    data = b"trace-x integrity test vector\n"
    assert hashlib.sha256(data).hexdigest() == hashlib.sha256(data).hexdigest()
    from app.integrity.verify import compute_file_sha256
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(data)
        path = fh.name
    assert compute_file_sha256(__import__("pathlib").Path(path)) == hashlib.sha256(data).hexdigest()


def test_safe_filename_generation():
    name = "../../etc/passwd with spaces.txt"
    stored = storage.generate_stored_filename(name)
    assert "/" not in stored and ".." not in stored and "\\" not in stored
    assert stored.endswith(".txt")
    assert storage.sanitize_original_name(name).startswith(".._.._etc_passwd")


def test_dangerous_extension_rejected():
    ok, message = storage.validate_extension("exe")
    assert not ok and "Unsupported" in message


def test_supported_extension_ok():
    for ext in ("log", "csv", "json", "eml", "txt", "png"):
        ok, message = storage.validate_extension(ext)
        assert ok
    ok, message = storage.validate_extension("zip")
    assert ok and message == "metadata_only"


def test_log_parser_ssh_and_kv():
    text = """2026-10-07 10:01:05 WEB-SRV-01 sshd[2312]: Failed password for user a.carter from 203.0.113.10 port 51234
2026-10-07 10:04:41 WEB-SRV-01 sshd[2340]: Accepted password for user a.carter from 203.0.113.10 port 51260
2026-10-07 10:07:19 WEB-SRV-01 sudo: a.carter : TTY=pts/0 ; USER=root ; COMMAND=/bin/cat /etc/shadow
"""
    events = log_parser.parse(text, evidence_id=1, evidence_code="EV-0001")
    types = [e["event_type"] for e in events]
    assert types == ["LOGIN_FAILURE", "LOGIN_SUCCESS", "PRIVILEGE_ESCALATION"]
    assert events[0]["username"] == "a.carter"
    assert events[0]["source_ip"] == "203.0.113.10"
    assert events[0]["timestamp"] == "2026-10-07 10:01:05"
    # every event references its source evidence (traceability invariant)
    assert all(e["source_evidence_id"] == "EV-0001" for e in events)


def test_log_parser_key_value_block_format():
    text = """2026-10-07 10:22:31
User: admin
Source IP: 185.203.116.44
Action: login
Status: failed

2026-10-07 10:23:00
User: admin
Source IP: 185.203.116.44
Action: login
Status: success
"""
    events = log_parser.parse(text, evidence_id=1, evidence_code="EV-0001")
    assert len(events) == 2
    assert events[0]["username"] == "admin"
    assert events[0]["status"] == "failed"
    assert events[1]["status"] == "success"


def test_csv_parser_column_detection():
    text = """timestamp,source_ip,destination_ip,destination_port,bytes,event,user
2026-10-07T10:18:04,192.0.2.50,198.51.100.23,443,851968000,outbound_transfer,a.carter
"""
    from app.parsers import csv_parser
    events, summary = csv_parser.parse(text, 1, "EV-0001")
    assert len(events) == 1
    e = events[0]
    assert e["source_ip"] == "192.0.2.50"
    assert e["byte_count"] == 851968000
    assert e["username"] == "a.carter"
    assert summary["columns_detected"]["destination_ip"] == "destination_ip"


def test_json_parser_recursive():
    text = """{
      "alerts": [
        {"id": "ALR-1", "timestamp": "2026-10-07T10:04:45", "type": "brute_force_detected",
         "severity": "high", "source_ip": "203.0.113.10", "username": "a.carter",
         "message": "Multiple failed authentications."}
      ]
    }"""
    from app.parsers import json_parser
    events, summary = json_parser.parse(text, 1, "EV-0001")
    assert len(events) == 1
    assert events[0]["source_ip"] == "203.0.113.10"
    assert "ALR-1" in events[0]["message"]
    assert events[0]["source_evidence_id"] == "EV-0001"


def test_json_parser_invalid():
    from app.parsers import json_parser
    events, summary = json_parser.parse("{not json", 1, "EV-0001")
    assert events == [] and "Invalid JSON" in summary["reason"]


def test_email_parser():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "demo" / "evidence" / "email.txt").read_text(encoding="utf-8")
    from app.parsers import email_parser
    events, summary = email_parser.parse(text, 1, "EV-0001")
    assert len(events) >= 1
    assert events[0]["event_type"] == "EMAIL_RECEIVED"
    assert summary["from"] == "security-alert@secure-notify.example"
    assert "a.carter@corp.example" == summary["to"]
    assert any("portal-secure.example-login.tk" in u for u in summary["urls"])


def test_dispatch_by_extension():
    events, summary, name = dispatch.parse_evidence("png", b"\x89PNG fake", 1, "EV-0001")
    assert events == [] and name == "image"
    events, summary, name = dispatch.parse_evidence("pcap", b"\xd4\xc3\xb2\xa1", 1, "EV-0001")
    assert name == "pcap"
