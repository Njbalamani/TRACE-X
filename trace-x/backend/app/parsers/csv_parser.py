"""CSV parser with automatic column detection via alias mapping."""
from __future__ import annotations

import csv
import io

from app.parsers.base import extract_domain, extract_first_url, normalize_event, normalize_timestamp

COLUMN_ALIASES = {
    "timestamp": "timestamp", "time": "timestamp", "date": "timestamp", "datetime": "timestamp",
    "date/time": "timestamp", "event_time": "timestamp", "@timestamp": "timestamp",
    "user": "username", "username": "username", "account": "username", "user_name": "username",
    "source_ip": "source_ip", "src_ip": "source_ip", "src": "source_ip", "source": "source_ip",
    "sourceip": "source_ip", "client_ip": "source_ip", "remote_ip": "source_ip", "ip": "source_ip",
    "destination_ip": "destination_ip", "dest_ip": "destination_ip", "dst_ip": "destination_ip",
    "dest": "destination_ip", "dst": "destination_ip", "destination": "destination_ip",
    "target_ip": "destination_ip",
    "event": "declared_type", "event_type": "declared_type", "type": "declared_type", "category": "declared_type",
    "action": "action", "operation": "action",
    "status": "status", "result": "status", "outcome": "status",
    "hostname": "hostname", "host": "hostname", "computer": "hostname", "server": "hostname",
    "port": "port", "destination_port": "port", "dst_port": "port", "dest_port": "port",
    "file": "file_path", "file_path": "file_path", "filename": "file_path", "path": "file_path",
    "bytes": "byte_count", "size": "byte_count", "bytes_sent": "byte_count", "sent_bytes": "byte_count",
    "session_id": "session_id", "session": "session_id",
    "process_id": "process_id", "pid": "process_id",
    "domain": "domain", "url": "url",
    "hash": "file_hash", "file_hash": "file_hash", "sha256": "file_hash",
    "message": "message", "msg": "message", "description": "message",
}


def parse(text: str, evidence_id: int, evidence_code: str) -> tuple[list[dict], dict]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return [], {"reason": "CSV had no header row"}

    header_map: dict[str, str] = {}
    for col in reader.fieldnames:
        canonical = COLUMN_ALIASES.get(col.strip().lower())
        if canonical:
            header_map[col] = canonical

    events: list[dict] = []
    skipped = 0
    for row in reader:
        fields: dict = {}
        for col, canonical in header_map.items():
            value = (row.get(col) or "").strip()
            if value == "":
                continue
            if canonical == "byte_count":
                digits = "".join(ch for ch in value if ch.isdigit())
                if digits:
                    fields[canonical] = int(digits)
            else:
                fields[canonical] = value
        if not fields.get("timestamp") and not fields.get("declared_type") and not fields.get("message"):
            skipped += 1
            continue
        fields.setdefault("timestamp", normalize_timestamp(fields.get("timestamp")) or "")
        if "url" not in fields and fields.get("message"):
            u = extract_first_url(fields["message"])
            if u:
                fields["url"] = u
                fields.setdefault("domain", extract_domain(u))
        fields["raw_line"] = ", ".join(f"{k}={v}" for k, v in row.items() if v) [:2000]
        events.append(normalize_event(evidence_id, evidence_code, **fields))

    summary = {
        "columns_detected": {c: header_map[c] for c in header_map},
        "rows_total": (len(events) + skipped),
        "rows_normalized": len(events),
        "rows_skipped": skipped,
    }
    return events, summary
