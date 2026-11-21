"""JSON parser — recursively walks JSON structures and extracts
security-relevant records into normalized events."""
from __future__ import annotations

import json

from app.parsers.base import (
    extract_domain,
    extract_first_url,
    extract_ips,
    normalize_event,
)

TIME_KEYS = {"timestamp", "time", "date", "datetime", "@timestamp", "event_time", "ts"}
REQUIRED_HINTS = {"event", "event_type", "type", "action", "status", "message", "msg",
                  "severity", "source_ip", "username", "url", "file"}


def _walk(node, path: str = ""):
    if isinstance(node, dict):
        if TIME_KEYS & {k.lower() for k in node} and ({k.lower() for k in node} & REQUIRED_HINTS or _has_nested_payload(node)):
            yield node, path
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            yield from _walk(item, f"{path}[{idx}]")


def _has_nested_payload(node: dict) -> bool:
    return any(isinstance(v, (dict, list)) for v in node.values())


def _flatten(node, prefix: str = "", depth: int = 0) -> dict:
    """Flatten nested dicts so alias lookup can find fields like alert.source.ip."""
    flat: dict = {}
    if depth > 4:
        return flat
    if isinstance(node, dict):
        for k, v in node.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                flat.update(_flatten(v, key, depth + 1))
            else:
                flat[key] = v
    return flat


def _pick(flat: dict, *names):
    for n in names:
        if n in flat and flat[n] not in (None, ""):
            return flat[n]
    # suffix match (e.g. alert.source_ip or item.user)
    for k, v in flat.items():
        lk = k.lower().rsplit(".", 1)[-1]
        if lk in names and v not in (None, ""):
            return v
    return None


def parse(text: str, evidence_id: int, evidence_code: str) -> tuple[list[dict], dict]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], {"reason": f"Invalid JSON: {exc.msg} (line {exc.lineno})"}

    events: list[dict] = []
    for node, path in _walk(data):
        flat = _flatten(node)
        ts = _pick(flat, "timestamp", "time", "date", "datetime", "@timestamp", "event_time", "ts")
        message = _pick(flat, "message", "msg", "description", "details", "summary")
        declared = _pick(flat, "event_type", "event", "type", "category")
        fields = {
            "timestamp": ts,
            "declared_type": str(declared).upper() if declared else None,
            "username": _pick(flat, "username", "user", "account"),
            "source_ip": _pick(flat, "source_ip", "src_ip", "src", "source", "client_ip"),
            "destination_ip": _pick(flat, "destination_ip", "dest_ip", "dst_ip", "dest", "dst", "destination"),
            "hostname": _pick(flat, "hostname", "host", "computer", "server"),
            "action": _pick(flat, "action", "operation"),
            "status": _pick(flat, "status", "result", "outcome"),
            "port": _pick(flat, "port", "destination_port", "dst_port"),
            "file_path": _pick(flat, "file_path", "file", "filename", "path"),
            "byte_count": _pick(flat, "bytes", "size", "bytes_transferred", "sent_bytes"),
            "session_id": _pick(flat, "session_id", "session"),
            "process_id": _pick(flat, "process_id", "pid"),
            "domain": _pick(flat, "domain"),
            "url": _pick(flat, "url", "uri"),
            "file_hash": _pick(flat, "file_hash", "sha256", "hash", "md5"),
            "message": message if isinstance(message, str) else json.dumps(message) if message else None,
            "raw_line": json.dumps(node)[:2000],
        }
        # Regex enrichment
        blob = json.dumps(node)
        if not fields.get("url"):
            fields["url"] = extract_first_url(blob)
        if fields.get("url") and not fields.get("domain"):
            fields["domain"] = extract_domain(fields["url"])
        if not fields.get("source_ip"):
            ips = extract_ips(blob)
            if ips:
                fields["source_ip"] = ips[0]
        if not fields.get("destination_ip"):
            ips = extract_ips(blob)
            if len(ips) > 1:
                fields["destination_ip"] = ips[1]
        # keep an external reference (e.g. alert id) in the message
        ref = _pick(flat, "id", "alert_id", "event_id")
        if ref is not None and fields.get("message"):
            fields["message"] = f"[{ref}] {fields['message']}"
        events.append(normalize_event(evidence_id, evidence_code, **fields))

    summary = {
        "records_found": len(events),
        "note": "JSON walked recursively; records with timestamp + payload normalized" if events else "No event-like records found",
    }
    return events, summary
