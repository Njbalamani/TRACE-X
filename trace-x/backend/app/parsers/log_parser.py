"""Text-log parser. Handles:
- Key:value records (spec example format), grouped by leading timestamp line
- OpenSSH-style auth logs (Failed/Accepted password, sudo)
- Firewall-style 'ALLOW TCP src:port -> dst:port'
- Falls back to timestamp + message extraction with regex enrichment.
"""
from __future__ import annotations

import re

from app.parsers.base import (
    extract_domain,
    extract_first_url,
    normalize_event,
)

TS_LINE_RE = re.compile(r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*(.*)$")
KV_RE = re.compile(r"([A-Za-z_ ][A-Za-z0-9_ /-]{1,30}?)\s*[:=]\s*([^:=]{1,300}?)(?=\s+[A-Za-z_ ][A-Za-z0-9_ /-]{1,30}\s*[:=]|$)")
SSH_FAIL_RE = re.compile(r"Failed \S+ for (?:invalid user |user |unknown user )?(\S+) from ((?:\d{1,3}\.){3}\d{1,3})(?: port (\d+))?", re.I)
SSH_OK_RE = re.compile(r"Accepted \S+ for (?:user )?(\S+) from ((?:\d{1,3}\.){3}\d{1,3})(?: port (\d+))?", re.I)
SUDO_RE = re.compile(r"(\S+)\s*:.*?USER=(\S+).*?COMMAND=(.*)", re.I)
FW_RE = re.compile(r"\b(ALLOW|DENY|ACCEPT|DROP|REJECT|BLOCK)\b\s*(TCP|UDP|ICMP)?\s+"
                   r"((?:\d{1,3}\.){3}\d{1,3})[:\.](\d+)\s*->\s*((?:\d{1,3}\.){3}\d{1,3})[:\.](\d+)", re.I)
SIZE_RE = re.compile(r"\bsize[=: ]+(\d+)\b", re.I)
HOST_RE = re.compile(r"^\s*([\w.-]+\w)\s+\w+[\[\d]*\]*\s*:")  # 'host proc:' prefix

KV_FIELD_MAP = {
    "user": "username", "username": "username",
    "source ip": "source_ip", "src ip": "source_ip", "source": "source_ip", "src": "source_ip",
    "ip": "source_ip", "client ip": "source_ip", "remote ip": "source_ip",
    "destination ip": "destination_ip", "dest ip": "destination_ip", "dst ip": "destination_ip",
    "destination": "destination_ip", "dest": "destination_ip",
    "action": "action", "event": "declared_type", "event type": "declared_type", "type": "declared_type",
    "status": "status", "result": "status",
    "hostname": "hostname", "host": "hostname", "computer": "hostname", "server": "hostname",
    "port": "port", "dest port": "port", "destination port": "port",
    "file": "file_path", "file name": "file_path", "filename": "file_path", "path": "file_path",
    "bytes": "byte_count", "size": "byte_count",
    "session id": "session_id", "session": "session_id",
    "process id": "process_id", "pid": "process_id",
    "domain": "domain", "url": "url",
    "hash": "file_hash", "sha256": "file_hash",
    "message": "message", "msg": "message",
}


def _clean(v: str) -> str:
    return v.strip().strip('"').strip("'").rstrip(",;").strip()


def _kv_fields(text: str) -> dict:
    """Extract key:value pairs from a line of free text."""
    fields: dict = {}
    for key, value in KV_RE.findall(text):
        k = _clean(key).lower()
        if k in KV_FIELD_MAP:
            v = _clean(value)
            if k in ("bytes", "size"):
                digits = re.sub(r"[^\d]", "", v)
                if digits:
                    fields[KV_FIELD_MAP[k]] = int(digits)
            else:
                fields[KV_FIELD_MAP[k]] = v
    return fields


def parse(text: str, evidence_id: int, evidence_code: str) -> list[dict]:
    events: list[dict] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue

        ts_match = TS_LINE_RE.match(line)
        if not ts_match:
            i += 1
            continue

        ts, rest = ts_match.group(1), ts_match.group(2)
        # A bare timestamp line may be followed by key:value lines (spec format)
        block = [rest]
        j = i + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if not nxt or TS_LINE_RE.match(lines[j]):
                break
            block.append(nxt)
            j += 1

        full_block = " ".join(block).strip()
        fields: dict = {"timestamp": ts, "raw_line": full_block[:2000]}

        # key:value fields, parsed per line so multi-line record blocks are handled
        for block_line in block:
            fields.update(_kv_fields(block_line))

        hostname = None
        host_m = HOST_RE.match(rest)
        if host_m and "." not in host_m.group(1) or (host_m and re.match(r"^[A-Za-z0-9-]+$", host_m.group(1))):
            hostname = host_m.group(1)
        if hostname and "hostname" not in fields:
            fields["hostname"] = hostname

        # SSH auth patterns
        m = SSH_FAIL_RE.search(full_block)
        if m:
            fields.update({"username": fields.get("username", m.group(1)),
                           "source_ip": fields.get("source_ip", m.group(2)),
                           "port": fields.get("port", m.group(3)),
                           "action": fields.get("action", "login"),
                           "declared_type": "LOGIN_FAILURE",
                           "message": fields.get("message", stripped)})
        else:
            m = SSH_OK_RE.search(full_block)
            if m:
                fields.update({"username": fields.get("username", m.group(1)),
                               "source_ip": fields.get("source_ip", m.group(2)),
                               "port": fields.get("port", m.group(3)),
                               "action": fields.get("action", "login"),
                               "declared_type": "LOGIN_SUCCESS",
                               "message": fields.get("message", stripped)})
            else:
                m = SUDO_RE.search(full_block)
                if m:
                    fields.update({"username": m.group(1),  # the sudoer, not the target account
                                   "action": fields.get("action", "privileged command"),
                                   "declared_type": "PRIVILEGE_ESCALATION",
                                   "process_id": fields.get("process_id"),
                                   "message": fields.get("message", f"USER={m.group(2)} COMMAND={m.group(3)}")})
                else:
                    fm = FW_RE.search(full_block)
                    if fm:
                        fields.update({
                            "status": fields.get("status", "success" if fm.group(1).upper() in ("ALLOW", "ACCEPT") else "failed"),
                            "source_ip": fields.get("source_ip", fm.group(3)),
                            "port": fields.get("port", fm.group(4)),
                            "destination_ip": fields.get("destination_ip", fm.group(5)),
                            "action": fields.get("action", f"{fm.group(2) or 'NETWORK'} connection"),
                            "declared_type": "NETWORK_CONNECTION",
                            "message": fields.get("message", stripped),
                        })
                    else:
                        sm = SIZE_RE.search(full_block)
                        if sm and "byte_count" not in fields:
                            fields["byte_count"] = int(sm.group(1))
                        if "message" not in fields and rest:
                            fields["message"] = full_block[:500]
                        if "action" not in fields and "declared_type" not in fields:
                            fields["declared_type"] = None

        if "url" not in fields:
            u = extract_first_url(full_block)
            if u:
                fields["url"] = u
                fields.setdefault("domain", extract_domain(u))
        if "source_ip" not in fields and "destination_ip" not in fields:
            from app.parsers.base import extract_ips
            ips = extract_ips(full_block)
            if len(ips) >= 1:
                fields["source_ip"] = fields.get("source_ip", ips[0])
            if len(ips) >= 2:
                fields.setdefault("destination_ip", ips[1])

        events.append(normalize_event(evidence_id, evidence_code, **fields))
        i = j if j > i else i + 1

    return events
