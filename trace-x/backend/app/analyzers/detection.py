"""Deterministic detection rules. These run BEFORE any AI and produce
candidate findings that are, by construction, backed by real event IDs."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

SENSITIVE_FILE_PATTERNS = (
    "/etc/shadow", "/etc/passwd", "shadow", "id_rsa", ".ssh", ".env", "secret",
    "credential", "password", "customer", "payroll", "backup", "dump", "export",
    "database", "private key", "api_key", "apikey", "token",
)

LARGE_TRANSFER_BYTES = 100 * 1024 * 1024        # 100 MB single transfer
BULK_TRANSFER_BYTES = 500 * 1024 * 1024         # 500 MB aggregate
BRUTE_FORCE_MEDIUM = 5                           # failures in window -> Medium
BRUTE_FORCE_HIGH = 10                            # failures in window -> High
BRUTE_FORCE_WINDOW_MIN = 10
COMPROMISE_MIN_FAILURES = 3
BULK_FILE_ACCESS_COUNT = 10
BULK_FILE_ACCESS_WINDOW_MIN = 15


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        try:
            return datetime.fromisoformat(str(value))
        except ValueError:
            return None


def _excerpts(events, limit=6):
    return [
        {
            "event_code": e.code,
            "evidence_code": e.evidence.code if e.evidence else None,
            "timestamp": e.timestamp,
            "text": (e.raw_line or e.message or f"{e.event_type} {e.action or ''}".strip())[:300],
        }
        for e in events[:limit]
    ]


def _ids(events):
    evidence_ids = sorted({e.evidence.code for e in events if e.evidence})
    event_ids = [e.code for e in events]
    timestamps = sorted({e.timestamp for e in events if e.timestamp})
    return evidence_ids, event_ids, timestamps


def _detection(rule_id, title, severity, confidence, classification, conclusion,
               explanation, stage, events, recommendations=None):
    evidence_ids, event_ids, timestamps = _ids(events)
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "classification": classification,
        "conclusion": conclusion,
        "explanation": explanation,
        "attack_stage": stage,
        "event_ids": event_ids,
        "evidence_ids": evidence_ids,
        "timestamps": timestamps,
        "excerpts": _excerpts(events),
        "recommendations": recommendations or [],
        "events": events,
    }


def rule_brute_force(events):
    """Multiple failed logins from the same source IP within a time window."""
    findings = []
    groups = defaultdict(list)
    for e in events:
        if e.event_type == "LOGIN_FAILURE" and e.source_ip:
            groups[e.source_ip].append(e)
    for ip, evs in groups.items():
        evs.sort(key=lambda x: x.timestamp or "")
        n = len(evs)
        if n < BRUTE_FORCE_MEDIUM:
            continue
        # check sliding window
        in_window = n
        first, last = _ts(evs[0].timestamp), _ts(evs[-1].timestamp)
        if first and last:
            minutes = (last - first).total_seconds() / 60
            if minutes > BRUTE_FORCE_WINDOW_MIN * 3:
                in_window = sum(1 for e in evs if first and _ts(e.timestamp)
                                and (_ts(e.timestamp) - first).total_seconds() <= BRUTE_FORCE_WINDOW_MIN * 60)
        severity = "High" if n >= BRUTE_FORCE_HIGH or in_window >= BRUTE_FORCE_HIGH else "Medium"
        findings.append(_detection(
            "BRUTE_FORCE", "Possible Brute-Force Activity", severity, "High", "Likely",
            f"{n} failed login attempts were observed from source IP {ip}"
            + (f" within {int(minutes)} minutes" if first and last else "") + ".",
            f"TRACE-X flagged this activity because events {evs[0].code} through {evs[-1].code} "
            f"record repeated failed authentications for "
            f"{', '.join(sorted({e.username for e in evs if e.username}) or ['unknown accounts'])} "
            f"originating from the same IP address {ip}.",
            "Credential Access", evs,
            ["Block or rate-limit the source IP at the perimeter while the investigation continues.",
             "Check whether any authentication from this IP succeeded afterwards."]))
    return findings


def rule_account_compromise(events):
    """Successful login after multiple failures, same account / same IP."""
    findings = []
    failures_by_key = defaultdict(list)
    for e in events:
        if e.event_type == "LOGIN_FAILURE" and e.username:
            failures_by_key[(e.username, e.source_ip)].append(e)
    for (username, ip), fails in failures_by_key.items():
        if len(fails) < COMPROMISE_MIN_FAILURES:
            continue
        fails.sort(key=lambda x: x.timestamp or "")
        for succ in events:
            if succ.event_type != "LOGIN_SUCCESS" or succ.username != username:
                continue
            if ip and succ.source_ip and succ.source_ip != ip:
                continue
            t_f, t_s = _ts(fails[0].timestamp), _ts(succ.timestamp)
            if t_f and t_s and 0 <= (t_s - t_f).total_seconds() <= 3600 * 6:
                seq = fails + [succ]
                findings.append(_detection(
                    "ACCOUNT_COMPROMISE", "Possible Account Compromise", "High", "High", "Likely",
                    f"The account '{username}' may have been compromised: repeated failed logins were "
                    f"followed by a successful login from the same source IP {ip or succ.source_ip}.",
                    f"TRACE-X identified this activity because the account {username} experienced "
                    f"{len(fails)} failed login attempts and then a successful login from the same "
                    f"source IP {ip or succ.source_ip} within the same time window.",
                    "Initial Access", seq,
                    ["Disable or reset credentials for the affected account.",
                     "Review all sessions and activity for this account in the surrounding window.",
                     "Confirm with the legitimate owner whether the successful login was expected."]))
                break
    return findings


def rule_privilege_escalation(events):
    priv = [e for e in events if e.event_type == "PRIVILEGE_ESCALATION"]
    if not priv:
        return []
    return [_detection(
        "PRIVILEGE_ESCALATION", "Privileged Command Execution Observed", "High", "High", "Confirmed",
        f"{len(priv)} privileged command execution event(s) were recorded"
        + (f" by account '{priv[0].username}'" if priv[0].username else "") + ".",
        "Privilege escalation events were present in the normalized evidence "
        "(e.g. sudo/root command execution), which is uncommon for standard user activity.",
        "Privilege Escalation", priv,
        ["Determine whether the executed commands were authorized.",
         "Correlate the privileged session with surrounding login activity."])]


def rule_sensitive_file_access(events):
    flagged = [e for e in events if e.event_type == "FILE_ACCESS" and e.file_path
               and any(p in e.file_path.lower() for p in SENSITIVE_FILE_PATTERNS)]
    if not flagged:
        return []
    users = sorted({e.username for e in flagged if e.username})
    return [_detection(
        "SENSITIVE_FILE_ACCESS", "Sensitive File Access Detected", "High", "High", "Confirmed",
        f"Sensitive or regulated files were accessed ({', '.join(dict.fromkeys(e.file_path for e in flagged[:3]))}"
        f"{', …' if len(flagged) > 3 else ''})" + (f" by {', '.join(users)}" if users else "") + ".",
        "The accessed file paths match sensitive-data patterns (credentials, backups, customer or "
        "database exports) in the normalized evidence.",
        "Collection", flagged,
        ["Verify whether the file access was part of the user's normal duties.",
         "Snapshot access-control lists and review who else touched these files."])]


def rule_bulk_file_access(events):
    groups = defaultdict(list)
    for e in events:
        if e.event_type == "FILE_ACCESS" and e.username:
            groups[e.username].append(e)
    findings = []
    for user, evs in groups.items():
        if len(evs) >= BULK_FILE_ACCESS_COUNT:
            findings.append(_detection(
                "BULK_FILE_ACCESS", "Unusual Volume of File Access", "Medium", "Medium", "Likely",
                f"Account '{user}' accessed {len(evs)} files in the analyzed evidence window.",
                "A high volume of file-access events concentrated on one account is atypical "
                "compared with the remainder of the evidence.",
                "Collection", evs))
    return findings


def rule_large_transfer(events):
    singles = [e for e in events if e.event_type in ("DATA_TRANSFER", "NETWORK_CONNECTION")
               and (e.byte_count or 0) >= LARGE_TRANSFER_BYTES]
    findings = []
    if singles:
        total = sum(e.byte_count for e in singles)
        findings.append(_detection(
            "LARGE_TRANSFER", "Large Outbound Data Transfer", "High", "High", "Confirmed",
            f"Outbound transfer(s) totalling approximately {total / (1024 * 1024):.0f} MB were observed "
            f"towards {sorted({e.destination_ip for e in singles if e.destination_ip})}.",
            "Transfer sizes recorded in the evidence exceed the configured large-transfer threshold "
            f"({LARGE_TRANSFER_BYTES // (1024 * 1024)} MB) for outbound data.",
            "Exfiltration", singles,
            ["Confirm whether the destination is an approved business service.",
             "Retrieve proxy/CASB logs for the destination domain."]))
    # aggregate per destination
    agg = defaultdict(int)
    for e in events:
        if e.event_type in ("DATA_TRANSFER", "NETWORK_CONNECTION") and e.destination_ip:
            agg[e.destination_ip] += e.byte_count or 0
    bulk = {ip: total for ip, total in agg.items() if total >= BULK_TRANSFER_BYTES}
    if bulk and not singles:
        evs = [e for e in events if e.destination_ip in bulk]
        findings.append(_detection(
            "BULK_TRANSFER", "Aggregate Outbound Transfer Volume", "High", "Medium", "Likely",
            f"Cumulative outbound transfers exceeded {BULK_TRANSFER_BYTES // (1024 * 1024)} MB towards "
            f"{sorted(bulk)}.",
            "Multiple outbound transfer events summed over the investigation window exceed the "
            "aggregate volume threshold.", "Exfiltration", evs))
    return findings


def rule_impossible_travel(events):
    """Two successful logins, same account, distant IPs, short window.
    NOTE: heuristic inference — geo-IP is unavailable locally, so this is
    labelled LOW confidence and explicitly marked as an inference."""
    logins = sorted([e for e in events if e.event_type == "LOGIN_SUCCESS" and e.username and e.source_ip],
                    key=lambda x: x.timestamp or "")
    findings = []
    for i in range(len(logins)):
        for j in range(i + 1, len(logins)):
            a, b = logins[i], logins[j]
            if a.username != b.username or a.source_ip == b.source_ip:
                continue
            if not (a.source_ip.split(".")[0] and b.source_ip.split(".")[0]):
                continue
            if a.source_ip.split(".")[0] == b.source_ip.split(".")[0]:
                continue
            ta, tb = _ts(a.timestamp), _ts(b.timestamp)
            if ta and tb and abs((tb - ta).total_seconds()) <= 3600:
                findings.append(_detection(
                    "IMPOSSIBLE_TRAVEL", "Possible Impossible-Travel Login", "Medium", "Low", "Possible",
                    f"Two logins for account '{a.username}' occurred from different network ranges "
                    f"({a.source_ip} and {b.source_ip}) within one hour.",
                    "INFERENCE — based solely on login source/IPv4 diversity and time proximity. "
                    "No geo-location data was available in the evidence; VPN or proxy use can produce "
                    "false positives.", "Initial Access", [a, b],
                    ["Confirm the user's physical location and VPN usage for both logins."]))
    return findings


def rule_suspicious_ip(events):
    """Aggregate view: IPs involved in multiple distinct suspicious contexts."""
    from collections import Counter
    counts = Counter()
    for e in events:
        if e.is_suspicious:
            if e.source_ip:
                counts[e.source_ip] += 1
            if e.destination_ip and e.event_type in ("DATA_TRANSFER", "NETWORK_CONNECTION"):
                counts[e.destination_ip] += 1
    findings = []
    for ip, count in counts.items():
        if count >= 3:
            involved = [e for e in events if e.source_ip == ip or e.destination_ip == ip]
            involved = [e for e in involved if e.is_suspicious]
            findings.append(_detection(
                "SUSPICIOUS_IP", "Potentially Suspicious Source IP", "Medium", "Medium", "Possible",
                f"IP address {ip} appears in {count} suspicious events within this investigation.",
                "Potentially suspicious source IP based on observed behavior only — no external "
                "threat-intelligence lookup was performed, so no claim of known malice is made.",
                None, involved))
    return findings


def rule_after_hours(events):
    """Logins far outside business hours — low severity heuristic."""
    flagged = []
    for e in events:
        if e.event_type != "LOGIN_SUCCESS":
            continue
        t = _ts(e.timestamp)
        if t and (t.hour < 6 or t.hour >= 22):
            flagged.append(e)
    if not flagged:
        return []
    return [_detection(
        "AFTER_HOURS_LOGIN", "After-Hours Successful Login", "Low", "Low", "Possible",
        f"{len(flagged)} successful login(s) occurred between 22:00 and 06:00.",
        "Heuristic based only on timestamps in the evidence; shift work or time-zone differences "
        "can explain this activity.", None, flagged)]


ALL_RULES = [
    rule_brute_force,
    rule_account_compromise,
    rule_privilege_escalation,
    rule_sensitive_file_access,
    rule_bulk_file_access,
    rule_large_transfer,
    rule_impossible_travel,
    rule_suspicious_ip,
    rule_after_hours,
]


def run_detections(events) -> list[dict]:
    """Run all deterministic rules over normalized events."""
    detections: list[dict] = []
    for rule in ALL_RULES:
        try:
            detections.extend(rule(events))
        except Exception as exc:  # a broken rule must not kill the pipeline
            detections.append({
                "rule_id": rule.__name__, "title": f"Rule error: {rule.__name__}",
                "severity": "Low", "confidence": "Low", "classification": "Insufficient Evidence",
                "conclusion": "", "explanation": f"Detection rule failed: {exc}",
                "attack_stage": None, "event_ids": [], "evidence_ids": [], "timestamps": [],
                "excerpts": [], "recommendations": [], "events": [],
            })
    return detections
