"""Attack stage classification (Lockheed Martin Cyber Kill Chain inspired).
A stage is only reported when supporting events exist — never assumed."""
from __future__ import annotations

EVENT_TYPE_TO_STAGE = {
    "LOGIN_FAILURE": "Credential Access",
    "LOGIN_SUCCESS": "Initial Access",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "FILE_ACCESS": "Collection",
    "DATA_TRANSFER": "Exfiltration",
    "NETWORK_CONNECTION": "Command and Control",
    "EMAIL_RECEIVED": "Initial Access",
    "EMAIL_LINK": "Initial Access",
    "MALWARE_EVENT": "Execution",
    "ACCOUNT_CHANGE": "Persistence",
    "SECURITY_ALERT": None,  # alerts are meta-events, classified by their content
}

MESSAGE_HINTS = [
    ("privileg", "Privilege Escalation"),
    ("sudo", "Privilege Escalation"),
    ("root command", "Privilege Escalation"),
    ("exfiltrat", "Exfiltration"),
    ("outbound transfer", "Exfiltration"),
    ("lateral", "Lateral Movement"),
    ("psexec", "Lateral Movement"),
    ("credential dump", "Credential Access"),
    ("mimikatz", "Credential Access"),
    ("beacon", "Command and Control"),
    ("c2", "Command and Control"),
    ("phishing", "Initial Access"),
    ("persist", "Persistence"),
    ("defen", "Defense Evasion"),
    ("discovery", "Discovery"),
    ("enumerat", "Discovery"),
    ("encrypt", "Impact"),
    ("ransom", "Impact"),
]

STAGE_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def classify_event_stage(event) -> str | None:
    if event.event_type in EVENT_TYPE_TO_STAGE:
        stage = EVENT_TYPE_TO_STAGE[event.event_type]
        if stage:
            return stage
    text = ((event.message or "") + " " + (event.action or "")).lower()
    for hint, stage in MESSAGE_HINTS:
        if hint in text:
            return stage
    return EVENT_TYPE_TO_STAGE.get(event.event_type)


def build_stages(events) -> list[dict]:
    """Return only stages that have real supporting events, ordered by kill chain."""
    stages: dict[str, list] = {}
    for event in events:
        if not event.is_suspicious:
            continue
        stage = classify_event_stage(event)
        if not stage:
            continue
        stages.setdefault(stage, []).append(event)

    result = []
    for stage in STAGE_ORDER:
        evs = stages.get(stage)
        if not evs:
            continue
        evs.sort(key=lambda e: e.timestamp or "")
        sev_rank = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        confidence = "High" if len(evs) >= 2 or any(e.severity in ("High", "Critical") for e in evs) else "Medium"
        result.append({
            "stage": stage,
            "confidence": confidence,
            "event_count": len(evs),
            "event_ids": [e.code for e in evs],
            "evidence_ids": sorted({e.evidence.code for e in evs if e.evidence}),
            "timestamps": [e.timestamp for e in evs if e.timestamp],
            "summary": f"{stage}: {len(evs)} suspicious event(s) observed, e.g. "
                       f"{evs[0].code} at {evs[0].timestamp or 'unknown time'}.",
        })
    return result
