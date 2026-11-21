"""AI provider abstraction.

- DeterministicProvider: fully local rule-based narrative engine (default).
- OpenAIProvider: optional, enabled only when AI_PROVIDER=openai and an API key
  is configured via environment. No keys are ever hard-coded.

Both return an ai.schemas.AIAnalysisResult. The deterministic engine derives
everything from detections/correlations; the LLM path validates output and
drops any finding that references non-existent evidence/event IDs.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict

from app.ai.prompts import SYSTEM_PROMPT
from app.ai.schemas import AIAnalysisResult, AIFinding


def _build_context(investigation, events, detections, chains, stages) -> dict:
    suspicious = [e for e in events if e.is_suspicious]
    return {
        "investigation": {
            "code": investigation.code, "name": investigation.name,
            "incident_type": investigation.incident_type,
            "severity": investigation.severity,
        },
        "counts": {
            "evidence_events": len(events),
            "suspicious_events": len(suspicious),
            "detections": len(detections),
            "correlation_chains": len(chains),
        },
        "suspicious_events": [
            {"event_id": e.code, "timestamp": e.timestamp, "event_type": e.event_type,
             "username": e.username, "source_ip": e.source_ip, "destination_ip": e.destination_ip,
             "hostname": e.hostname, "file_path": e.file_path, "byte_count": e.byte_count,
             "message": (e.message or "")[:300],
             "evidence_id": e.evidence.code if e.evidence else None}
            for e in suspicious[:80]
        ],
        "detections": [
            {"rule_id": d["rule_id"], "title": d["title"], "severity": d["severity"],
             "confidence": d["confidence"], "classification": d["classification"],
             "conclusion": d["conclusion"], "event_ids": d["event_ids"],
             "evidence_ids": d["evidence_ids"]}
            for d in detections
        ],
        "correlation_chains": [
            {"chain_id": c["chain_id"], "event_ids": c["event_ids"],
             "shared_attributes": c["shared_attributes"],
             "time_span": c["time_span"]}
            for c in chains
        ],
        "attack_stages": stages,
    }


def _deterministic_result(investigation, events, detections, chains, stages) -> AIAnalysisResult:
    suspicious = [e for e in sorted(events, key=lambda e: e.timestamp or "") if e.is_suspicious]
    users = sorted({e.username for e in suspicious if e.username})
    systems = sorted({e.hostname for e in suspicious if e.hostname})
    ips = sorted({e.source_ip for e in suspicious if e.source_ip} |
                 {e.destination_ip for e in suspicious if e.destination_ip and
                  e.event_type in ("DATA_TRANSFER", "NETWORK_CONNECTION")})

    det_by_stage: dict[str | None, list] = defaultdict(list)
    for d in detections:
        det_by_stage[d.get("attack_stage")].append(d)

    # What happened: narrate the correlated sequence of suspicious events
    seq_parts = []
    for e in suspicious[:12]:
        piece = f"at {e.timestamp}, {e.event_type.lower().replace('_', ' ')}"
        if e.username:
            piece += f" involving '{e.username}'"
        if e.source_ip:
            piece += f" from {e.source_ip}"
        if e.file_path:
            piece += f" on {e.file_path}"
        seq_parts.append(piece)
    sequence_sentence = "; ".join(seq_parts) + "." if seq_parts else "No suspicious events recorded."

    has_compromise = any(d["rule_id"] == "ACCOUNT_COMPROMISE" for d in detections)
    has_exfil = any(d.get("attack_stage") == "Exfiltration" for d in detections)

    summary_lines = [
        f"Investigation {investigation.code} ({investigation.incident_type}) analyzed "
        f"{len(events)} normalized events from the evidence, of which {len(suspicious)} were flagged suspicious "
        f"by {len(detections)} deterministic detections."
    ]
    if has_compromise and has_exfil:
        summary_lines.append(
            f"The correlated sequence suggests a possible account compromise of "
            f"{', '.join(users) or 'an account'} followed by privileged access, sensitive file access "
            f"and a large outbound transfer. This is a LIKELY inference, not a confirmed fact.")
    elif has_compromise:
        summary_lines.append("A likely account-compromise pattern (repeated failures then success from the same IP) was detected.")
    elif suspicious:
        summary_lines.append("Suspicious activity was detected and is itemized in the findings below.")
    else:
        summary_lines.append("No suspicious activity met the detection thresholds in the available evidence.")

    confirmed = [f"{d['title']} — {d['classification']}: {d['conclusion']}"
                 for d in detections if d["classification"] == "Confirmed"]
    suspected = [f"{d['title']} — {d['classification']}: {d['conclusion']}"
                 for d in detections if d["classification"] != "Confirmed"]

    missing = []
    if not any("MFA" in (e.message or "") or "mfa" in (e.raw_line or "") for e in events):
        missing.append("No multi-factor authentication logs were present in the evidence.")
    if not any(e.event_type in ("NETWORK_CONNECTION",) and e.destination_ip for e in events):
        missing.append("Insufficient evidence to determine full network scope (limited firewall/flow data).")
    missing.append("Geo-location / threat-intelligence enrichment was not performed (local deterministic mode).")
    if not any(e.event_type == "MALWARE_EVENT" for e in events):
        missing.append("No malware-specific artifacts were found in the provided evidence.")

    next_steps = []
    for d in detections:
        next_steps.extend(d.get("recommendations") or [])
    next_steps.append("Collect endpoint telemetry (EDR) for the affected hosts to confirm process lineage.")
    next_steps.append("Preserve volatile data and re-verify evidence integrity before further analysis.")
    # dedupe, keep order
    next_steps = list(dict.fromkeys(next_steps))[:12]

    findings = [
        AIFinding(
            title=d["title"], severity=d["severity"], confidence=d["confidence"],
            classification=d["classification"], attack_stage=d.get("attack_stage"),
            conclusion=d["conclusion"], explanation=d["explanation"],
            supporting_evidence_ids=d["evidence_ids"], supporting_event_ids=d["event_ids"],
            recommendations=d.get("recommendations") or [],
        )
        for d in detections if d.get("events")
    ]

    return AIAnalysisResult(
        executive_summary=" ".join(summary_lines),
        what_happened=f"Observed sequence: {sequence_sentence}" if seq_parts else
                      "Insufficient evidence to determine a sequence of activity.",
        suspicious_activities=[f"{d['title']}: {d['conclusion']}" for d in detections],
        affected_systems=systems,
        affected_users=users,
        confirmed=confirmed,
        suspected=suspected,
        missing_information=missing,
        next_steps=next_steps,
        findings=findings,
    )


class DeterministicProvider:
    """Local, private, always-available analysis engine. Sends nothing off-box."""
    name = "deterministic"

    def analyze(self, investigation, events, detections, chains, stages) -> AIAnalysisResult:
        return _deterministic_result(investigation, events, detections, chains, stages)

    def build_context(self, investigation, events, detections, chains, stages) -> dict:
        return _build_context(investigation, events, detections, chains, stages)


class OpenAIProvider:
    """Optional external provider. Only used when explicitly configured."""
    name = "openai"

    def __init__(self, api_key: str | None = None, model: str | None = None, base_url: str | None = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = (base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def analyze(self, investigation, events, detections, chains, stages) -> AIAnalysisResult:
        import httpx  # local import: only needed when external AI is enabled

        context = _build_context(investigation, events, detections, chains, stages)
        valid_event_ids = {e.code for e in events}
        valid_evidence_ids = {e.evidence.code for e in events if e.evidence}

        response = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(context)},
                ],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            },
            timeout=60,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        data = json.loads(content)

        result = AIAnalysisResult.model_validate(data)

        # Anti-hallucination gate: drop references that don't exist, then
        # reject findings left with no real supporting references.
        kept: list[AIFinding] = []
        for finding in result.findings:
            finding.supporting_event_ids = [i for i in finding.supporting_event_ids if i in valid_event_ids]
            finding.supporting_evidence_ids = [i for i in finding.supporting_evidence_ids if i in valid_evidence_ids]
            if finding.supporting_event_ids or finding.supporting_evidence_ids:
                kept.append(finding)
        result.findings = kept
        return result


_provider: DeterministicProvider | OpenAIProvider | None = None


def get_provider() -> DeterministicProvider | OpenAIProvider:
    """Resolve the AI provider from environment configuration.

    AI_PROVIDER=openai  -> external OpenAI-compatible API (requires OPENAI_API_KEY)
    anything else       -> local deterministic engine (default; privacy-preserving)
    """
    global _provider
    if _provider is not None:
        return _provider
    if os.environ.get("AI_PROVIDER", "").strip().lower() == "openai":
        candidate = OpenAIProvider()
        if candidate.configured:
            _provider = candidate
            return _provider
    _provider = DeterministicProvider()
    return _provider


def provider_mode() -> str:
    """'external' when an external LLM is actively configured, else local."""
    return "external" if isinstance(get_provider(), OpenAIProvider) else "local-deterministic"
