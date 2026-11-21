"""Cryptographic fingerprints and blockchain-style hash-chain integrity records.

Every evidence item, timeline event and finding is fingerprinted with SHA-256.
Each investigation maintains a tamper-evident chain: block_hash covers the
object payload hash, the previous block hash and metadata, so any unauthorized
modification of investigation data breaks the chain at that height.
"""

import hashlib
import json

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

GENESIS_HASH = "0" * 64

OBJECT_SERIALIZERS = {}


def register_serializer(object_type):
    def deco(fn):
        OBJECT_SERIALIZERS[object_type] = fn
        return fn

    return deco


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_evidence(evidence) -> str:
    if evidence.file:
        evidence.file.open("rb")
        try:
            digest = sha256_bytes(evidence.file.read())
        finally:
            evidence.file.close()
    else:
        digest = sha256_text(evidence.content)
    return digest


def _payload(obj) -> str:
    serializer = OBJECT_SERIALIZERS.get(type(obj).__name__.lower())
    data = serializer(obj) if serializer else {"repr": repr(obj)}
    return sha256_text(json.dumps(data, sort_keys=True, default=str))


@register_serializer("evidence")
def _serialize_evidence(e):
    # Re-hash the file from disk on every call (rather than trusting the stored
    # sha256 column) so an evidence file altered on disk is detected during
    # verification. When no file is attached this falls back to hashing content.
    try:
        digest = fingerprint_evidence(e)
    except (OSError, ValueError):
        digest = e.sha256
    return {
        "pk": str(e.pk),
        "title": e.title,
        "evidence_type": e.evidence_type,
        "sha256": digest,
        "content": e.content,
        "source": e.source,
        "collected_at": e.collected_at.isoformat() if e.collected_at else None,
    }


@register_serializer("timelineevent")
def _serialize_event(ev):
    return {
        "pk": str(ev.pk),
        "title": ev.title,
        "description": ev.description,
        "severity": ev.severity,
        "occurred_at": ev.occurred_at.isoformat() if ev.occurred_at else None,
        "source_ip": ev.source_ip,
        "evidence": str(ev.evidence_id) if ev.evidence_id else None,
    }


@register_serializer("finding")
def _serialize_finding(f):
    return {
        "pk": str(f.pk),
        "title": f.title,
        "category": f.category,
        "severity": f.severity,
        "confidence": f.confidence,
        "summary": f.summary,
        "explanation": f.explanation,
        "status": f.status,
        "links": sorted(
            [
                f"{l.evidence_id}:{l.relation}:{l.timeline_event_id}"
                for l in f.evidence_links.all()
            ]
        ),
    }


def compute_block_hash(payload_hash: str, prev_hash: str, height: int, created_at) -> str:
    material = f"{height}|{created_at.isoformat()}|{prev_hash}|{payload_hash}"
    return sha256_text(material)


def record_object(obj, investigation, user=None) -> "IntegrityRecord":
    from investigations.models import IntegrityRecord

    last = (
        IntegrityRecord.objects.filter(investigation=investigation).order_by("-height").first()
    )
    height = (last.height + 1) if last else 0
    prev_hash = last.block_hash if last else GENESIS_HASH
    payload_hash = _payload(obj)
    created_at = timezone.now()
    block_hash = compute_block_hash(payload_hash, prev_hash, height, created_at)
    record = IntegrityRecord.objects.create(
        investigation=investigation,
        object_type=type(obj).__name__.lower(),
        object_id=str(obj.pk),
        payload_hash=payload_hash,
        prev_hash=prev_hash,
        block_hash=block_hash,
        height=height,
        recorded_by=user,
        created_at=created_at,
    )
    # Anchor the current tip on the investigation itself. This lives outside the
    # append-only ledger, so deleting the newest block(s) leaves a mismatch.
    investigation.ledger_length = height + 1
    investigation.ledger_tip = block_hash
    investigation.save(update_fields=["ledger_length", "ledger_tip"])
    return record


def verify_chain_for(investigation) -> dict:
    """Recompute the whole chain and compare it to the anchored tip so that
    truncation (deleting the newest blocks) is also detected."""
    from investigations.models import IntegrityRecord

    # The anchor is authoritative on the database row, not on whatever (possibly
    # stale) instance the caller happens to be holding.
    try:
        investigation.refresh_from_db(fields=["ledger_length", "ledger_tip"])
    except ObjectDoesNotExist:
        return {"valid": False, "blocks": 0, "tip": None, "broken_at": {"height": 0, "object": "investigation"}}

    records = list(
        IntegrityRecord.objects.filter(investigation=investigation).order_by("height")
    )
    prev_hash = GENESIS_HASH
    broken = None
    for record in records:
        expected = compute_block_hash(record.payload_hash, prev_hash, record.height, record.created_at)
        if record.prev_hash != prev_hash or record.block_hash != expected:
            broken = {"height": record.height, "object": f"{record.object_type}:{record.object_id}"}
            break
        prev_hash = record.block_hash
    if broken is None:
        tip = records[-1].block_hash if records else GENESIS_HASH
        stored_tip = investigation.ledger_tip or GENESIS_HASH
        if len(records) != investigation.ledger_length or tip != stored_tip:
            broken = {"height": len(records), "object": "ledger"}
    return {
        "valid": broken is None,
        "blocks": len(records),
        "tip": prev_hash if broken is None else None,
        "broken_at": broken,
    }


def verify_object(obj, investigation) -> dict:
    """Check that an object's current data still matches its recorded fingerprint."""
    from investigations.models import IntegrityRecord

    record = (
        IntegrityRecord.objects.filter(
            investigation=investigation, object_type=type(obj).__name__.lower(), object_id=str(obj.pk)
        )
        .order_by("-height")
        .first()
    )
    if record is None:
        return {"checked": False, "valid": None, "reason": "No integrity record yet"}
    current = _payload(obj)
    valid = current == record.payload_hash
    return {
        "checked": True,
        "valid": valid,
        "recorded_hash": record.payload_hash,
        "current_hash": current,
        "recorded_at": record.created_at.isoformat(),
        "reason": "Fingerprint matches" if valid else "Payload changed since fingerprint was recorded",
    }


def verify_investigation(investigation) -> dict:
    """Chain verification plus per-object fingerprint checks."""
    from investigations.models import Evidence, Finding, TimelineEvent

    chain = verify_chain_for(investigation)
    tampered = []
    groups = [
        ("evidence", Evidence.objects.filter(investigation=investigation)),
        ("timelineevent", TimelineEvent.objects.filter(investigation=investigation)),
        ("finding", Finding.objects.filter(investigation=investigation)),
    ]
    for name, qs in groups:
        for obj in qs:
            result = verify_object(obj, investigation)
            if result["checked"] and not result["valid"]:
                tampered.append(
                    {"object_type": name, "object_id": str(obj.pk), "label": str(obj)}
                )
    return {
        "valid": chain["valid"] and not tampered,
        "chain": chain,
        "tampered_objects": tampered,
        "checked_at": timezone.now().isoformat(),
    }
