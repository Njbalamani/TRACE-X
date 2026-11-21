"""Evidence integrity verification: recompute SHA-256 of every stored evidence
file, compare with the recorded fingerprint, and verify the ledger hash chain."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrity.ledger import ledger
from app.models.models import Evidence, Investigation

EVIDENCE_STORAGE = Path(__file__).resolve().parents[3] / "storage" / "evidence"


def compute_file_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _now():
    return datetime.now(timezone.utc)


def verify_evidence_file(db: Session, evidence: Evidence) -> Evidence:
    """Recompute one file's hash and update its integrity status."""
    path = EVIDENCE_STORAGE / evidence.stored_filename
    if not path.is_file():
        evidence.integrity_status = "Missing"
    else:
        current = compute_file_sha256(path)
        evidence.integrity_status = "Verified" if current == evidence.sha256 else "Violation"
    evidence.last_verified_at = _now()
    return evidence


def verify_investigation_integrity(db: Session, investigation: Investigation) -> dict:
    """Full verification pass: file hashes + ledger chain. Records the result in the ledger."""
    evidences = list(db.scalars(select(Evidence).where(Evidence.investigation_id == investigation.id)))
    items = []
    modified = missing = verified = 0
    for ev in evidences:
        path = EVIDENCE_STORAGE / ev.stored_filename
        if not path.is_file():
            ev.integrity_status = "Missing"
            current_hash = None
            missing += 1
        else:
            current_hash = compute_file_sha256(path)
            if current_hash == ev.sha256:
                ev.integrity_status = "Verified"
                verified += 1
            else:
                ev.integrity_status = "Violation"
                modified += 1
        ev.last_verified_at = _now()
        items.append({
            "evidence_code": ev.code,
            "filename": ev.original_filename,
            "stored_hash": ev.sha256,
            "current_hash": current_hash,
            "status": ev.integrity_status.upper().replace("VIOLATION", "INTEGRITY VIOLATION"),
            "last_verified_at": ev.last_verified_at,
        })

    chain = ledger.verify_chain(db, investigation_id=investigation.id)

    ledger.add_record(db, action="integrity_verified", investigation_id=investigation.id, payload={
        "total_evidence": len(evidences),
        "verified": verified,
        "modified": modified,
        "missing": missing,
        "chain_valid": chain["valid"],
    })
    db.commit()

    return {
        "investigation_code": investigation.code,
        "chain_valid": chain["valid"],
        "chain_error": chain.get("error"),
        "total_evidence": len(evidences),
        "verified": verified,
        "modified": modified,
        "missing": missing,
        "integrity_violations": modified + missing,
        "ledger_length": chain["blocks_checked"],
        "items": items,
    }
