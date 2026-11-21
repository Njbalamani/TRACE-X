"""Evidence service: upload -> hash -> store -> parse -> normalized events."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.integrity.ledger import ledger
from app.models.models import Evidence, Event, Investigation
from app.parsers import dispatch
from app.services import storage
from app.services.audit_service import log_action


def _read_upload(upload: UploadFile) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > storage.MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413, detail="Evidence file is too large.")
            chunks.append(chunk)
    finally:
        upload.file.close()
    return b"".join(chunks)


def upload_evidence(db: Session, investigation: Investigation, upload: UploadFile,
                    source: str = "", description: str = "") -> Evidence:
    if upload is None or not upload.filename:
        raise HTTPException(status_code=400, detail="No evidence file was provided.")

    original_name = upload.filename
    extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    ok, message = storage.validate_extension(extension)
    if not ok:
        raise HTTPException(status_code=415, detail=message)

    data = _read_upload(upload)
    if not data:
        raise HTTPException(status_code=400, detail="The uploaded evidence file is empty.")

    # 1. Fingerprint BEFORE anything else — the hash is calculated on the exact bytes received.
    sha256 = hashlib.sha256(data).hexdigest()
    stored_filename = storage.generate_stored_filename(original_name)
    target = storage.EVIDENCE_STORAGE / stored_filename
    storage.ensure_dirs()
    target.write_bytes(data)  # original evidence is written once and never modified

    metadata_only = (message == "metadata_only")
    evidence = Evidence(
        investigation_id=investigation.id,
        original_filename=storage.sanitize_original_name(original_name),
        stored_filename=stored_filename,
        file_type=extension or "bin",
        size=len(data),
        sha256=sha256,
        source=source[:120],
        description=description[:2000],
        status="Metadata only" if metadata_only else "Processing",
    )
    db.add(evidence)
    db.flush()  # assigns evidence.id for the events' foreign key

    if not metadata_only:
        try:
            events_data, parse_summary, parser_name = dispatch.parse_evidence(
                extension, data, evidence.id, evidence.code)
            for ev_data in events_data:
                db.add(Event(investigation_id=investigation.id, evidence_id=evidence.id, **{
                    k: v for k, v in ev_data.items()
                    if not k.startswith("_") and k != "source_evidence_id"
                }))
            evidence.parser_name = parser_name
            evidence.parse_summary = parse_summary
            evidence.event_count = len(events_data)
            evidence.status = "Processed"
        except Exception as exc:  # parsing must never corrupt the stored evidence
            evidence.status = "Failed"
            evidence.parse_summary = {"reason": f"Evidence could not be parsed: {exc}"}
    else:
        evidence.parser_name = "metadata"
        evidence.parse_summary = {"reason": "Unsupported file type: stored with metadata and hash only."}
        evidence.status = "Metadata only"

    ledger.add_record(db, action="evidence_uploaded", investigation_id=investigation.id,
                      evidence_id=evidence.id, payload={
                          "evidence_code": evidence.code,
                          "original_filename": evidence.original_filename,
                          "sha256": sha256,
                          "size": evidence.size,
                          "status": evidence.status,
                      })
    log_action(db, action="evidence_uploaded", investigation_id=investigation.id,
               object_id=evidence.code,
               details={"filename": evidence.original_filename, "sha256": sha256[:16] + "…"})
    db.commit()
    db.refresh(evidence)
    return evidence


def evidence_preview(db: Session, evidence: Evidence) -> dict:
    """Safe content preview: text excerpt only, never executed."""
    path = storage.EVIDENCE_STORAGE / evidence.stored_filename
    result = {
        "evidence_code": evidence.code,
        "original_filename": evidence.original_filename,
        "sha256": evidence.sha256,
        "size": evidence.size,
        "integrity_status": evidence.integrity_status,
        "parse_summary": evidence.parse_summary,
        "preview": None,
        "preview_truncated": False,
        "content_type": "text/plain",
    }
    if not path.is_file():
        result["preview"] = "[File missing from storage — see Integrity page]"
        return result
    if evidence.file_type in ("png", "jpg", "jpeg"):
        result["content_type"] = f"image/{'png' if evidence.file_type == 'png' else 'jpeg'}"
        result["preview"] = f"/api/evidence/{evidence.id}/raw"
        return result
    if evidence.file_type in ("pdf", "pcap", "pcapng", "bin"):
        result["preview"] = f"[Binary evidence — {evidence.size} bytes stored. Deep content preview not available.]"
        return result
    try:
        text = path.read_text("utf-8", errors="replace")
    except Exception:
        result["preview"] = "[Preview unavailable — file could not be decoded as text.]"
        return result
    if len(text) > dispatch.MAX_PREVIEW_BYTES:
        result["preview"] = text[:dispatch.MAX_PREVIEW_BYTES]
        result["preview_truncated"] = True
    else:
        result["preview"] = text
    return result


def raw_image_response(evidence: Evidence):
    from fastapi.responses import FileResponse
    path = storage.EVIDENCE_STORAGE / evidence.stored_filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file missing from storage.")
    media = "image/png" if evidence.file_type == "png" else "image/jpeg"
    return FileResponse(path, media_type=media)


def parse_summary_json(evidence: Evidence) -> str:
    return json.dumps(evidence.parse_summary, indent=2, default=str)
