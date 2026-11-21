"""System information router (AI mode, storage, privacy indicator)."""
from __future__ import annotations

import os

from fastapi import APIRouter

from app.ai import provider as ai_provider_module
from app.services.storage import EVIDENCE_STORAGE, MAX_UPLOAD_BYTES, REPORT_STORAGE

router = APIRouter()

VERSION = "1.0.0"


@router.get("/system/info")
def system_info():
    provider = ai_provider_module.get_provider()
    mode = ai_provider_module.provider_mode()
    return {
        "app": "TRACE-X",
        "version": VERSION,
        "ai_provider": getattr(provider, "name", "deterministic"),
        "ai_provider_mode": mode,
        "database_url": os.environ.get("TRACE_X_DB_URL", "sqlite:///data/tracex.db"),
        "evidence_storage": str(EVIDENCE_STORAGE),
        "report_storage": str(REPORT_STORAGE),
        "max_upload_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
        "privacy_note": ("External AI analysis is ENABLED — evidence summaries are sent to the "
                         "configured provider." if mode == "external" else
                         "All analysis runs locally. No evidence leaves this machine."),
    }
