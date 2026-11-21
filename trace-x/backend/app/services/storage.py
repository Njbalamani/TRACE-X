"""Secure evidence storage: safe unique filenames, path-traversal protection,
size limits, extension policy."""
from __future__ import annotations

import re
import secrets
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_STORAGE = REPO_ROOT / "storage" / "evidence"
REPORT_STORAGE = REPO_ROOT / "storage" / "reports"

MAX_UPLOAD_BYTES = int(__import__("os").environ.get("TRACE_X_MAX_UPLOAD_MB", "50")) * 1024 * 1024

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

from app.parsers.dispatch import DANGEROUS_EXTENSIONS, STORE_ONLY_EXTENSIONS, SUPPORTED_EXTENSIONS  # noqa: E402


def ensure_dirs() -> None:
    EVIDENCE_STORAGE.mkdir(parents=True, exist_ok=True)
    REPORT_STORAGE.mkdir(parents=True, exist_ok=True)


def sanitize_original_name(name: str) -> str:
    """Human-readable sanitized copy of the original name (never used as path).
    Directory separators are preserved as underscores so path-like names
    keep their context without being usable as a path."""
    base = name.replace("\\", "_").replace("/", "_")
    parts = base.rsplit(".", 1)
    stem = SAFE_NAME_RE.sub("_", parts[0])[:80] or "evidence"
    ext = ("." + SAFE_NAME_RE.sub("", parts[1].lower())) if len(parts) > 1 else ""
    return f"{stem}{ext}"


def generate_stored_filename(original_name: str) -> str:
    """Random unique filename; original name is NEVER used as a storage path."""
    ext = Path(sanitize_original_name(original_name)).suffix[:16]
    return f"{uuid.uuid4().hex}{ext}"


def validate_extension(extension: str) -> tuple[bool, str]:
    ext = extension.lower().lstrip(".")
    if ext in DANGEROUS_EXTENSIONS:
        return False, "Unsupported file type: executable or script content is not accepted as evidence."
    if ext in STORE_ONLY_EXTENSIONS:
        return True, "metadata_only"
    if ext not in SUPPORTED_EXTENSIONS:
        # Spec 8: unsupported types may still be stored as metadata/hash-only.
        return True, "metadata_only"
    return True, "ok"


def safe_report_path(relative_name: str) -> Path:
    """Resolve a report filename inside REPORT_STORAGE, refusing traversal."""
    candidate = (REPORT_STORAGE / relative_name).resolve()
    if not str(candidate).startswith(str(REPORT_STORAGE.resolve())):
        raise ValueError("Path traversal detected")
    return candidate
