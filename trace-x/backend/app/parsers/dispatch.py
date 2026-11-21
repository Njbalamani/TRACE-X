"""Parser dispatch: chooses the right parser by extension and content sniffing."""
from __future__ import annotations

from app.parsers import csv_parser, email_parser, json_parser, log_parser

TEXT_EXTENSIONS = {"txt", "log", "csv", "json", "eml"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg"}
STORE_ONLY_EXTENSIONS = {"pdf", "pcap", "pcapng"}

SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | IMAGE_EXTENSIONS | STORE_ONLY_EXTENSIONS
DANGEROUS_EXTENSIONS = {"exe", "bat", "cmd", "ps1", "sh", "dll", "scr", "msi", "js", "vbs", "com", "jar"}

MAX_PREVIEW_BYTES = 4096


def _sniff(text: str) -> str:
    """Decide what kind of text content this is."""
    head = text[:2000]
    if email_parser._looks_like_email(head):
        return "email"
    stripped = head.lstrip()
    if stripped[:1] in "{[":
        return "json"
    if "," in head.splitlines()[0] if head.splitlines() else False:
        return "csv"
    return "log"


def parse_evidence(extension: str, data: bytes, evidence_id: int, evidence_code: str) -> tuple[list[dict], dict, str]:
    """Returns (events, parse_summary, parser_name)."""
    ext = extension.lower().lstrip(".")
    summary: dict = {}

    if ext in IMAGE_EXTENSIONS:
        return [], {
            "parser": "image-metadata",
            "note": "Image stored with metadata and cryptographic hash. "
                    "OCR text extraction is not enabled in this build; the original is preserved bit-for-bit.",
            "content_type": {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}.get(ext, "application/octet-stream"),
        }, "image"

    if ext == "pdf":
        preview = data[:5]
        looks_pdf = preview.startswith(b"%PDF")
        return [], {
            "parser": "pdf-metadata",
            "valid_pdf_signature": looks_pdf,
            "note": "PDF stored with metadata and hash; text extraction not performed in this build.",
        }, "pdf"

    if ext in {"pcap", "pcapng"}:
        return [], {
            "parser": "pcap-metadata",
            "note": "Packet capture stored with metadata and hash. Flow extraction not enabled in this build.",
        }, "pcap"

    # Text formats: decode safely
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", errors="replace")

    kind = ext if ext in ("csv", "json", "eml") else _sniff(text)
    if kind == "eml":
        kind = "email"

    if kind == "email":
        events, summary = email_parser.parse(text, evidence_id, evidence_code)
        return events, summary, "email"

    if kind == "json":
        return (*json_parser.parse(text, evidence_id, evidence_code), "json")

    if kind == "csv":
        return (*csv_parser.parse(text, evidence_id, evidence_code), "csv")

    return log_parser.parse(text, evidence_id, evidence_code), summary, "log"
