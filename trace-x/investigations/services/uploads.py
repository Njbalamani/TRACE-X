"""Upload validation: size, extension allow-list, content sniffing, safe names."""

import os
import re

from django.core.exceptions import ValidationError

ALLOWED_EXTENSIONS = {
    # text / structured logs
    "log", "txt", "csv", "tsv", "json", "jsonl", "ndjson", "xml", "eml",
    # network / host artifacts
    "pcap", "pcapng", "cap", "evtx", "dmp", "bin",
    # documents / images
    "pdf", "png", "jpg", "jpeg", "gif", "bmp", "webp",
}
TEXT_EXTENSIONS = {"log", "txt", "csv", "tsv", "json", "jsonl", "ndjson", "xml", "eml"}

MAGIC = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"], "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "bmp": [b"BM"],
    "webp": [b"RIFF"],
    "pcap": [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"],
    "cap": [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"],
    "pcapng": [b"\x0a\x0d\x0d\x0a"],
    "evtx": [b"ElfFile\x00"],
}

# Executable containers must never be disguised as text/log evidence.
EXECUTABLE_MAGIC = [b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe"]

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ \-()]")


def extension_of(filename):
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def safe_filename(name: str) -> str:
    """Strip any path components / control characters from a client filename."""
    base = os.path.basename((name or "").replace("\\", "/")).strip()
    base = _SAFE_NAME.sub("_", base).lstrip(".") or "evidence"
    if len(base) > 120:
        stem, _, ext = base.rpartition(".")
        base = (stem[:100] + "." + ext) if stem and len(ext) <= 8 else base[:120]
    return base


def validate_upload(filename: str, head: bytes, size: int, max_bytes: int):
    """Raise ``ValidationError`` when the upload must be refused."""
    ext = extension_of(filename)
    if size > max_bytes:
        raise ValidationError(f"Evidence file is too large: {filename} (limit {max_bytes // (1024 * 1024)} MB).")
    if size == 0:
        raise ValidationError(f"{filename}: file is empty.")
    if ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(f"{filename}: file type '.{ext or '?'}' is not an accepted evidence format.")
    if ext in TEXT_EXTENSIONS:
        if any(head.startswith(sig) for sig in EXECUTABLE_MAGIC):
            raise ValidationError(f"{filename}: content looks like an executable, not a .{ext} file.")
        if b"\x00" in head[:4096]:
            raise ValidationError(f"{filename}: binary content in a .{ext} file (content/type mismatch).")
    signatures = MAGIC.get(ext)
    if signatures and not any(head.startswith(sig) for sig in signatures):
        raise ValidationError(f"{filename}: file signature does not match its .{ext} extension.")
