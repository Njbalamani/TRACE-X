"""Email parser (RFC-822 / .eml and text files that start with mail headers)."""
from __future__ import annotations

import email
import email.policy
import re
from email.utils import parseaddr, parsedate_to_datetime

from app.parsers.base import (
    DOMAIN_RE,
    extract_first_url,
    normalize_event,
)

RECEIVED_IP_RE = re.compile(r"Received:.*?\[?((?:\d{1,3}\.){3}\d{1,3})\]?", re.I | re.S)


def _looks_like_email(text: str) -> bool:
    head = text[:600].lower()
    return "from:" in head and ("to:" in head or "subject:" in head)


def parse(text: str, evidence_id: int, evidence_code: str) -> tuple[list[dict], dict]:
    try:
        msg = email.message_from_string(text, policy=email.policy.default)
    except Exception as exc:  # malformed mail
        return [], {"reason": f"Could not parse email: {exc}"}

    sender_name, sender_addr = parseaddr(str(msg.get("From", "")))
    _, recipient = parseaddr(str(msg.get("To", "")))
    subject = str(msg.get("Subject", "") or "")
    date_raw = str(msg.get("Date", "") or "")
    try:
        date_norm = parsedate_to_datetime(date_raw).strftime("%Y-%m-%d %H:%M:%S") if date_raw else None
    except (TypeError, ValueError):
        date_norm = None

    body_parts: list[str] = []
    attachments: list[dict] = []
    urls: list[str] = []
    try:
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment" or part.get_filename():
                attachments.append({"filename": str(part.get_filename() or "unnamed"),
                                    "content_type": part.get_content_type()})
                continue
            if part.get_content_maintype() == "text":
                payload = part.get_content()
                if isinstance(payload, str):
                    body_parts.append(payload)
    except Exception:
        pass
    body = "\n".join(body_parts)

    for u in re.findall(r"https?://[^\s<>\"')\]]+", body or "", re.I):
        if u not in urls:
            urls.append(u)
    if not urls and subject:
        u = extract_first_url(subject)
        if u:
            urls.append(u)

    # Originating IP from Received chain (best effort)
    src_ip = None
    received_headers = msg.get_all("Received") or []
    for header in received_headers:
        m = RECEIVED_IP_RE.search(str(header))
        if m:
            src_ip = m.group(1)
            break

    domains = list(dict.fromkeys(DOMAIN_RE.findall((sender_addr or "") + " " + " ".join(urls))))[:5]
    domain = domains[0] if domains else None

    message = f"Email received | From: {sender_addr or 'unknown'} | To: {recipient or 'unknown'} | Subject: {subject}"
    if attachments:
        message += f" | Attachments: {', '.join(a['filename'] for a in attachments)}"

    fields = {
        "timestamp": date_norm,
        "declared_type": "EMAIL_RECEIVED",
        "username": sender_addr or None,
        "source_ip": src_ip,
        "domain": domain,
        "url": urls[0] if urls else None,
        "action": "email received",
        "message": message,
        "raw_line": f"From: {sender_addr}\nTo: {recipient}\nSubject: {subject}\nDate: {date_raw}",
    }
    events = [normalize_event(evidence_id, evidence_code, **fields)]
    if urls and len(urls) > 1:
        for u in urls[1:6]:
            events.append(normalize_event(
                evidence_id, evidence_code,
                timestamp=date_norm, declared_type="EMAIL_LINK", url=u,
                domain=extract_domain_of(u), action="link contained in email",
                message=f"Link found in email '{subject}': {u}",
            ))

    summary = {
        "from": sender_addr,
        "to": recipient,
        "subject": subject,
        "date": date_norm,
        "urls": urls[:10],
        "attachments": attachments,
        "domains": domains,
        "originating_ip": src_ip,
    }
    return events, summary


def extract_domain_of(url: str):
    m = DOMAIN_RE.search(url.replace("https://", "").replace("http://", ""))
    return m.group(0).lower() if m else None
