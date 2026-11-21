import json
import os
import re
import time
import urllib.error
import urllib.request

from django.conf import settings

GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"

# Transient failures (overload, throttling, connectivity): retry, then fall back.
_RETRIES = 3
_BACKOFF_BASE = 1.5
_TRANSIENT_CODES = {408, 425, 429, 500, 502, 503, 504}
_CODE_RE = re.compile(r"\b(\d{3})\b")

SYSTEM_PROMPT = (
    "You are TRACE-X Assist, the built-in AI assistant of TRACE-X, a digital forensics "
    "and cyber investigation platform. You help investigators with case analysis, evidence "
    "handling, SHA-256 integrity verification, hash-chain tamper detection, IOC extraction, "
    "timeline reconstruction, and general cybersecurity/forensics questions. Be concise, "
    "accurate and professional. Use markdown lists for steps. Never invent case data you "
    "were not given; if the user shares findings or logs, reason about them carefully."
)


def provider() -> str:
    value = (getattr(settings, "AI_PROVIDER", "") or os.environ.get("AI_PROVIDER", "")).lower()
    if value not in ("gemini", "openai"):
        return "gemini"
    return value


def gemini_key() -> str:
    return getattr(settings, "GEMINI_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "")


def openai_key() -> str:
    return getattr(settings, "OPENAI_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")


def openai_keys() -> list:
    return [k for k in getattr(settings, "OPENAI_API_KEYS", []) if k]


def provider_source() -> str:
    return ("openai" if provider() == "openai" else "gemini").upper()


def send(history, system_prompt: str = SYSTEM_PROMPT, timeout: int = 60) -> str:
    """history: [{"role": "user"|"model"|"assistant", "text": str}, ...] -> reply text.

    Retries the primary provider on transient failures (overload / rate-limit /
    connectivity) and, when it is still unavailable, falls back to the other
    provider so the user always gets an answer.
    """
    primary = provider()
    secondary = "openai" if primary == "gemini" else "gemini"

    try:
        return _call(primary, history, system_prompt, timeout, retries=_RETRIES)
    except RuntimeError as exc:
        if not _is_transient(exc):
            raise
    try:
        return _call(secondary, history, system_prompt, timeout, retries=_RETRIES)
    except RuntimeError as exc:
        raise RuntimeError(
            f"{primary.upper()} is temporarily busy and {secondary.upper()} failed too: {exc}"
        ) from exc


def _call(provider_name, history, system_prompt, timeout, retries) -> str:
    last_error = None
    for attempt in range(retries):
        try:
            if provider_name == "openai":
                return _send_openai(history, system_prompt, timeout)
            return _send_gemini(history, system_prompt, timeout)
        except RuntimeError as exc:
            if not _is_transient(exc):
                raise
            last_error = exc
            if attempt < retries - 1:
                time.sleep(min(_BACKOFF_BASE ** (attempt + 1), 6))
    raise last_error or RuntimeError(f"{provider_name.upper()} is unavailable")


def _is_transient(exc: RuntimeError) -> bool:
    message = str(exc)
    lowered = message.lower()
    # Quota exhaustion is permanent for the key in use - do not burn retries on it.
    if "insufficient_quota" in lowered or "quota" in lowered:
        return False
    if "Could not reach" in message or "UNAVAILABLE" in lowered:
        return True
    match = _CODE_RE.search(message)
    if not match:
        return False
    try:
        return int(match.group(1)) in _TRANSIENT_CODES
    except ValueError:
        return False


def _normalize_history(history, target):
    """target: "gemini" (user/model) or "openai" (user/assistant)."""
    out = []
    for m in history:
        role = m["role"]
        if role in ("assistant", "model"):
            out.append({"role": "model" if target == "gemini" else "assistant", "text": m["text"]})
        else:
            out.append({"role": "user", "text": m["text"]})
    return out


def _send_gemini(history, system_prompt, timeout) -> str:
    key = gemini_key()
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not configured")

    contents = [{"role": m["role"], "parts": [{"text": m["text"]}]} for m in _normalize_history(history, "gemini")]
    body = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.6, "maxOutputTokens": 1024},
    }
    req = urllib.request.Request(
        GEMINI_URL.format(model=getattr(settings, "GEMINI_MODEL", "gemini-3.8-flash")),
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Gemini API error {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not reach Gemini API: {exc.reason if isinstance(exc, urllib.error.URLError) else exc}") from exc

    candidates = data.get("candidates") or []
    if not candidates:
        raise RuntimeError("Gemini returned no candidates")
    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts).strip()
    if not text:
        raise RuntimeError("Gemini returned an empty reply")
    return text


def _send_openai(history, system_prompt, timeout) -> str:
    keys = openai_keys() or ([openai_key()] if openai_key() else [])
    if not keys:
        raise RuntimeError("OPENAI_API_KEY is not configured")

    messages = [{"role": "system", "content": system_prompt}]
    messages += [
        {"role": m["role"], "content": m["text"]} for m in _normalize_history(history, "openai")
    ]
    body = {"model": getattr(settings, "OPENAI_MODEL", "gpt-4o-mini"), "messages": messages}

    last_error = None
    for key in keys:
        req = urllib.request.Request(
            OPENAI_URL,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices") or []
            if not choices:
                raise RuntimeError("OpenAI returned no choices")
            content = (choices[0].get("message") or {}).get("content", "").strip()
            if not content:
                raise RuntimeError("OpenAI returned an empty reply")
            return content
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            last_error = f"OpenAI API error {exc.code}: {detail}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = f"Could not reach OpenAI API: {exc.reason if isinstance(exc, urllib.error.URLError) else exc}"
    raise RuntimeError(last_error or "OpenAI returned an unreadable response")