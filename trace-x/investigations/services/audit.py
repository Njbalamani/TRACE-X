"""Append-only audit trail.

Every security-relevant action funnels through :func:`record` so the audit log
is complete and consistent.  Rows are immutable (see ``AuditEvent.save``).
"""

from django.conf import settings

from ..models import AuditEvent


def client_ip(request):
    """Best-effort client address.

    ``X-Forwarded-For`` is only honoured when ``TRACEX_TRUST_PROXY`` is on,
    otherwise any client could forge the address recorded in the audit trail.
    """
    if request is None:
        return None
    if getattr(settings, "TRACEX_TRUST_PROXY", False):
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded:
            return forwarded.split(",")[0].strip() or None
    return request.META.get("REMOTE_ADDR") or None


def record(action, *, request=None, user=None, investigation=None, obj=None, **metadata):
    if user is None and request is not None and getattr(request, "user", None) is not None:
        user = request.user if request.user.is_authenticated else None
    return AuditEvent.objects.create(
        investigation=investigation,
        user=user,
        action=action,
        object_type=type(obj).__name__.lower() if obj is not None else metadata.pop("object_type", ""),
        object_id=str(getattr(obj, "pk", "")) if obj is not None else str(metadata.pop("object_id", "")),
        metadata=metadata,
        ip_address=client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT", "")[:255] if request is not None else ""),
    )
