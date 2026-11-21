"""Case-level role-based access control.

Roles (lowest to highest privilege):

* ``viewer``            read-only
* ``reviewer``          read + notes + finding review
* ``analyst``           reviewer + upload evidence, run analysis, manage IOCs/response
* ``lead_investigator`` analyst + assign people, close the case

Django staff users act as lead investigator on every case; the case creator is
always its lead investigator.
"""

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404

from ..models import CaseAssignment, Investigation
from . import audit

ROLE_RANK = {
    CaseAssignment.ROLE_VIEWER: 1,
    CaseAssignment.ROLE_REVIEWER: 2,
    CaseAssignment.ROLE_ANALYST: 3,
    CaseAssignment.ROLE_LEAD: 4,
}

# capability -> minimum role required
CAPABILITY_MIN_ROLE = {
    "view": CaseAssignment.ROLE_VIEWER,
    "review": CaseAssignment.ROLE_REVIEWER,   # notes, finding status
    "write": CaseAssignment.ROLE_ANALYST,     # upload, analyze, IOC, response
    "manage": CaseAssignment.ROLE_LEAD,       # assignments, close case
}


def role_for(user, investigation):
    if not user.is_authenticated:
        return None
    if user.is_staff or investigation.created_by_id == user.id:
        return CaseAssignment.ROLE_LEAD
    assignment = CaseAssignment.objects.filter(investigation=investigation, user=user).values_list("role", flat=True).first()
    return assignment


def can(user, investigation, capability):
    role = role_for(user, investigation)
    if role is None:
        return False
    return ROLE_RANK[role] >= ROLE_RANK[CAPABILITY_MIN_ROLE[capability]]


def accessible_cases(user):
    qs = Investigation.objects.all()
    if user.is_staff:
        return qs
    return qs.filter(Q(created_by=user) | Q(assignments__user=user)).distinct()


def get_case(request, pk, capability="view"):
    """Fetch a case the requester may act on.

    * no access at all  -> 404 (do not reveal that the case exists)
    * access, wrong role -> 403 and an ACCESS_DENIED audit event
    """
    investigation = get_object_or_404(Investigation, pk=pk)
    role = role_for(request.user, investigation)
    if role is None:
        raise Http404
    if not can(request.user, investigation, capability):
        audit.record("ACCESS_DENIED", request=request, investigation=investigation, capability=capability, role=role)
        raise PermissionDenied(f"Your role ({role}) cannot perform '{capability}' on this case.")
    return investigation
