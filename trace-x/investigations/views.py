import json

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from django.views.static import serve as serve_static

from .forms import InvestigationForm
from .models import Evidence, Finding, Investigation, TimelineEvent
from .services.analysis import run_analysis
from .services.integrity import fingerprint_evidence, record_object, sha256_bytes, verify_investigation, verify_object


def _case_number():
    last = Investigation.objects.order_by("-created_at").first()
    seq = (Investigation.objects.count() or 0) + 1
    if last and last.case_number.startswith("TRX-"):
        try:
            seq = max(seq, int(last.case_number.split("-")[1]) + 1)
        except (IndexError, ValueError):
            pass
    return f"TRX-{seq:04d}"


def _user_can_access(user, investigation) -> bool:
    """Admins (staff) may open every case; investigators only their own."""
    return user.is_staff or investigation.created_by_id == user.id


def _accessible_investigation(request, pk) -> Investigation:
    obj = get_object_or_404(Investigation, pk=pk)
    if not _user_can_access(request.user, obj):
        raise Http404
    return obj


def _viewable_investigation(request, pk) -> Investigation:
    """Read-only access: any signed-in investigator may view a case.

    Mutations (upload, analysis, status changes) still go through
    _accessible_investigation and stay restricted to the owner/staff.
    """
    return get_object_or_404(Investigation, pk=pk)


def signup(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    if not settings.ALLOW_SIGNUP:
        if request.method == "POST":
            messages.error(
                request,
                "Self-registration is disabled. Ask an administrator to create your account.",
            )
            return redirect("login")
        return render(request, "registration/signup.html", {"signup_disabled": True})
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, f"Welcome to TRACE-X, {user.username}. Your account is ready.")
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "registration/signup.html", {"form": form})


@login_required
def users_dashboard(request):
    if not request.user.is_staff:
        raise Http404
    users = (
        User.objects.annotate(
            investigation_count=Count("investigations", distinct=True),
            evidence_count=Count("evidence_uploads", distinct=True),
            finding_count=Count("findings", distinct=True),
        )
        .order_by("-is_active", "-last_login", "username")
    )
    context = {
        "users": users,
        "total_users": users.count(),
        "active_investigators": sum(1 for u in users if u.investigation_count or u.evidence_count),
        "total_cases": Investigation.objects.count(),
        "total_evidence": Evidence.objects.count(),
        "total_findings": Finding.objects.count(),
    }
    return render(request, "investigations/users.html", context)


@login_required
def investigator_roster(request):
    """Directory of investigators — see who worked on which attacks."""
    roster = (
        User.objects.filter(is_active=True)
        .annotate(
            case_count=Count("investigations", distinct=True),
            evidence_count=Count("evidence_uploads", distinct=True),
            finding_count=Count("findings", distinct=True),
        )
        .order_by("-is_staff", "-case_count", "username")
    )
    query = request.GET.get("q", "").strip()
    if query:
        roster = roster.filter(
            Q(username__icontains=query)
            | Q(first_name__icontains=query)
            | Q(last_name__icontains=query)
            | Q(email__icontains=query)
        )
    return render(
        request,
        "investigations/investigators.html",
        {"roster": roster, "query": query, "total_count": User.objects.filter(is_active=True).count()},
    )


@login_required
def investigator_profile(request, username):
    """Read-only profile of a fellow investigator and their attack cases."""
    profile_user = get_object_or_404(User, username=username, is_active=True)
    cases = (
        profile_user.investigations.annotate(
            evidence_count=Count("evidence", distinct=True),
            finding_count=Count("findings", distinct=True),
        ).order_by("-created_at")
    )
    return render(
        request,
        "investigations/investigator_profile.html",
        {
            "profile_user": profile_user,
            "cases": cases,
            "case_count": cases.count(),
            "evidence_count": Evidence.objects.filter(investigation__created_by=profile_user).count(),
            "finding_count": Finding.objects.filter(investigation__created_by=profile_user).count(),
            "is_self": profile_user.pk == request.user.pk,
        },
    )


MAX_EVIDENCE_BYTES = 25 * 1024 * 1024  # 25 MB per evidence file


@login_required
def incident_report(request, pk):
    """Executive summary — timeline, evidence, findings and custody in one view."""
    from .services.reporting import build_report

    investigation = _viewable_investigation(request, pk)
    return render(
        request,
        "investigations/incident_report.html",
        {"investigation": investigation, "report": build_report(investigation)},
    )


@login_required
def incident_report_pdf(request, pk):
    """One-click PDF download of the compiled incident report."""
    from .services.reporting import build_report, render_pdf

    investigation = _viewable_investigation(request, pk)
    report = build_report(investigation)
    response = HttpResponse(render_pdf(report), content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{report["filename"]}"'
    return response


@login_required
def dashboard(request):
    investigations = Investigation.objects.annotate(
        evidence_count=Count("evidence", distinct=True),
        finding_count=Count("findings", distinct=True),
        event_count=Count("timeline_events", distinct=True),
    )
    if not request.user.is_staff:
        investigations = investigations.filter(created_by=request.user)
    context = {
        "investigations": investigations[:10],
        "total_cases": investigations.count(),
        "total_evidence": Evidence.objects.filter(
            investigation__in=investigations.values_list("pk", flat=True)
        ).count(),
        "total_findings": Finding.objects.filter(
            investigation__in=investigations.values_list("pk", flat=True)
        ).count(),
        "total_events": TimelineEvent.objects.filter(
            investigation__in=investigations.values_list("pk", flat=True)
        ).count(),
    }
    return render(request, "investigations/dashboard.html", context)


@login_required
def investigation_list(request):
    investigations = Investigation.objects.annotate(
        evidence_count=Count("evidence", distinct=True),
        finding_count=Count("findings", distinct=True),
    )
    if not request.user.is_staff:
        investigations = investigations.filter(created_by=request.user)
    query = request.GET.get("q", "").strip()
    if query:
        investigations = investigations.filter(
            Q(title__icontains=query) | Q(case_number__icontains=query) | Q(description__icontains=query)
        )
    return render(request, "investigations/investigation_list.html", {"investigations": investigations, "q": query})


@login_required
def investigation_create(request):
    if request.method == "POST":
        form = InvestigationForm(request.POST)
        if form.is_valid():
            investigation = form.save(commit=False)
            investigation.case_number = _case_number()
            investigation.created_by = request.user
            investigation.save()
            messages.success(request, f"Investigation {investigation.case_number} created.")
            return redirect("investigation_detail", pk=investigation.pk)
    else:
        form = InvestigationForm()
    return render(request, "investigations/investigation_form.html", {"form": form, "title": "New Investigation"})


@login_required
def investigation_detail(request, pk):
    investigation = _viewable_investigation(request, pk)
    evidence = investigation.evidence.all()
    events = investigation.timeline_events.select_related("evidence")
    findings = investigation.findings.annotate(link_count=Count("evidence_links")).ordered()
    integrity = verify_investigation(investigation)
    analysis = None
    if request.session.get("last_analysis") == str(investigation.pk):
        analysis = request.session.pop("last_analysis_report", None)
    return render(
        request,
        "investigations/investigation_detail.html",
        {
            "investigation": investigation,
            "evidence": evidence,
            "events": events,
            "findings": findings,
            "integrity": integrity,
            "analysis": analysis,
            "readonly": not _user_can_access(request.user, investigation),
        },
    )


@login_required
@require_POST
def evidence_upload(request, pk):
    investigation = _accessible_investigation(request, pk)
    files = request.FILES.getlist("files")
    if not files:
        messages.error(request, "Attach at least one file.")
        return redirect("investigation_detail", pk=pk)
    created = 0
    skipped = 0
    for file in files:
        if file.size > MAX_EVIDENCE_BYTES:
            messages.error(request, f"Evidence file is too large: {file.name} (limit {MAX_EVIDENCE_BYTES // (1024 * 1024)} MB).")
            continue
        raw = file.read()
        file.seek(0)
        digest = sha256_bytes(raw)
        if Evidence.objects.filter(investigation=investigation, sha256=digest).exists():
            skipped += 1
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = ""
        evidence = Evidence(
            investigation=investigation,
            title=file.name,
            evidence_type=_classify_upload(file.name, content),
            file=file,
            content=content,
            source=file.name,
            uploaded_by=request.user,
        )
        # hash the bytes already read — fingerprint_evidence() would re-open
        # the uploaded stream and leave it closed for the storage save
        evidence.sha256 = digest
        evidence.save()
        record_object(evidence, investigation, request.user)
        created += 1
    investigation.status = Investigation.STATUS_OPEN
    investigation.save(update_fields=["status", "updated_at"])
    summary = f"{created} evidence item(s) added and fingerprinted."
    if skipped:
        summary += f" {skipped} duplicate upload(s) skipped."
    messages.success(request, summary)
    return redirect("investigation_detail", pk=pk)


def _classify_upload(filename: str, content: str) -> str:
    """Pick the evidence type from the extension, refined by file content.

    Previously every .json upload was treated as network data, even SIEM/IDS
    alert payloads.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    text = (content or "").lower()

    if ext == "eml" or ("from:" in text and "subject:" in text):
        return Evidence.TYPE_EMAIL
    if ext in {"png", "jpg", "jpeg", "gif", "bmp", "webp"}:
        return Evidence.TYPE_SCREENSHOT
    if ext == "json":
        if any(k in text for k in ('"alert"', "rule=", "signature=", '"rule"')):
            return Evidence.TYPE_ALERT
        if any(k in text for k in ("dst-ip", '"dst"', "dport", "bytes=", "src=")):
            return Evidence.TYPE_NETWORK
        return Evidence.TYPE_FILE
    if ext in {"csv", "pcap", "cap"}:
        return Evidence.TYPE_NETWORK
    if ext in {"log", "txt"}:
        return Evidence.TYPE_LOG
    return Evidence.TYPE_FILE


@login_required
def evidence_detail(request, pk, evidence_pk):
    investigation = _viewable_investigation(request, pk)
    evidence = get_object_or_404(Evidence, pk=evidence_pk, investigation=investigation)
    integrity = verify_object(evidence, investigation)
    links = evidence.finding_links.select_related("finding")
    return render(
        request,
        "investigations/evidence_detail.html",
        {
            "investigation": investigation,
            "evidence": evidence,
            "integrity": integrity,
            "links": links,
            "readonly": not _user_can_access(request.user, investigation),
        },
    )


@login_required
@require_POST
def analyze(request, pk):
    investigation = _accessible_investigation(request, pk)
    if not investigation.evidence.exists():
        messages.error(request, "Add evidence before running AI analysis.")
        return redirect("investigation_detail", pk=pk)
    report = run_analysis(investigation, user=request.user)
    request.session["last_analysis"] = str(investigation.pk)
    request.session["last_analysis_report"] = report
    messages.success(request, f"Analysis complete: {report['events']} events, {len(report['findings'])} findings.")
    return redirect("investigation_detail", pk=pk)


@login_required
def finding_detail(request, pk, finding_pk):
    investigation = _viewable_investigation(request, pk)
    finding = get_object_or_404(
        Finding.objects.select_related("investigation").prefetch_related("evidence_links__evidence", "evidence_links__timeline_event"),
        pk=finding_pk,
        investigation=investigation,
    )
    integrity = verify_object(finding, investigation)
    related_events = investigation.timeline_events.filter(
        evidence_id__in=[link.evidence_id for link in finding.evidence_links.all()]
    )
    return render(
        request,
        "investigations/finding_detail.html",
        {
            "investigation": investigation,
            "finding": finding,
            "links": finding.evidence_links.select_related("evidence", "timeline_event"),
            "integrity": integrity,
            "related_events": related_events,
            "status_choices": Finding._meta.get_field("status").choices,
            "readonly": not _user_can_access(request.user, investigation),
        },
    )


@login_required
@require_POST
def finding_status(request, pk, finding_pk):
    investigation = _accessible_investigation(request, pk)
    finding = get_object_or_404(Finding, pk=finding_pk, investigation=investigation)
    valid = {value for value, _label in Finding._meta.get_field("status").choices}
    new_status = (request.POST.get("status") or "").strip()
    if new_status not in valid:
        messages.error(request, "Invalid finding status.")
        return redirect("finding_detail", pk=pk, finding_pk=finding_pk)
    finding.status = new_status
    finding.save(update_fields=["status"])
    record_object(finding, investigation, request.user)
    messages.success(request, "Finding status updated and re-fingerprinted.")
    return redirect("finding_detail", pk=pk, finding_pk=finding_pk)


@login_required
def integrity_view(request, pk):
    investigation = _viewable_investigation(request, pk)
    report = verify_investigation(investigation)
    records = investigation.integrity_records.order_by("-height")
    return render(
        request,
        "investigations/integrity.html",
        {"investigation": investigation, "report": report, "records": records},
    )


# ------------------------------------------------------------------ JSON API

@login_required
def api_investigations(request):
    investigations = Investigation.objects.all()
    if not request.user.is_staff:
        investigations = investigations.filter(created_by=request.user)
    data = [
        {
            "id": str(i.pk),
            "case_number": i.case_number,
            "title": i.title,
            "status": i.status,
            "evidence": i.evidence.count(),
            "findings": i.findings.count(),
            "timeline_events": i.timeline_events.count(),
            "created_at": i.created_at.isoformat(),
        }
        for i in investigations[:100]
    ]
    return JsonResponse({"investigations": data})


@login_required
def api_investigation_detail(request, pk):
    investigation = _viewable_investigation(request, pk)
    return JsonResponse(
        {
            "id": str(investigation.pk),
            "case_number": investigation.case_number,
            "title": investigation.title,
            "description": investigation.description,
            "status": investigation.status,
            "integrity": verify_investigation(investigation),
            "evidence": [
                {
                    "id": str(e.pk),
                    "title": e.title,
                    "type": e.evidence_type,
                    "sha256": e.sha256,
                    "collected_at": e.collected_at.isoformat(),
                }
                for e in investigation.evidence.all()
            ],
            "timeline": [
                {
                    "id": str(ev.pk),
                    "occurred_at": ev.occurred_at.isoformat(),
                    "title": ev.title,
                    "severity": ev.severity,
                    "source_ip": ev.source_ip,
                    "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
                }
                for ev in investigation.timeline_events.all()
            ],
            "findings": [
                {
                    "id": str(f.pk),
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "summary": f.summary,
                    "explanation": f.explanation,
                    "traceability": [
                        {
                            "evidence_id": str(l.evidence_id),
                            "evidence_title": l.evidence.title,
                            "relation": l.relation,
                            "rationale": l.rationale,
                            "excerpt": l.excerpt,
                        }
                        for l in f.evidence_links.all()
                    ],
                }
                for f in investigation.findings.ordered()
            ],
        }
    )


@login_required
@require_POST
def api_analyze(request, pk):
    investigation = _accessible_investigation(request, pk)
    if not investigation.evidence.exists():
        return JsonResponse({"error": "No evidence to analyze."}, status=400)
    report = run_analysis(investigation, user=request.user)
    return JsonResponse(report)


@login_required
def api_integrity(request, pk):
    investigation = _viewable_investigation(request, pk)
    return JsonResponse(verify_investigation(investigation))


@login_required
def protected_media(request, path):
    """Serve uploaded evidence to authenticated users only."""
    return serve_static(request, path, document_root=settings.MEDIA_ROOT)


def api_health(request):
    return JsonResponse({"status": "ok", "service": "trace-x"})


@login_required
@require_POST
def api_assistant(request):
    """Sentinel chat endpoint — one message in, one human-style reply out."""
    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON body."}, status=400)
    message = str(payload.get("message", ""))[:2000]
    from .services.assistant import respond

    return JsonResponse(respond(request.user, message))
