import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

def _severity_rank(field="severity"):
    return models.Case(
        models.When(**{field: "critical"}, then=models.Value(4)),
        models.When(**{field: "high"}, then=models.Value(3)),
        models.When(**{field: "medium"}, then=models.Value(2)),
        models.When(**{field: "low"}, then=models.Value(1)),
        default=models.Value(0),
        output_field=models.IntegerField(),
    )


class FindingQuerySet(models.QuerySet):
    def ordered(self):
        """Order by real severity (critical -> info), not alphabetically."""
        return self.annotate(_severity_rank=_severity_rank()).order_by("-_severity_rank", "-created_at")


class Investigation(models.Model):
    STATUS_OPEN = "open"
    STATUS_ANALYZING = "analyzing"
    STATUS_REPORTED = "reported"
    STATUS_CLOSED = "closed"
    STATUS_CHOICES = [
        (STATUS_OPEN, "Open"),
        (STATUS_ANALYZING, "Analyzing"),
        (STATUS_REPORTED, "Reported"),
        (STATUS_CLOSED, "Closed"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case_number = models.CharField(max_length=32, unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_OPEN)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="investigations"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # Tamper-evident anchor kept outside the append-only chain so deleting the
    # newest block (truncating the ledger) can be detected.
    ledger_length = models.PositiveIntegerField(default=0)
    ledger_tip = models.CharField(max_length=64, blank=True, default="")
    # Fingerprint of the evidence set at last analysis, used to make re-runs
    # idempotent (no duplicate timeline/finding/ledger entries).
    analysis_signature = models.CharField(max_length=64, blank=True, default="")
    analysis_report = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.case_number} - {self.title}"

    @property
    def integrity_status(self):
        from .services.integrity import verify_chain_for

        result = verify_chain_for(self)
        return "verified" if result["valid"] else "tampered"


class Evidence(models.Model):
    TYPE_LOG = "log"
    TYPE_ALERT = "alert"
    TYPE_EMAIL = "email"
    TYPE_SCREENSHOT = "screenshot"
    TYPE_NETWORK = "network"
    TYPE_FILE = "file"
    TYPE_CHOICES = [
        (TYPE_LOG, "Log"),
        (TYPE_ALERT, "Alert"),
        (TYPE_EMAIL, "Email"),
        (TYPE_SCREENSHOT, "Screenshot"),
        (TYPE_NETWORK, "Network Data"),
        (TYPE_FILE, "File Artifact"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name="evidence")
    title = models.CharField(max_length=255)
    evidence_type = models.CharField(max_length=16, choices=TYPE_CHOICES, default=TYPE_FILE)
    description = models.TextField(blank=True)
    file = models.FileField(upload_to="evidence/%Y/%m/", blank=True, null=True)
    content = models.TextField(blank=True, help_text="Text content for logs, alerts, emails, network data")
    sha256 = models.CharField(max_length=64, db_index=True)
    source = models.CharField(max_length=255, blank=True)
    collected_at = models.DateTimeField(default=timezone.now)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="evidence_uploads"
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    parsed_summary = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["collected_at"]

    def __str__(self):
        return f"[{self.get_evidence_type_display()}] {self.title}"

    @property
    def size_bytes(self):
        if self.file:
            try:
                return self.file.size
            except (OSError, ValueError):
                return 0
        return len(self.content.encode("utf-8"))

    @property
    def short_hash(self):
        return f"{self.sha256[:16]}..."


class TimelineEvent(models.Model):
    SEVERITY_INFO = "info"
    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CRITICAL = "critical"
    SEVERITY_CHOICES = [
        (SEVERITY_INFO, "Info"),
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
        (SEVERITY_CRITICAL, "Critical"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name="timeline_events")
    evidence = models.ForeignKey(Evidence, on_delete=models.SET_NULL, null=True, related_name="timeline_events")
    occurred_at = models.DateTimeField()
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_INFO)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    actor = models.CharField(max_length=128, blank=True)
    generated_by = models.CharField(max_length=32, default="manual")
    raw = models.TextField(blank=True)

    class Meta:
        ordering = ["occurred_at"]

    def __str__(self):
        return f"{self.occurred_at:%Y-%m-%d %H:%M} {self.title}"


class Finding(models.Model):
    CATEGORY_CHOICES = [
        ("reconnaissance", "Reconnaissance"),
        ("initial_access", "Initial Access"),
        ("execution", "Execution"),
        ("persistence", "Persistence"),
        ("privilege_escalation", "Privilege Escalation"),
        ("credential_access", "Credential Access"),
        ("lateral_movement", "Lateral Movement"),
        ("collection", "Collection"),
        ("exfiltration", "Exfiltration"),
        ("defense_evasion", "Defense Evasion"),
        ("anomaly", "Anomaly"),
        ("integrity", "Integrity"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name="findings")
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=32, choices=CATEGORY_CHOICES, default="anomaly")
    severity = models.CharField(max_length=16, choices=TimelineEvent.SEVERITY_CHOICES, default=TimelineEvent.SEVERITY_MEDIUM)
    confidence = models.FloatField(default=0.5, help_text="0..1")
    summary = models.TextField()
    explanation = models.TextField(blank=True, help_text="Natural language explanation of the conclusion")
    mitre_technique = models.CharField(max_length=64, blank=True)
    status = models.CharField(
        max_length=16,
        choices=[("confirmed", "Confirmed"), ("suspected", "Suspected"), ("dismissed", "Dismissed")],
        default="suspected",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="findings"
    )
    generated_by = models.CharField(max_length=32, default="manual")
    created_at = models.DateTimeField(auto_now_add=True)

    objects = FindingQuerySet.as_manager()

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title

    @property
    def evidence_count(self):
        return self.evidence_links.count()


class FindingEvidence(models.Model):
    RELATION_CHOICES = [
        ("supports", "Supports conclusion"),
        ("corroborates", "Corroborates"),
        ("context", "Context"),
        ("contradicts", "Contradicts"),
    ]

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="evidence_links")
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE, related_name="finding_links")
    timeline_event = models.ForeignKey(
        TimelineEvent, on_delete=models.SET_NULL, null=True, blank=True, related_name="finding_links"
    )
    relation = models.CharField(max_length=16, choices=RELATION_CHOICES, default="supports")
    rationale = models.TextField(blank=True, help_text="Why this evidence supports the conclusion")
    excerpt = models.TextField(blank=True, help_text="Quoted excerpt from the evidence")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("finding", "evidence", "timeline_event")]

    def __str__(self):
        return f"{self.finding.title} <- {self.evidence.title}"


class IntegrityRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    investigation = models.ForeignKey(Investigation, on_delete=models.CASCADE, related_name="integrity_records")
    object_type = models.CharField(max_length=32)
    object_id = models.CharField(max_length=64)
    payload_hash = models.CharField(max_length=64)
    prev_hash = models.CharField(max_length=64)
    block_hash = models.CharField(max_length=64, db_index=True)
    height = models.PositiveIntegerField()
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name="integrity_records"
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["height"]
        unique_together = [("investigation", "height")]

    def __str__(self):
        return f"#{self.height} {self.object_type}:{self.object_id}"
