"""One-Click Incident Report — shared builder for the executive summary page
and the downloadable PDF.

build_report() compiles everything about a case into a single plain dict so
the HTML template and the PDF renderer stay in sync.
"""

import html
from io import BytesIO

from django.utils import timezone

from ..models import Evidence, Finding, TimelineEvent

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SECTIONS = [
    "Cover sheet",
    "Executive summary",
    "Key findings",
    "Attack timeline",
    "Evidence register",
    "Chain of custody",
    "Sign-off",
]


def _fmt(value):
    return html.escape(str(value)) if value is not None else ""


def _severity_rank(severity):
    return SEVERITY_ORDER.get(severity, -1)


def build_report(investigation):
    """Compile timeline, evidence, findings and custody into one dict."""
    from .integrity import verify_investigation

    events = list(
        investigation.timeline_events.select_related("evidence").order_by("occurred_at")
    )
    findings = sorted(investigation.findings.all(), key=lambda f: -_severity_rank(f.severity))
    evidence = list(investigation.evidence.all().order_by("uploaded_at"))
    integrity = verify_investigation(investigation)

    high_risk = sum(1 for f in findings if _severity_rank(f.severity) >= 3)
    narrative = _narrative(investigation, events, findings, evidence, integrity)

    return {
        "case_number": investigation.case_number,
        "title": investigation.title,
        "description": investigation.description,
        "status": investigation.get_status_display(),
        "status_code": investigation.status,
        "lead": investigation.created_by.username if investigation.created_by else "system",
        "opened_at": investigation.created_at,
        "updated_at": investigation.updated_at,
        "generated_at": timezone.now(),
        "filename": f"{investigation.case_number}-incident-report.pdf",
        "sections": SECTIONS,
        "stats": {
            "evidence": len(evidence),
            "events": len(events),
            "findings": len(findings),
            "high_risk": high_risk,
            "chain_blocks": integrity["chain"].get("blocks", 0),
        },
        "narrative": narrative,
        "findings": [
            {
                "id": str(f.pk),
                "title": f.title,
                "severity": f.severity,
                "confidence": f.confidence,
                "category": f.get_category_display(),
                "category_code": f.category,
                "mitre": f.mitre_technique or "—",
                "status": f.get_status_display(),
                "summary": f.summary,
                "explanation": f.explanation,
                "evidence_count": f.evidence_links.count(),
                "created_at": f.created_at,
                "generated_by": f.generated_by,
            }
            for f in findings
        ],
        "events": [
            {
                "occurred_at": e.occurred_at,
                "title": e.title,
                "description": e.description,
                "severity": e.severity,
                "actor": e.actor or "—",
                "source_ip": e.source_ip or "—",
                "generated_by": e.generated_by,
                "evidence": e.evidence.title if e.evidence else "—",
            }
            for e in events
        ],
        "evidence": [
            {
                "id": str(e.pk),
                "title": e.title,
                "type": e.get_evidence_type_display(),
                "type_code": e.evidence_type,
                "sha256": e.sha256 or "not fingerprinted",
                "source": e.source or "—",
                "uploaded_at": e.uploaded_at,
                "uploaded_by": e.uploaded_by.username if e.uploaded_by else "—",
                "events": e.parsed_summary.get("event_count", 0) if isinstance(e.parsed_summary, dict) else 0,
            }
            for e in evidence
        ],
        "integrity": {
            "valid": integrity["valid"],
            "blocks": integrity["chain"].get("blocks", 0),
            "tip": integrity["chain"].get("tip") or investigation.ledger_tip or "—",
            "checked_at": integrity["checked_at"],
            "tampered": integrity["tampered_objects"],
        },
    }


def _narrative(investigation, events, findings, evidence, integrity):
    stored = investigation.analysis_report or {}
    if stored.get("narrative"):
        return stored["narrative"]

    lines = [
        f"Investigation {investigation.case_number}: {investigation.title}. "
        f"{len(evidence)} evidence item(s), {len(events)} timeline event(s), {len(findings)} finding(s)."
    ]
    if events:
        lines.append(
            f"Recorded activity spans {events[0].occurred_at:%Y-%m-%d %H:%M} UTC to "
            f"{events[-1].occurred_at:%Y-%m-%d %H:%M} UTC."
        )
    if findings:
        top = findings[0]
        lines.append(
            f"Most severe conclusion: '{top.title}' ({top.severity}, confidence {top.confidence:.0%}) — {top.summary}"
        )
    else:
        lines.append(
            "No confirmed attack patterns yet — this report reflects the activity recorded so far. "
            "Run AI analysis from the case page to generate findings."
        )
    lines.append(
        "Chain of custody: "
        + ("integrity chain VERIFIED — every evidence and conclusion fingerprint checks out."
           if integrity["valid"] else
           "integrity chain FAILED verification — see the chain-of-custody section below.")
    )
    return " ".join(lines)


# --------------------------------------------------------------------- PDF
def render_pdf(report):
    """Render the compiled report to PDF bytes (reportlab platypus)."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    GOLD = colors.HexColor("#b8912a")
    GOLD_SOFT = colors.HexColor("#f3e3ae")
    INK = colors.HexColor("#1c1c22")
    GREY = colors.HexColor("#6b6b78")
    RED = colors.HexColor("#c0392b")
    LINE = colors.HexColor("#d9d4c4")

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        title=f"Incident Report {report['case_number']}",
        author="TRACE-X Digital Forensics",
    )

    base = getSampleStyleSheet()
    styles = {
        "brand": ParagraphStyle("brand", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=9, textColor=GOLD, alignment=TA_CENTER, spaceAfter=2),
        "title": ParagraphStyle("title", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=19, textColor=INK, alignment=TA_CENTER, spaceAfter=4),
        "sub": ParagraphStyle("sub", parent=base["Normal"], fontName="Helvetica",
                              fontSize=10, textColor=GREY, alignment=TA_CENTER, spaceAfter=2),
        "conf": ParagraphStyle("conf", parent=base["Normal"], fontName="Helvetica-Bold",
                               fontSize=8.5, textColor=RED, alignment=TA_CENTER, spaceAfter=10),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=12.5, textColor=INK, spaceBefore=14, spaceAfter=5),
        "body": ParagraphStyle("body", parent=base["Normal"], fontName="Helvetica",
                               fontSize=9.5, leading=13.5, textColor=INK, alignment=TA_JUSTIFY),
        "cell": ParagraphStyle("cell", parent=base["Normal"], fontName="Helvetica",
                               fontSize=8.5, leading=11, textColor=INK),
        "cellb": ParagraphStyle("cellb", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=8.5, leading=11, textColor=INK),
        "small": ParagraphStyle("small", parent=base["Normal"], fontName="Helvetica",
                                fontSize=8, textColor=GREY, leading=10.5),
    }

    def P(text, style="body"):
        return Paragraph(_fmt(text), styles[style])

    def head(text):
        return [Spacer(1, 2), Paragraph(_fmt(text), styles["h2"]),
                HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=6)]

    def tbl(data, widths, header=True, align_right=()):
        t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#faf8f2")]),
        ]
        if header:
            style += [
                ("BACKGROUND", (0, 0), (-1, 0), GOLD_SOFT),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ]
        for col in align_right:
            style.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
        t.setStyle(TableStyle(style))
        return t

    story = []

    # -------- cover
    story += [
        Spacer(1, 6 * mm),
        Paragraph("TRACE-X &#9670; DIGITAL FORENSICS", styles["brand"]),
        Paragraph("INCIDENT INVESTIGATION REPORT", styles["title"]),
        Paragraph(f"Case {report['case_number']} &mdash; {report['title']}", styles["sub"]),
        Paragraph("CONFIDENTIAL &#183; FOR AUTHORISED PERSONNEL ONLY", styles["conf"]),
    ]
    meta = [
        [Paragraph("Case number", styles["cellb"]), Paragraph(report["case_number"], styles["cell"]),
         Paragraph("Status", styles["cellb"]), Paragraph(report["status"], styles["cell"])],
        [Paragraph("Lead investigator", styles["cellb"]), Paragraph(report["lead"], styles["cell"]),
         Paragraph("Opened (UTC)", styles["cellb"]),
         Paragraph(f"{report['opened_at']:%Y-%m-%d %H:%M}", styles["cell"])],
        [Paragraph("Evidence items", styles["cellb"]), Paragraph(str(report["stats"]["evidence"]), styles["cell"]),
         Paragraph("Timeline events", styles["cellb"]), Paragraph(str(report["stats"]["events"]), styles["cell"])],
        [Paragraph("Findings", styles["cellb"]),
         Paragraph(f"{report['stats']['findings']} ({report['stats']['high_risk']} high/critical)", styles["cell"]),
         Paragraph("Generated", styles["cellb"]),
         Paragraph(f"{report['generated_at']:%Y-%m-%d %H:%M} UTC", styles["cell"])],
    ]
    story.append(tbl(meta, [34 * mm, 51 * mm, 34 * mm, 51 * mm], header=False))
    if report["description"]:
        story += head("Case description")
        story.append(P(report["description"]))

    # -------- executive summary
    story += head("1. Executive summary")
    story.append(P(report["narrative"]))

    # -------- findings
    story += head("2. Key findings")
    if report["findings"]:
        rows = [[Paragraph(h, styles["cellb"]) for h in
                 ("Severity", "Finding", "Confidence", "Technique", "Status", "Evidence")]]
        for f in report["findings"]:
            rows.append([
                Paragraph(f["severity"].upper(), styles["cellb"]),
                Paragraph(f"<b>{_fmt(f['title'])}</b><br/>{_fmt(f['summary'])}", styles["cell"]),
                Paragraph(f"{f['confidence']:.0%}", styles["cell"]),
                Paragraph(f["mitre"], styles["cell"]),
                Paragraph(f["status"], styles["cell"]),
                Paragraph(str(f["evidence_count"]), styles["cell"]),
            ])
        story.append(tbl(rows, [17 * mm, 66 * mm, 18 * mm, 30 * mm, 22 * mm, 17 * mm]))
    else:
        story.append(P("No findings recorded yet — run AI analysis to generate conclusions."))

    # -------- timeline
    story += head("3. Attack timeline")
    if report["events"]:
        rows = [[Paragraph(h, styles["cellb"]) for h in ("When (UTC)", "Event", "Severity", "Actor / source")]]
        for e in report["events"][:300]:
            rows.append([
                Paragraph(f"{e['occurred_at']:%Y-%m-%d %H:%M}", styles["cell"]),
                Paragraph(_fmt(e["title"]), styles["cell"]),
                Paragraph(e["severity"].upper(), styles["cellb"]),
                Paragraph(_fmt(f"{e['actor']} / {e['source_ip']}"), styles["cell"]),
            ])
        story.append(tbl(rows, [30 * mm, 78 * mm, 18 * mm, 44 * mm]))
        if len(report["events"]) > 300:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"&#8230; {len(report['events']) - 300} earlier events omitted — see the case timeline.",
                                   styles["small"]))
    else:
        story.append(P("No timeline events recorded yet."))

    # -------- evidence
    story += head("4. Evidence register")
    if report["evidence"]:
        rows = [[Paragraph(h, styles["cellb"]) for h in ("Evidence", "Type", "SHA-256 fingerprint", "Uploaded")]]
        for e in report["evidence"]:
            rows.append([
                Paragraph(_fmt(e["title"]), styles["cell"]),
                Paragraph(_fmt(e["type"]), styles["cell"]),
                Paragraph(_fmt(e["sha256"]), styles["small"]),
                Paragraph(f"{e['uploaded_at']:%Y-%m-%d} by {_fmt(e['uploaded_by'])}", styles["cell"]),
            ])
        story.append(tbl(rows, [42 * mm, 24 * mm, 68 * mm, 36 * mm]))
    else:
        story.append(P("No evidence uploaded yet."))

    # -------- chain of custody
    story += head("5. Chain of custody")
    ic = report["integrity"]
    verdict = "VERIFIED — no tampering detected" if ic["valid"] else "FAILED — tampering detected"
    rows = [
        [Paragraph("Verification result", styles["cellb"]),
         Paragraph(verdict, styles["cellb"])],
        [Paragraph("Ledger blocks", styles["cellb"]), Paragraph(str(ic["blocks"]), styles["cell"])],
        [Paragraph("Chain tip", styles["cellb"]), Paragraph(_fmt(ic["tip"]), styles["small"])],
        [Paragraph("Checked at (UTC)", styles["cellb"]), Paragraph(str(ic["checked_at"]), styles["cell"])],
    ]
    if ic["tampered"]:
        rows.append([Paragraph("Tampered objects", styles["cellb"]),
                     Paragraph(", ".join(_fmt(t.get("label", t.get("object_id", "?"))) for t in ic["tampered"]),
                              styles["cell"])])
    story.append(tbl(rows, [42 * mm, 128 * mm], header=False))

    # -------- sign-off
    story += head("6. Sign-off")
    story.append(P(
        f"This report was compiled automatically by TRACE-X from case {report['case_number']} "
        f"on {report['generated_at']:%Y-%m-%d %H:%M} UTC. Every conclusion above is traceable to the "
        "evidence register: open any finding in TRACE-X to see the exact supporting excerpts and rationale. "
        "The evidence fingerprints and hash chain quoted here can be re-verified at any time from the "
        "case's Integrity page."
    ))
    story += [
        Spacer(1, 14),
        Table(
            [[Paragraph("Lead investigator", styles["small"]), Paragraph("Signature / date", styles["small"])],
             [Paragraph("_________________________", styles["cell"]),
              Paragraph("_________________________", styles["cell"])]],
            colWidths=[85 * mm, 85 * mm],
            style=TableStyle([("TOPPADDING", (0, 0), (-1, -1), 6)]),
        ),
        Spacer(1, 8),
        Paragraph(
            f"TRACE-X &#183; Evidence-to-Conclusion traceability &#183; generated {report['generated_at']:%Y-%m-%d %H:%M} UTC",
            styles["brand"],
        ),
    ]

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(GOLD)
        canvas.setLineWidth(0.6)
        canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(GREY)
        canvas.drawString(18 * mm, 10 * mm,
                          f"TRACE-X Incident Report {report['case_number']} \u00b7 CONFIDENTIAL")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
