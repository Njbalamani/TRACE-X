"""Investigation report generation: Markdown + HTML + PDF (fpdf2).
Everything in the report is sourced from stored evidence, findings and the
integrity ledger — nothing is fabricated."""
from __future__ import annotations

import hashlib
import html as html_mod
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrity.ledger import ledger
from app.models.models import AnalysisRun, Event, Evidence, Finding, Investigation, Report
from app.services import storage
from app.services.audit_service import log_action


def _esc(text) -> str:
    return html_mod.escape(str(text if text is not None else ""))


def _collect(db: Session, investigation: Investigation) -> dict:
    evidences = list(db.scalars(select(Evidence).where(
        Evidence.investigation_id == investigation.id).order_by(Evidence.id)))
    findings = list(db.scalars(select(Finding).where(
        Finding.investigation_id == investigation.id).order_by(Finding.id)))
    events = list(db.scalars(select(Event).where(
        Event.investigation_id == investigation.id).order_by(Event.timestamp, Event.id)))
    run = db.scalars(select(AnalysisRun).where(
        AnalysisRun.investigation_id == investigation.id)
        .order_by(AnalysisRun.id.desc())).first()
    events_by_id = {e.id: e for e in events}
    return {"evidences": evidences, "findings": findings, "events": events,
            "run": run, "events_by_id": events_by_id}


def _finding_links(db: Session, finding: Finding) -> list[tuple[Event, Evidence | None]]:
    from app.models.models import FindingEvidenceLink
    out = []
    links = db.scalars(select(FindingEvidenceLink).where(
        FindingEvidenceLink.finding_id == finding.id)).all()
    for link in links:
        event = db.get(Event, link.event_id) if link.event_id else None
        evidence = db.get(Evidence, link.evidence_id) if link.evidence_id else None
        out.append((event, evidence))
    return out


def build_report_sections(db: Session, investigation: Investigation) -> dict:
    data = _collect(db, investigation)
    evidences, findings, events, run = (
        data["evidences"], data["findings"], data["events"], data["run"])
    suspicious = [e for e in events if e.is_suspicious]
    summary = (run.summary if run else {}) or {}

    lines: list[str] = []
    lines.append(f"# TRACE-X Investigation Report — {investigation.code}")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(summary.get("executive_summary") or
                 "Analysis has not been run yet. Generate an analysis to populate the executive summary.")
    lines.append("")

    lines.append("## Investigation Details")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Investigation ID | {investigation.code} |")
    lines.append(f"| Name | {_esc(investigation.name)} |")
    lines.append(f"| Investigator | {_esc(investigation.investigator) or '—'} |")
    lines.append(f"| Incident type | {_esc(investigation.incident_type)} |")
    lines.append(f"| Severity | {investigation.severity} |")
    lines.append(f"| Status | {investigation.status} |")
    lines.append(f"| Created | {investigation.created_at} |")
    lines.append("")

    lines.append("## Evidence Summary")
    if evidences:
        lines.append("| Evidence ID | Filename | Type | Size (bytes) | SHA-256 | Status |")
        lines.append("|---|---|---|---|---|---|")
        for ev in evidences:
            lines.append(f"| {ev.code} | {_esc(ev.original_filename)} | {ev.file_type} | "
                         f"{ev.size} | `{ev.sha256[:32]}…` | {ev.integrity_status} |")
    else:
        lines.append("_No evidence uploaded._")
    lines.append("")

    lines.append("## Timeline")
    if suspicious:
        lines.append("| Time | Event | Evidence | Stage |")
        lines.append("|---|---|---|---|")
        for e in sorted(suspicious, key=lambda x: (x.timestamp or "9999", x.id)):
            lines.append(f"| {e.timestamp or '—'} | {_esc((e.message or e.event_type)[:120])} | "
                         f"{e.evidence.code if e.evidence else '—'} ({e.code}) | "
                         f"{_stage_of(e)} |")
    else:
        lines.append("_No suspicious events recorded._")
    lines.append("")

    lines.append("## Findings")
    if findings:
        for f in findings:
            lines.append(f"### {f.code} — {_esc(f.title)}")
            lines.append(f"- **Severity:** {f.severity}  ")
            lines.append(f"- **Confidence:** {f.confidence}  ")
            lines.append(f"- **Classification:** {f.classification}"
                         + (f"  \n- **Attack stage (possible):** {f.attack_stage}" if f.attack_stage else ""))
            lines.append(f"- **Conclusion:** {_esc(f.conclusion)}")
            lines.append(f"- **Explanation:** {_esc(f.explanation)}")
            lines.append("- **Supporting evidence:** " +
                         (", ".join(f.supporting_evidence_ids) or "—"))
            lines.append("- **Supporting events:** " +
                         (", ".join(f.supporting_event_ids) or "—"))
            if f.excerpts:
                lines.append("- **Evidence excerpts:**")
                for ex in f.excerpts[:5]:
                    lines.append(f"    - `{ex.get('evidence_code')} · {ex.get('timestamp')}` — {_esc(ex.get('text'))[:200]}")
            lines.append("")
    else:
        lines.append("_No findings generated yet._")
    lines.append("")

    lines.append("## Evidence Traceability")
    lines.append("Each finding with the exact events and evidence that support it:")
    for f in findings:
        lines.append(f"- **{f.code} {_esc(f.title)}**")
        for event, evidence in _finding_links(db, f):
            if event:
                lines.append(f"    - {event.code} ({event.timestamp or 'no timestamp'}) "
                             f"→ {evidence.code if evidence else '—'} "
                             f"{_esc(evidence.original_filename if evidence else '')}")
    if not findings:
        lines.append("- _No findings to trace._")
    lines.append("")

    lines.append("## Integrity Verification")
    chain = ledger.verify_chain(db, investigation_id=investigation.id)
    lines.append(f"Tamper-evident ledger: {'VALID' if chain['valid'] else 'CHAIN BROKEN — ' + str(chain.get('error'))}")
    lines.append(f"Ledger blocks checked: {chain['blocks_checked']}")
    lines.append("")
    lines.append("Note: hashes prove the stored bytes match the recorded fingerprint; "
                 "they do not prove that file contents are truthful.")
    lines.append("")

    lines.append("## Attack Analysis")
    stages = summary.get("attack_stages") or []
    if stages:
        for s in stages:
            lines.append(f"- **{s['stage']}** (confidence: {s['confidence']}) — "
                         f"{s['event_count']} event(s): {', '.join(s['event_ids'][:8])}")
        if summary.get("correlation", {}).get("chains"):
            c0 = summary["correlation"]["chains"][0]
            lines.append("")
            lines.append(f"Most correlated sequence ({c0['chain_id']}): " +
                         " → ".join(f"{s['event_code']}@{s['timestamp']}" for s in c0["sequence"][:8]))
    else:
        lines.append("_Run the analysis to generate attack-stage classification._")
    lines.append("")

    lines.append("## Confidence — Confirmed vs Suspected")
    for item in summary.get("confirmed", []) or []:
        lines.append(f"- **CONFIRMED:** {item}")
    for item in summary.get("suspected", []) or []:
        lines.append(f"- **SUSPECTED:** {item}")
    if not summary:
        lines.append("_No analysis run yet._")
    lines.append("")

    lines.append("## Missing Information")
    for item in summary.get("missing_information", []) or ["No analysis run yet."]:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Recommendations")
    for item in summary.get("next_steps", []) or []:
        lines.append(f"- {item}")
    if not summary:
        lines.append("- Run the investigation analysis to generate recommendations.")
    lines.append("")
    return {"markdown": "\n".join(lines), "data": data, "summary": summary}


def _stage_of(event: Event) -> str:
    from app.analyzers.stages import classify_event_stage
    return classify_event_stage(event) or "—"


def _build_html(title: str, sections_md: str, investigation: Investigation) -> str:
    """Very small markdown→HTML converter for the fixed report structure."""
    body: list[str] = []
    in_table = False
    for raw in sections_md.splitlines():
        line = raw.rstrip()
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if not in_table:
                body.append("<table>")
                in_table = True
                body.append("<tr>" + "".join(f"<th>{_esc(c)}</th>" for c in cells) + "</tr>")
            else:
                body.append("<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("# "):
            body.append(f"<h1>{_esc(line[2:])}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{_esc(line[3:])}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{_esc(line[4:])}</h3>")
        elif line.startswith("- "):
            body.append(f"<li>{_inline(line[2:])}</li>")
        elif line.startswith("    - "):
            body.append(f"<li class='sub'>{_inline(line[6:])}</li>")
        elif line:
            body.append(f"<p>{_inline(line)}</p>")
    if in_table:
        body.append("</table>")
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{_esc(title)}</title>
<style>
 body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px auto; max-width: 900px;
        color: #111827; line-height: 1.55; }}
 h1 {{ border-bottom: 3px solid #0e7490; padding-bottom: 8px; color: #0e7490; }}
 h2 {{ color: #155e75; border-bottom: 1px solid #d1d5db; padding-bottom: 4px; margin-top: 32px; }}
 table {{ border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 0.92em; }}
 th, td {{ border: 1px solid #d1d5db; padding: 6px 10px; text-align: left; }}
 th {{ background: #f1f5f9; }}
 li {{ margin: 4px 0; }}
 li.sub {{ list-style: circle; margin-left: 28px; }}
 code {{ background: #f1f5f9; padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }}
 footer {{ margin-top: 48px; color: #6b7280; font-size: 0.85em; border-top: 1px solid #e5e7eb; padding-top: 12px; }}
 @media print {{ body {{ margin: 10mm; }} h2 {{ page-break-after: avoid; }} }}
</style></head><body>
{chr(10).join(body)}
<footer>Generated by TRACE-X — evidence-to-conclusion traceability. Hashes prove stored bytes match
recorded fingerprints; they do not certify content truthfulness.</footer>
</body></html>"""


def _inline(text: str) -> str:
    text = _esc(text)
    # simple markdown bold/code/italic handling
    import re
    out = text
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    out = re.sub(r"_(.+?)_", r"<em>\1</em>", out)
    return out


def _build_pdf(md_text: str, out_path: Path) -> bool:
    try:
        from fpdf import FPDF
    except ImportError:
        return False
    import textwrap

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    def _clean(s: str) -> str:
        s = (s.replace("—", "-").replace("–", "-").replace("→", "->")
              .replace("…", "...").replace("·", "-").encode("latin-1", "replace").decode("latin-1"))
        # break unbreakable long tokens (hashes) so a single char never exceeds line width
        words = [w if len(w) <= 48 else " ".join(w[i:i + 32] for i in range(0, len(w), 32))
                 for w in s.split(" ")]
        s = " ".join(words)
        return textwrap.shorten(s, width=400, placeholder="…")

    def _emit(line: str, font: tuple[str, str], size: float, ln_h: float):
        pdf.set_font(font[0], font[1], size)
        try:
            pdf.multi_cell(0, ln_h, line)
        except Exception:
            pdf.set_font("Helvetica", "", size)
            try:
                pdf.multi_cell(0, ln_h, textwrap.shorten(line, width=120, placeholder="..."))
            except Exception:
                pass  # a single unrenderable line must not kill the report

    for raw in md_text.splitlines():
        line = raw.rstrip()
        if not line:
            pdf.ln(2)
            continue
        if line.startswith("### "):
            _emit(_clean(line[4:]), ("Helvetica", "B"), 11, 6)
        elif line.startswith("## "):
            pdf.ln(2)
            pdf.set_text_color(14, 116, 144)
            _emit(_clean(line[3:]), ("Helvetica", "B"), 13, 7)
            pdf.set_text_color(0)
        elif line.startswith("# "):
            _emit(_clean(line[2:]), ("Helvetica", "B"), 17, 8)
            pdf.ln(2)
        elif line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            _emit(_clean(" | ".join(cells)), ("Helvetica", ""), 8.5, 5)
        elif line.startswith("- "):
            _emit("  * " + _clean(line[2:]), ("Helvetica", ""), 9.5, 5)
        elif line.startswith("    - "):
            _emit("      - " + _clean(line[6:]), ("Helvetica", ""), 9, 5)
        else:
            _emit(_clean(line), ("Helvetica", ""), 9.5, 5)
    try:
        pdf.output(str(out_path))
    except Exception:
        return False
    return True


def generate_report(db: Session, investigation: Investigation) -> Report:
    storage.ensure_dirs()
    built = build_report_sections(db, investigation)
    md_text = built["markdown"]

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = f"{investigation.code}-report-{stamp}"
    md_path = storage.REPORT_STORAGE / f"{base}.md"
    html_path = storage.REPORT_STORAGE / f"{base}.html"
    pdf_path = storage.REPORT_STORAGE / f"{base}.pdf"

    md_path.write_text(md_text, encoding="utf-8")
    html_path.write_text(_build_html(f"TRACE-X Report {investigation.code}", md_text, investigation),
                         encoding="utf-8")
    pdf_ok = _build_pdf(md_text, pdf_path)

    formats = ["md", "html"] + (["pdf"] if pdf_ok else [])
    report = Report(
        investigation_id=investigation.id,
        title=f"Investigation Report {investigation.code}",
        formats=formats,
        md_path=str(md_path), html_path=str(html_path),
        pdf_path=str(pdf_path) if pdf_ok else "",
        sha256=hashlib.sha256(html_path.read_bytes()).hexdigest(),
    )
    db.add(report)
    db.flush()

    ledger.add_record(db, action="report_generated", investigation_id=investigation.id,
                      payload={"report_code": report.code, "formats": formats,
                               "html_sha256": report.sha256})
    log_action(db, action="report_generated", investigation_id=investigation.id,
               object_id=report.code, details={"formats": formats})
    db.commit()
    db.refresh(report)
    return report
