"""Load the fictional demo investigation CASE-2026-001 through the real API
pipeline (TestClient) so hashes, events, findings and the ledger are genuine.

Usage:  python scripts/seed_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from fastapi.testclient import TestClient  # noqa: E402

from app.database.database import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import Investigation  # noqa: E402
from app.services.storage import ensure_dirs  # noqa: E402

DEMO_EVIDENCE = REPO_ROOT / "demo" / "evidence"
FILES = ["auth.log", "firewall.log", "network.csv", "security_alerts.json", "email.txt"]


def main() -> None:
    init_db()
    ensure_dirs()
    db = SessionLocal()

    existing = db.query(Investigation).filter(Investigation.name == "Demo — Account Compromise (a.carter)").first()
    if existing:
        print(f"Demo investigation already exists as {existing.code} — nothing to seed.")
        return
    db.close()

    client = TestClient(app)

    resp = client.post("/api/investigations", json={
        "name": "Demo — Account Compromise (a.carter)",
        "description": "An employee account (a.carter) may have been compromised. Repeated failed "
                       "logins from an external IP were followed by a successful login, privileged "
                       "command execution, sensitive file access and a large outbound transfer.",
        "investigator": "J. Rivera",
        "incident_type": "Account Compromise",
        "severity": "High",
        "status": "Investigating",
    })
    resp.raise_for_status()
    inv = resp.json()
    case_id = inv["id"]
    print(f"Created investigation {inv['code']} (id={case_id})")

    for filename in FILES:
        path = DEMO_EVIDENCE / filename
        with open(path, "rb") as fh:
            resp = client.post(
                f"/api/investigations/{case_id}/evidence",
                files={"file": (filename, fh)},
                data={"source": "demo dataset", "description": f"Fictional demo evidence: {filename}"},
            )
        resp.raise_for_status()
        ev = resp.json()
        print(f"  uploaded {ev['code']:8} {filename:24} sha256={ev['sha256'][:16]}… "
              f"events={ev['event_count']:3} status={ev['status']}")

    resp = client.post(f"/api/investigations/{case_id}/analyze")
    resp.raise_for_status()
    summary = resp.json()["summary"]
    counts = summary["counts"]
    print(f"Analyzed: engine={summary['engine']}, events={counts['events']}, "
          f"suspicious={counts['suspicious_events']}, findings={counts['findings']}, "
          f"chains={counts['chains']}, stages={counts['stages']}")

    resp = client.post(f"/api/investigations/{case_id}/integrity/verify")
    resp.raise_for_status()
    integrity = resp.json()
    print(f"Integrity: verified={integrity['verified']}/{integrity['total_evidence']}, "
          f"chain_valid={integrity['chain_valid']}, ledger_blocks={integrity['ledger_length']}")

    print("\nDemo investigation ready. Open the dashboard and look for "
          f"{inv['code']}.")


if __name__ == "__main__":
    main()
