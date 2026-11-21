"""Shared pytest fixtures: isolated temp database + fresh storage per test."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "backend"))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh app + isolated sqlite db + isolated evidence storage per test."""
    # Isolated storage BEFORE importing the app modules that bind paths.
    import app.services.storage as storage
    import app.integrity.verify as verify_mod
    evidence_dir = tmp_path / "evidence"
    report_dir = tmp_path / "reports"
    monkeypatch.setattr(storage, "EVIDENCE_STORAGE", evidence_dir)
    monkeypatch.setattr(storage, "REPORT_STORAGE", report_dir)
    monkeypatch.setattr(verify_mod, "EVIDENCE_STORAGE", evidence_dir)
    evidence_dir.mkdir()
    report_dir.mkdir()

    # Isolated database
    import app.database.database as database
    monkeypatch.setenv("TRACE_X_DB_URL", f"sqlite:///{tmp_path / 'test.db'}")
    database.engine.dispose()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}",
                                connect_args={"check_same_thread": False})
    database.engine = test_engine
    database.SessionLocal = sessionmaker(bind=test_engine, autoflush=False, autocommit=False,
                                         expire_on_commit=False)
    database.Base.metadata.create_all(bind=test_engine)

    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def demo_case(client):
    """An investigation with the demo evidence files uploaded."""
    resp = client.post("/api/investigations", json={
        "name": "Test Case — Account Compromise",
        "description": "Automated test case",
        "investigator": "pytest",
        "incident_type": "Account Compromise",
        "severity": "High",
        "status": "Investigating",
    })
    assert resp.status_code == 201, resp.text
    inv = resp.json()

    demo_dir = REPO_ROOT / "demo" / "evidence"
    for name in ["auth.log", "firewall.log", "network.csv", "security_alerts.json", "email.txt"]:
        with open(demo_dir / name, "rb") as fh:
            resp = client.post(f"/api/investigations/{inv['id']}/evidence",
                               files={"file": (name, fh)})
        assert resp.status_code == 201, resp.text
    return client.get(f"/api/investigations/{inv['id']}").json()


@pytest.fixture()
def analyzed(client, demo_case):
    resp = client.post(f"/api/investigations/{demo_case['id']}/analyze")
    assert resp.status_code == 200, resp.text
    return demo_case
