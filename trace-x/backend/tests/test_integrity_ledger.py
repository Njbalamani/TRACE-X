"""Integrity ledger hash-chain tests (tamper evidence)."""
from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.integrity.ledger import GENESIS_HASH, DatabaseBlockchainAdapter, ledger


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ledger.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


def test_chain_builds_and_verifies(db):
    r1 = ledger.add_record(db, action="evidence_uploaded", investigation_id=1,
                           payload={"sha256": "a" * 64})
    r2 = ledger.add_record(db, action="analysis_completed", investigation_id=1,
                           payload={"findings": 3})
    r3 = ledger.add_record(db, action="integrity_verified", investigation_id=1, payload={})
    db.commit()

    assert r1.previous_hash == GENESIS_HASH
    assert r2.previous_hash == r1.current_hash
    assert r3.previous_hash == r2.current_hash
    assert r1.current_hash != r2.current_hash != r3.current_hash

    result = ledger.verify_chain(db, investigation_id=1)
    assert result["valid"] is True
    assert result["blocks_checked"] == 3


def test_chain_detects_record_tampering(db):
    ledger.add_record(db, action="evidence_uploaded", investigation_id=1, payload={"n": 1})
    ledger.add_record(db, action="analysis_completed", investigation_id=1, payload={"n": 2})
    ledger.add_record(db, action="report_generated", investigation_id=1, payload={"n": 3})
    db.commit()

    # Tamper with an EARLY record's payload, like a hidden evidence modification would
    from app.models.models import IntegrityRecord
    victim = db.scalars(select(IntegrityRecord).order_by(IntegrityRecord.id).limit(1)).first()
    victim.payload = {"n": 999}  # history rewrite
    db.commit()

    result = ledger.verify_chain(db, investigation_id=1)
    assert result["valid"] is False
    assert "modified" in result["error"].lower() or "mismatch" in result["error"].lower()


def test_chain_detects_sequence_break(db):
    from app.models.models import IntegrityRecord
    ledger.add_record(db, action="a", investigation_id=1, payload={})
    ledger.add_record(db, action="b", investigation_id=1, payload={})
    db.commit()
    rows = list(db.scalars(select(IntegrityRecord).order_by(IntegrityRecord.id)))
    # simulate deletion of a middle block by breaking the link
    rows[-1].previous_hash = GENESIS_HASH
    db.commit()
    result = ledger.verify_chain(db, investigation_id=1)
    assert result["valid"] is False


def test_chain_scoped_per_investigation(db):
    ledger.add_record(db, action="a", investigation_id=1, payload={})
    ledger.add_record(db, action="b", investigation_id=2, payload={})
    db.commit()
    assert ledger.verify_chain(db, investigation_id=1)["valid"]
    assert ledger.verify_chain(db, investigation_id=2)["valid"]


def test_adapter_interface():
    assert isinstance(ledger, DatabaseBlockchainAdapter)
    assert isinstance(ledger, __import__("app.integrity.ledger", fromlist=["BlockchainAdapter"]).BlockchainAdapter)
