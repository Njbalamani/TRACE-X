"""Blockchain-style tamper-evident integrity ledger.

This is a LOCAL cryptographic hash-chain ledger — deliberately NOT claimed to
be a decentralized public blockchain. The BlockchainAdapter interface allows a
real distributed backend to be plugged in later.
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod

from sqlalchemy import select

from app.models.models import IntegrityRecord

GENESIS_HASH = "0" * 64


def canonical_json(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class BlockchainAdapter(ABC):
    """Interface for the tamper-evident ledger. Swap implementations freely."""

    @abstractmethod
    def add_record(self, db, *, action: str, payload: dict,
                   investigation_id: int | None = None,
                   evidence_id: int | None = None) -> IntegrityRecord: ...

    @abstractmethod
    def verify_chain(self, db, investigation_id: int | None = None) -> dict: ...

    @abstractmethod
    def get_record(self, db, record_id: int) -> IntegrityRecord | None: ...

    @abstractmethod
    def get_records(self, db, investigation_id: int | None = None): ...


class DatabaseBlockchainAdapter(BlockchainAdapter):
    """Hash-chained records stored in the integrity_records table.

    current_hash = SHA256(previous_hash + canonical_json(record_data))
    """

    def _chain_query(self, db, investigation_id: int | None):
        stmt = select(IntegrityRecord).order_by(IntegrityRecord.id.asc())
        if investigation_id is not None:
            stmt = stmt.where(IntegrityRecord.investigation_id == investigation_id)
        return db.scalars(stmt).all()

    def add_record(self, db, *, action: str, payload: dict,
                   investigation_id: int | None = None,
                   evidence_id: int | None = None) -> IntegrityRecord:
        records = self._chain_query(db, investigation_id)
        previous_hash = records[-1].current_hash if records else GENESIS_HASH
        sequence = (records[-1].sequence + 1) if records else 1

        record_data = {
            "sequence": sequence,
            "action": action,
            "investigation_id": investigation_id,
            "evidence_id": evidence_id,
            "payload": payload,
        }
        data_hash = sha256_hex(canonical_json(record_data))
        current_hash = sha256_hex(previous_hash + data_hash)

        record = IntegrityRecord(
            sequence=sequence,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            action=action,
            data_hash=data_hash,
            previous_hash=previous_hash,
            current_hash=current_hash,
            payload=payload,
        )
        db.add(record)
        db.flush()
        return record

    def verify_chain(self, db, investigation_id: int | None = None) -> dict:
        records = self._chain_query(db, investigation_id)
        previous_hash = GENESIS_HASH
        for record in records:
            record_data = {
                "sequence": record.sequence,
                "action": record.action,
                "investigation_id": record.investigation_id,
                "evidence_id": record.evidence_id,
                "payload": record.payload,
            }
            expected_data_hash = sha256_hex(canonical_json(record_data))
            expected_current = sha256_hex(previous_hash + expected_data_hash)
            if record.previous_hash != previous_hash:
                return {"valid": False, "error": (
                    f"Chain break at block {record.code}: stored previous_hash does not match "
                    f"the preceding block's current_hash."), "blocks_checked": len(records)}
            if record.data_hash != expected_data_hash or record.current_hash != expected_current:
                return {"valid": False, "error": (
                    f"Hash mismatch at block {record.code}: ledger record was modified after "
                    "being appended."), "blocks_checked": len(records)}
            previous_hash = record.current_hash
        return {"valid": True, "error": None, "blocks_checked": len(records)}

    def get_record(self, db, record_id: int) -> IntegrityRecord | None:
        return db.get(IntegrityRecord, record_id)

    def get_records(self, db, investigation_id: int | None = None):
        stmt = select(IntegrityRecord).order_by(IntegrityRecord.id.desc())
        if investigation_id is not None:
            stmt = stmt.where(IntegrityRecord.investigation_id == investigation_id)
        return list(db.scalars(stmt))


ledger = DatabaseBlockchainAdapter()
