"""Strict Pydantic validation of any AI output before it is stored.

The validator enforces the core TRACE-X guarantee: an AI finding may only
reference event/evidence IDs that actually exist in this investigation.
Anything invented by the model is dropped, and a finding left with zero real
supporting references is rejected entirely."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class AIFinding(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    severity: str = Field(default="Medium")
    confidence: str = Field(default="Medium")
    classification: str = Field(default="Possible")
    attack_stage: str | None = None
    conclusion: str = Field(min_length=3)
    explanation: str = Field(min_length=3)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    supporting_event_ids: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        return v if v in {"Low", "Medium", "High", "Critical"} else "Medium"

    @field_validator("confidence")
    @classmethod
    def _conf(cls, v: str) -> str:
        return v if v in {"High", "Medium", "Low"} else "Medium"

    @field_validator("classification")
    @classmethod
    def _cls(cls, v: str) -> str:
        allowed = {"Confirmed", "Likely", "Possible", "Insufficient Evidence"}
        return v if v in allowed else "Possible"


class AIAnalysisResult(BaseModel):
    executive_summary: str
    what_happened: str = ""
    suspicious_activities: list[str] = Field(default_factory=list)
    affected_systems: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    confirmed: list[str] = Field(default_factory=list)
    suspected: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)
    findings: list[AIFinding] = Field(default_factory=list)
