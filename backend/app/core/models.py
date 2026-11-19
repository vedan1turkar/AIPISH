"""SQLAlchemy ORM models — extended with investigation cases + audit events.

Evidence policy (documented in README):
- Default: raw .eml bytes are NOT stored. Only SHA-256 + size are kept.
- Optional raw retention: env ``CASE_EVIDENCE_STORE=raw`` stores exact bytes
  in the ``evidence_blob`` column; serving raw bytes requires the request
  header ``X-Evidence-Key`` to equal ``CASE_EVIDENCE_STORE_KEY`` when that
  env is set. Retention is documented; cleanup is a future ops task.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class Analysis(Base):
    """One ingested .eml message and its derived forensic summary."""

    __tablename__ = "analysis"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)

    # evidence integrity
    raw_sha256: Mapped[str] = mapped_column(String(64), index=True)
    raw_size_bytes: Mapped[int] = mapped_column(Integer)

    # identity & meta
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_domain: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_emails: Mapped[list | None] = mapped_column(JSON, nullable=True)
    cc_emails: Mapped[list | None] = mapped_column(JSON, nullable=True)
    reply_to_emails: Mapped[list | None] = mapped_column(JSON, nullable=True)
    return_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_header: Mapped[str | None] = mapped_column(Text, nullable=True)
    message_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    # routing & auth
    received_count: Mapped[int] = mapped_column(Integer, default=0)
    authentication_results: Mapped[list | None] = mapped_column(JSON, nullable=True)
    dkim_signature_count: Mapped[int] = mapped_column(Integer, default=0)

    # content
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_has_html: Mapped[bool] = mapped_column(default=False)

    # IOCs / attachments (metadata only)
    urls: Mapped[list | None] = mapped_column(JSON, nullable=True)
    attachments: Mapped[list | None] = mapped_column(JSON, nullable=True)
    header_counts: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # detection
    detection_score: Mapped[int] = mapped_column(Integer, default=0)
    detection_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    detection_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # forensics + auth + enrichment blocks
    forensics_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    auth_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    enrichment_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # raw evidence (opt-in only; default NULL)
    evidence_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # parse quality
    parse_defects: Mapped[list | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Case(Base):
    """An investigation grouping one or more analyses."""
    __tablename__ = "investigation_case"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    # human-friendly case number like CASE-2026-0007
    case_number: Mapped[str] = mapped_column(String(24), unique=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class CaseAnalysisLink(Base):
    """Case ↔ analysis membership (case id + first-class analysis id)."""
    __tablename__ = "case_analysis_link"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    case_id: Mapped[str] = mapped_column(String(32), index=True)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Application-level audit log — NOT a tamper-resistant record.

    This is append-only at the application layer: the API never exposes
    mutation of audit rows. It is NOT cryptographic chain-of-custody; a DB
    administrator or raw file access can alter it. Stated plainly in README.
    """
    __tablename__ = "audit_event"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    # analysis_created | evidence_accessed | integrity_verified | report_generated
    analysis_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    case_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AnalysisAssessment(Base):
    """Latest ML + SHAP + local-LLM assessment for one analysis (P4).

    Stored once when it is generated so the dashboard and the PDF report show
    the same result (the LLM takes ~1 min and is never re-run for a report).
    Holds derived results only — never raw email bytes.
    """
    __tablename__ = "analysis_assessment"

    analysis_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(24))   # upload | stored_analysis
    ml_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    explanation_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
