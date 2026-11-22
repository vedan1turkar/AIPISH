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

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, LargeBinary, String, Text, UniqueConstraint
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
    # P5e retention: None | "evidence_purged" | "redacted"
    retention_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    """Application audit log, tamper-EVIDENT since P5e (HMAC hash chain), not tamper-PROOF.

    Each row carries ``seq`` / ``prev_hash`` / ``event_hash`` (HMAC-SHA256 with AIPISH_AUDIT_KEY over a
    canonical serialisation + the previous hash), so changes, deletions, re-orderings and insertions are
    detected by ``app.audit.chain.verify``. Database triggers reject UPDATE/DELETE; the API has no
    mutation path. A database superuser can still bypass triggers, and an attacker holding both database
    write access and the audit key could forge a consistent chain: external checkpoints reduce that risk.
    Pre-chain rows were chained once at migration ("chain_genesis") without changing their content.
    """
    __tablename__ = "audit_event"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    event_type: Mapped[str] = mapped_column(String(40), index=True)
    # analysis_created | evidence_accessed | integrity_verified | report_generated
    analysis_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    case_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    # P5b: authenticated user who caused the event (None for anonymous/failed logins and pre-P5b rows)
    actor_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    # P5e: structured fields + hash chain (nullable only for databases mid-migration)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuditChainHead(Base):
    """Single row (id=1): the last chained seq and hash. Its row lock serialises appends (P5e)."""
    __tablename__ = "audit_chain_head"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    last_hash: Mapped[str] = mapped_column(String(64))


class LegalHold(Base):
    """Legal hold on an analysis or a case (P5e): held items are skipped by retention and cannot be erased."""
    __tablename__ = "legal_hold"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    target_type: Mapped[str] = mapped_column(String(16), index=True)        # analysis | case
    target_id: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    cleared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cleared_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    clear_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class AnalysisAssessment(Base):
    """LEGACY (P4): one latest assessment per analysis, overwritten on regeneration.

    Kept read-only so existing databases are never altered destructively; its
    rows are copied once into ``AssessmentVersion`` by ``migrate_assessments``.
    New assessments are written only to ``AssessmentVersion``.
    """
    __tablename__ = "analysis_assessment"

    analysis_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(24))   # upload | stored_analysis
    ml_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    explanation_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssessmentVersion(Base):
    """One generated ML + SHAP + local-LLM assessment (P4.1). Append-only in the API.

    Regeneration inserts a new row (version n+1); earlier rows are never
    updated, so a report produced from an assessment id stays reproducible.
    This is application-level history, not tamper-proof storage. Holds derived
    results only — never raw email bytes.
    """
    __tablename__ = "assessment_version"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(24))   # upload | stored_analysis | migrated_p4
    ml_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    explanation_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


def migrate_assessments(session) -> int:
    """Copy P4 single-row assessments into assessment_version once (idempotent).

    The legacy row keeps its original timestamp and becomes version 1 of its
    analysis (id ``p4-<analysis_id>``). The legacy table is left untouched.
    Returns the number of rows copied.
    """
    copied = 0
    for old in session.query(AnalysisAssessment).all():
        legacy_id = f"p4-{old.analysis_id}"[:32]
        if session.get(AssessmentVersion, legacy_id) is not None:
            continue
        existing = session.query(AssessmentVersion).filter_by(analysis_id=old.analysis_id).count()
        session.add(AssessmentVersion(
            id=legacy_id, analysis_id=old.analysis_id, version=existing + 1,
            source=old.source or "migrated_p4", ml_json=old.ml_json,
            explanation_json=old.explanation_json, summary_json=old.summary_json,
            created_at=old.created_at or utcnow()))
        copied += 1
    if copied:
        session.commit()
    return copied


class IntelCacheEntry(Base):
    """Threat-intel provider cache (P5a). One row per provider + indicator type + indicator.

    Holds only normalised, sanitised provider fields — never credentials, request
    URLs or any email content. Expired rows are kept so a later provider failure
    can fall back to them, always labelled stale.
    """
    __tablename__ = "intel_cache"

    key: Mapped[str] = mapped_column(String(400), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16))
    indicator: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(40))
    data_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ThreatIntelRun(Base):
    """One threat-intel lookup run for an analysis (P5a). Append-only in the API.

    Each run records the consent decision (granted or refused), its timestamp,
    the providers requested and every per-indicator result with provenance.
    Re-running inserts version n+1; earlier runs are never updated, so a PDF
    pinned to a run id stays reproducible. Informational only: never feeds the
    rule score, ML score or verdict.
    """
    __tablename__ = "threat_intel_run"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer)
    consent_granted: Mapped[bool] = mapped_column(default=False)
    consent_source: Mapped[str] = mapped_column(String(24))      # upload | on_demand
    providers_requested: Mapped[list | None] = mapped_column(JSON, nullable=True)
    offline: Mapped[bool] = mapped_column(default=False)
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class User(Base):
    """Local application user (P5b). Passwords are stored only as scrypt hashes.

    ``username`` is stored lower-cased, so uniqueness is case-insensitive.
    ``token_version`` is embedded in every JWT; bumping it (password change,
    role change, disable, logout) invalidates all of that user's tokens.
    """
    __tablename__ = "app_user"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16))                 # viewer | analyst | admin
    is_active: Mapped[bool] = mapped_column(default=True)
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    must_change_password: Mapped[bool] = mapped_column(default=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


def migrate_audit_actor(engine) -> bool:
    """Additive, idempotent: add ``audit_event.actor_user_id`` to pre-P5b SQLite databases."""
    from sqlalchemy import inspect, text
    cols = {c["name"] for c in inspect(engine).get_columns("audit_event")}
    if "actor_user_id" in cols:
        return False
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_event ADD COLUMN actor_user_id VARCHAR(32)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_audit_event_actor_user_id "
                          "ON audit_event (actor_user_id)"))
    return True


# ── P5c: cross-case correlation ──────────────────────────────────────────
class Entity(Base):
    """A normalised indicator observed in one or more analyses (P5c).

    Private/reserved IPs and trusted internal relays are never entities.
    Stop-listed (generic) values may exist as entities for search, but never link analyses.
    """
    __tablename__ = "corr_entity"
    __table_args__ = (UniqueConstraint("type", "normalized_value", name="uq_corr_entity_type_value"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    type: Mapped[str] = mapped_column(String(32), index=True)
    normalized_value: Mapped[str] = mapped_column(String(300), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Observation(Base):
    """Entity seen in one analysis, in one role, at one source field (the evidence reference)."""
    __tablename__ = "corr_observation"
    __table_args__ = (UniqueConstraint("entity_id", "analysis_id", "role", "source_field",
                                       name="uq_corr_observation"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    entity_id: Mapped[str] = mapped_column(String(32), index=True)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    role: Mapped[str] = mapped_column(String(40))
    source_field: Mapped[str] = mapped_column(String(120))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Campaign(Base):
    """Candidate campaign: analyses linked by shared, non-generic infrastructure (P5c).

    Never an attribution to a person. ``status``: candidate | merged | dissolved.
    Rows are never deleted, so references (PDFs, audit) stay resolvable.
    """
    __tablename__ = "corr_campaign"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    number: Mapped[int] = mapped_column(Integer, unique=True)
    label: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="candidate", index=True)
    confidence: Mapped[str] = mapped_column(String(8))
    confidence_score: Mapped[float] = mapped_column(Float)
    reasons: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    merged_into: Mapped[str | None] = mapped_column(String(32), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CampaignMember(Base):
    __tablename__ = "corr_campaign_member"

    campaign_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    analysis_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)


class CorrelationState(Base):
    """Per-analysis correlation status: correlation failures never affect the analysis itself."""
    __tablename__ = "corr_state"

    analysis_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16))          # ok | error
    error_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


def migrate_correlation_indexes(engine) -> None:
    """Additive, idempotent search indexes on the existing analysis table (P5c)."""
    from sqlalchemy import text
    with engine.begin() as conn:
        for name, col in (("ix_analysis_from_domain", "from_domain"),
                          ("ix_analysis_detection_verdict", "detection_verdict"),
                          ("ix_analysis_created_at", "created_at")):
            conn.execute(text(f"CREATE INDEX IF NOT EXISTS {name} ON analysis ({col})"))


def run_additive_migrations(engine) -> list[str]:
    """Every schema step, shared by app startup and the CLI (P5b lesson).

    P5i: delegates to the versioned, dialect-safe runner in ``app.core.migrations``.
    """
    from app.core.migrations import upgrade
    return upgrade(engine)


class SchemaMigration(Base):
    """One applied schema migration step (P5i). See ``app.core.migrations``."""
    __tablename__ = "schema_migrations"

    version: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    name: Mapped[str] = mapped_column(String(80))
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AttackMapping(Base):
    """MITRE ATT&CK mapping + source-type hypotheses for one analysis (P5d). Append-only versions.

    Informational only: never feeds the rule score, ML, verdict or the LLM. A new version is
    appended only when the inputs or results change (fingerprint), so backfill is idempotent.
    """
    __tablename__ = "attack_mapping"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(24))              # auto | recompute | backfill | intel_run
    mapping_engine_version: Mapped[str] = mapped_column(String(32))
    catalog_version: Mapped[str] = mapped_column(String(64))
    intel_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ml_assessment_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    results_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class GeoObservation(Base):
    """A stored infrastructure-location observation for one IP of one analysis (P5g).

    Written only by explicit, offline seeding (today: ``init-demo`` / ``seed-demo-campaign`` with
    ``source="simulated-demo"`` and ``simulated=True``). Real locations come from the stored enrichment and
    consented threat-intel results; nothing here performs lookups. Always shown with its SIMULATED label.
    """
    __tablename__ = "geo_observation"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    city: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(16), nullable=True)
    org: Mapped[str | None] = mapped_column(String(120), nullable=True)
    anonymity_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(32))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MlClassification(Base):
    """Upload-time ML classification (P5h): the cheap ensemble only — no SHAP, no LLM. Append-only.

    Stored because hash_only analyses cannot be re-classified later. Every outcome is kept, including
    unavailable / error / not_applicable, so a missing result is never read as "legitimate".
    Holds probabilities and metadata only, never message content.
    """
    __tablename__ = "ml_classification"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(24))              # upload
    status: Mapped[str] = mapped_column(String(24))
    model_version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class RiskAssessment(Base):
    """Explainable combined risk assessment (P5h). Append-only versions; a new version is added only when
    the result changes (fingerprint). An ADDITIONAL result: never alters the rule score, verdict or ML output.
    A risk index, not a probability."""
    __tablename__ = "risk_assessment"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    analysis_id: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(24))              # upload | intel_run | assessment_run | recompute | backfill
    engine_version: Mapped[str] = mapped_column(String(32))
    config_version: Mapped[str] = mapped_column(String(32))
    combined_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    level: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(8))
    fingerprint: Mapped[str] = mapped_column(String(64))
    results_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Alert(Base):
    """Risk-based alert (P5f), raised when an analysis is processed (upload, recompute, campaign update).

    Holds system-written titles and identifiers/labels only — never message subject, body, recipients,
    sender addresses or display names. ``dedupe_key`` identifies the subject of the alert (type + message
    SHA-256, or type + campaign id); ``active_key`` equals ``dedupe_key`` while the alert is new or
    acknowledged and is NULL once resolved, so the unique index allows one active alert per key on both
    SQLite and PostgreSQL.
    """
    __tablename__ = "alert"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    dedupe_key: Mapped[str] = mapped_column(String(160), index=True)
    active_key: Mapped[str | None] = mapped_column(String(160), nullable=True, unique=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)          # new | acknowledged | resolved
    analysis_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    campaign_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    risk_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    level_at_resolution: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    acknowledged_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    delivery_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)      # optimistic concurrency for transitions


class AlertEvent(Base):
    """Append-only alert history (P5f). ``analysis_id`` is copied from the alert so retention delete mode
    removes the history together with the alert (generic dependents)."""
    __tablename__ = "alert_event"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    alert_id: Mapped[str] = mapped_column(String(32), index=True)
    analysis_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(32))
    actor_user_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    detail_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
