"""Typed response schemas."""
from __future__ import annotations

import pydantic  # noqa: F401
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    version: str
    env: str
    db_connected: bool


class AddressOut(BaseModel):
    display_name: str = ""
    email: str = ""
    domain: str = ""


class UrlOut(BaseModel):
    url: str
    host: str
    scheme: str
    in_html: bool
    in_text: bool


class AttachmentOut(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_inline: bool
    content_id: str | None = None


class AnalysisSummary(BaseModel):
    id: str
    created_at: str
    sha256: str
    size_bytes: int
    subject: str | None
    sender: AddressOut | None
    received_count: int
    url_count: int
    attachment_count: int
    detection_score: int
    detection_verdict: str | None
    has_defects: bool


class FindingOut(BaseModel):
    rule_id: str
    severity: str
    weight: int
    contribution: int
    knowledge: str
    title: str
    evidence: str
    rationale: str


class UnknownOut(BaseModel):
    field: str
    reason: str


class DetectionOut(BaseModel):
    score: int
    verdict: str
    findings: list[FindingOut]
    unknowns: list[UnknownOut]
    observed_facts: list[str]


class InconsistencyOut(BaseModel):
    rule_id: str
    severity: str
    evidence: str
    rationale: str


class ChainHopOut(BaseModel):
    index: int
    from_host: str | None = None
    from_ip: str | None = None
    from_ip_category: str | None = None
    by_host: str | None = None
    protocol: str | None = None
    tls: bool = False
    timestamp: str | None = None
    trusted: bool = False
    confidence: int = 0
    confidence_reasons: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ForensicsOut(BaseModel):
    # P5d.1: 2 = fixed address comparison; None = analysis stored before the fix (not rewritten)
    header_comparison_version: int | None = None
    relay_chain: list[ChainHopOut] = Field(default_factory=list)
    trusted_boundary_index: int | None = None
    candidate_ips: list[str] = Field(default_factory=list)
    earliest_candidate_ip: str | None = None
    verified_originating_ip: str | None = None
    inconsistencies: list[InconsistencyOut] = Field(default_factory=list)
    confidence_rules: list[str] = Field(default_factory=list)
    forgery_note: str = ""
    disclaimer: str = ""


class AuthStatusOut(BaseModel):
    protocol: str
    status: str
    claims: list[str] = Field(default_factory=list)
    reason: str | None = None
    detail: dict = Field(default_factory=dict)


class AuthOut(BaseModel):
    spf: AuthStatusOut
    dkim: AuthStatusOut
    dmarc: AuthStatusOut
    alignment: dict[str, str] = Field(default_factory=dict)
    status_legend: dict[str, str] = Field(default_factory=dict)


class EnrichmentRecordOut(BaseModel):
    provider: str
    ioc: dict
    status: str
    latency_ms: int
    evidence: dict
    provenance: str


class EnrichmentOut(BaseModel):
    results: list[EnrichmentRecordOut] = Field(default_factory=list)
    degraded: list[str] = Field(default_factory=list)


class AnalysisDetail(BaseModel):
    id: str
    created_at: str
    sha256: str
    size_bytes: int
    subject: str | None
    from_: AddressOut | None = Field(alias="from", serialization_alias="from")
    to: list[AddressOut]
    cc: list[AddressOut]
    reply_to: list[AddressOut]
    return_path: str | None
    date: str | None
    message_id: str | None
    received_count: int
    authentication_results: list[str]
    dkim_signature_count: int
    has_html_body: bool
    body_text: str | None
    urls: list[UrlOut]
    attachments: list[AttachmentOut]
    header_counts: dict[str, int]
    detection: DetectionOut
    forensics: ForensicsOut
    authentication: AuthOut
    enrichment: EnrichmentOut
    parse_defects: list[str]

    model_config = {"populate_by_name": True}


class UploadValidationError(BaseModel):
    code: str
    message: str

    model_config = {"json_schema_extra": {"examples": [{"code": "PAYLOAD_TOO_LARGE", "message": "..."}]}}
