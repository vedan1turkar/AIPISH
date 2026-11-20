"""Detection engine — aggregates rule findings into a bounded, explainable score.

Guardrails (per requirements):
1. No single keyword or single failed auth check can make an email malicious:
   - every individual rule is capped at its configured weight (max 35);
   - the phishing band starts at 60, so a lone 20-25-point heuristic hit
     cannot reach it unaided.
2. Missing evidence is `unknown` → never interpreted as safe, never scored.
3. Deterministic: rules run in fixed order; same input → same output.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.detection.config import DetectionConfig, get_config
from app.detection.fs_model import FeatureModel, build_features
from app.detection.rules import ALL_RULES, Finding
from app.ingestion.parser import ParsedEmail

VERDICT_MINIMAL = "minimal"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_PHISHING = "phishing_fraud_likely"


@dataclass
class Unknown:
    field: str
    reason: str


@dataclass
class DetectionResult:
    score: int                      # bounded 0-100
    verdict: str                    # minimal | suspicious | phishing_fraud_likely
    findings: list[Finding] = field(default_factory=list)
    unknowns: list[Unknown] = field(default_factory=list)
    observed_facts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "unknowns": [u.__dict__ for u in self.unknowns],
            "observed_facts": self.observed_facts,
        }


def _verdict(score: int, cfg: DetectionConfig) -> str:
    if score >= cfg.band_phishing_min:
        return VERDICT_PHISHING
    if score >= cfg.band_suspicious_min:
        return VERDICT_SUSPICIOUS
    return VERDICT_MINIMAL


def run_detection(
    parsed: ParsedEmail,
    cfg: DetectionConfig | None = None,
    features: FeatureModel | None = None,
    *,
    forensic_inconsistencies: list[str] | None = None,
    auth_verified_fail_protocols: list[str] | None = None,
    auth_has_conflict: bool = False,
    auth_conflict_detail: str = "",
    auth_alignment: dict[str, str] | None = None,
    enrichment_url_ip_not_global: list[str] | None = None,
    enrichment_domain_no_mx_and_new: list[str] | None = None,
    legacy_domain_compare: bool = False,
) -> DetectionResult:
    """Run every rule in fixed order; aggregate into a bounded 0-100 score.

    Bridged forensics/auth evidence is optional; when absent the bridged
    rules return nothing (no fabricated results from missing evidence).
    """
    cfg = cfg or get_config()
    f = features or build_features(parsed, cfg, legacy_domain_compare=legacy_domain_compare)
    if forensic_inconsistencies is not None:
        f.forensic_inconsistencies = forensic_inconsistencies
    if auth_verified_fail_protocols is not None:
        f.auth_verified_fail_protocols = auth_verified_fail_protocols
    f.auth_has_conflict = auth_has_conflict
    f.auth_auth_conflict_detail = auth_conflict_detail
    f.auth_alignment = auth_alignment or {}
    f.enrichment_url_ip_not_global = enrichment_url_ip_not_global or []
    f.enrichment_domain_no_mx_and_new = enrichment_domain_no_mx_and_new or []

    findings: list[Finding] = []
    for rule in ALL_RULES:                       # fixed order → deterministic
        try:
            res = rule(f, cfg)
        except Exception:                        # a rule crash must not sink the run
            res = None
        if res is not None:
            findings.append(res)

    # highest contribution first, then rule_id → total determinism
    findings.sort(key=lambda r: (-r.contribution, r.rule_id))
    if len(findings) > cfg.max_findings:
        findings = findings[: cfg.max_findings]

    total = sum(min(r.contribution, r.weight) for r in findings)
    total = min(total, cfg.score_cap)

    # ── unknowns: missing evidence — never counted as safe ──
    unknowns: list[Unknown] = []
    if f.from_domain is None:
        unknowns.append(Unknown("from_domain", "no parsable From address — sender trust cannot be assessed"))
    if not f.text and not f.subject:
        unknowns.append(Unknown("content", "no body text and no subject — content rules were skipped, not passed"))
    if not f.urls:
        unknowns.append(Unknown("urls", "no URLs extracted — URL rules were skipped, not passed"))
    if not f.header_counts:
        unknowns.append(Unknown("headers", "message had no parsable headers — header rules were skipped, not passed"))

    observed_facts: list[str] = []
    if f.from_domain:
        observed_facts.append(f"sender domain: {f.from_domain}")
    observed_facts.append(f"URL count: {len(f.urls)}")
    observed_facts.append(f"attachment count: {len(f.attachment_names)}")
    observed_facts.append(f"Received headers: {f.received_count}")

    return DetectionResult(
        score=total,
        verdict=_verdict(total, cfg),
        findings=findings,
        unknowns=unknowns,
        observed_facts=observed_facts,
    )
