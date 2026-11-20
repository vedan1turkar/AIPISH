"""Threat-intel orchestration for one stored analysis (P5a).

Indicators come from the already-parsed, stored analysis only (relay IPs,
candidate origin IP, URL hosts, sender / Reply-To / Return-Path domains,
attachment SHA-256s). Only the bare indicator is ever passed to a provider:
never subjects, bodies, addresses, headers, URL paths/queries, case ids or
anything else.

Results are informational only: this module never touches the rule score,
ML score, ensemble or verdict, and a provider failure can never fail the
run — each failure becomes its own status on that one result.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import timezone
from typing import Iterator
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.core.models import Analysis, ThreatIntelRun, utcnow
from app.intel.base import (
    DISCLAIMER,
    NOT_APPLICABLE_INDICATOR,
    NOT_ATTEMPTED_CAP_REACHED,
    Provider,
    default_message,
)
from app.intel.config import NOT_CONFIGURED, PROVIDERS, IntelConfig, get_intel_config
from app.intel.providers import PROVIDER_CLASSES
from app.intel.validate import DOMAIN, HASH, IP, reason_text, validate


@dataclass
class Indicator:
    value: str
    indicator_type: str
    origins: list[str] = field(default_factory=list)
    eligible: bool = True
    rejection: str | None = None


def _domain_of(address: str | None) -> str | None:
    if not address or "@" not in address:
        return None
    return address.strip().strip("<>").rpartition("@")[2].strip().strip(">") or None


def extract_indicators(rec: Analysis) -> list[Indicator]:
    """Candidate IOCs from the stored analysis, most investigative value first."""
    seen: dict[tuple[str, str], Indicator] = {}
    rejected: dict[str, Indicator] = {}

    def add(raw: object, origin: str, want: str | None = None) -> None:
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            return
        itype, norm, reason = validate(raw, want)
        if norm is None:
            key = f"{itype}:{str(raw)[:200].lower()}"
            ind = rejected.setdefault(key, Indicator(str(raw)[:200], itype or "unknown",
                                                     eligible=False, rejection=reason))
            if origin not in ind.origins:
                ind.origins.append(origin)
            return
        ind = seen.setdefault((itype, norm), Indicator(norm, itype))
        if origin not in ind.origins:
            ind.origins.append(origin)

    fx = rec.forensics_json or {}
    add(fx.get("verified_originating_ip"), "verified originating IP", IP)
    add(fx.get("earliest_candidate_ip"), "earliest candidate origin IP", IP)
    for ip in fx.get("candidate_ips") or []:
        add(ip, "relay-chain candidate IP", IP)
    for u in rec.urls or []:
        host = (u or {}).get("host") or urlsplit(str((u or {}).get("url") or "")).hostname
        if host:
            host = str(host).strip("[]")
            looks_ip = validate(host, IP)[2] != "invalid_ip"   # valid or rejected-but-IP-shaped
            add(host, "URL host", IP if looks_ip else DOMAIN)
    for a in rec.attachments or []:
        add((a or {}).get("sha256"), "attachment SHA-256", HASH)
    add(rec.from_domain, "sender (From) domain", DOMAIN)
    for e in rec.reply_to_emails or []:
        add(_domain_of(e), "Reply-To domain", DOMAIN)
    add(_domain_of(rec.return_path), "Return-Path domain", DOMAIN)
    for hop in fx.get("relay_chain") or []:
        ip = (hop or {}).get("from_ip")
        if ip:
            add(ip, f"Received hop {hop.get('index')}", IP)
    return list(seen.values()) + list(rejected.values())


# One run per analysis at a time (in-process), like AI assessments.
_running: set[str] = set()
_lock = threading.Lock()


class RunInProgress(Exception):
    pass


@contextmanager
def exclusive(analysis_id: str) -> Iterator[None]:
    with _lock:
        if analysis_id in _running:
            raise RunInProgress(analysis_id)
        _running.add(analysis_id)
    try:
        yield
    finally:
        with _lock:
            _running.discard(analysis_id)


def run_threat_intel(db: Session, rec: Analysis, *, consent: bool, source: str = "on_demand",
                     providers: list[str] | None = None, cfg: IntelConfig | None = None,
                     client=None, sleep=None) -> dict:
    """Run (or refuse, without consent) lookups and append a ThreatIntelRun."""
    cfg = cfg or get_intel_config()
    chosen = [p for p in PROVIDERS if providers is None or p in providers]
    decided_at = utcnow()
    kwargs = {"client": client} | ({"sleep": sleep} if sleep else {})
    instances: dict[str, Provider] = {p: PROVIDER_CLASSES[p](cfg, **kwargs) for p in chosen}

    indicators = extract_indicators(rec)
    eligible = [i for i in indicators if i.eligible]
    memo: dict[tuple[str, str, str], dict] = {}
    out = []
    looked_up = cap_skipped = 0
    for ind in indicators:
        entry = {"indicator": ind.value, "indicator_type": ind.indicator_type, "origins": ind.origins,
                 "eligible": ind.eligible, "state": "looked_up", "rejection_reason": None, "results": []}
        applicable = [p for p in chosen if ind.indicator_type in instances[p].types]
        if not ind.eligible:
            entry["state"] = NOT_APPLICABLE_INDICATOR
            entry["rejection_reason"] = reason_text(ind.rejection)
            entry["message"] = f"Not looked up: {reason_text(ind.rejection)}. Never sent to any provider."
        elif eligible.index(ind) >= cfg.max_iocs_per_analysis:
            entry["state"] = NOT_ATTEMPTED_CAP_REACHED
            entry["message"] = default_message(NOT_ATTEMPTED_CAP_REACHED, "") + \
                f" (cap {cfg.max_iocs_per_analysis})"
            cap_skipped += 1
        else:
            looked_up += 1
            for p in applicable:
                key = (p, ind.indicator_type, ind.value)
                if key not in memo:          # dedup identical lookups within this run
                    memo[key] = instances[p].lookup(ind.value, ind.indicator_type, consent=consent,
                                                    offline=cfg.offline, db=db).to_dict()
                entry["results"].append(memo[key])
        out.append(entry)

    summary: dict[str, dict[str, int]] = {p: {} for p in chosen}
    for entry in out:
        for r in entry["results"]:
            s = summary[r["provider"]]
            s[r["status"]] = s.get(r["status"], 0) + 1

    last = (db.query(ThreatIntelRun).filter_by(analysis_id=rec.id)
            .order_by(ThreatIntelRun.version.desc()).first())
    row = ThreatIntelRun(analysis_id=rec.id, version=(last.version + 1) if last else 1,
                         consent_granted=bool(consent), consent_source=source, providers_requested=chosen,
                         offline=cfg.offline, created_at=decided_at)
    db.add(row)
    db.flush()
    row.result_json = {
        "consent": {"granted": bool(consent), "decided_at": decided_at.isoformat(), "source": source,
                    "providers": chosen},
        "offline": cfg.offline,
        "simulated": cfg.simulated,
        "informational_only": True,
        "ioc_cap": cfg.max_iocs_per_analysis,
        "counts": {"total": len(indicators), "eligible": len(eligible), "looked_up": looked_up,
                   "rejected": len(indicators) - len(eligible), "cap_skipped": cap_skipped,
                   "provider_calls_planned": len(memo)},
        "indicators": out,
        "provider_summary": summary,
        "not_configured": NOT_CONFIGURED,
        "disclaimer": DISCLAIMER,
    }
    from app.cases.service import record_audit
    record_audit(db, "threat_intel_lookup", analysis_id=rec.id, detail={
        "run_id": row.id, "version": row.version, "consent_granted": bool(consent),
        "consent_source": source, "decided_at": decided_at.isoformat(), "providers": chosen,
        "offline": cfg.offline, "simulated": cfg.simulated, "counts": row.result_json["counts"]})
    db.commit()
    return run_dict(row)


def run_dict(row: ThreatIntelRun) -> dict:
    created = row.created_at
    if created is not None and created.tzinfo is None:      # SQLite drops tzinfo; stored values are UTC
        created = created.replace(tzinfo=timezone.utc)
    return {"run_id": row.id, "analysis_id": row.analysis_id, "version": row.version,
            "created_at": created.isoformat() if created else None, **(row.result_json or {})}


def latest_run(db: Session, analysis_id: str) -> ThreatIntelRun | None:
    return (db.query(ThreatIntelRun).filter_by(analysis_id=analysis_id)
            .order_by(ThreatIntelRun.version.desc()).first())


def get_run(db: Session, analysis_id: str, run_id: str) -> ThreatIntelRun | None:
    row = db.get(ThreatIntelRun, run_id)
    return row if row is not None and row.analysis_id == analysis_id else None
