"""Server-side analytics aggregates (P5g).

Dialect-safe: only portable ``GROUP BY`` counts in SQL; date bucketing, histograms and JSON-derived
counts are done in Python over a bounded window of the most recent analyses (``MAX_WINDOW``), so the
same code runs on SQLite and PostgreSQL. Outputs are capped. No email bodies, subjects, addresses or
any data beyond sender domains / IP-derived countries and ASNs already shown elsewhere.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.models import (
    Analysis, AssessmentVersion, AttackMapping, Campaign, CampaignMember, ThreatIntelRun, utcnow,
)
from app.geo.service import analysis_geo

MAX_WINDOW = 2000          # most recent analyses considered for JSON-derived aggregates
MAX_DAYS = 365
TOP_N = 10
SCORE_BUCKETS = [(0, 9), (10, 19), (20, 29), (30, 39), (40, 49), (50, 59), (60, 69), (70, 79), (80, 89), (90, 100)]
SIZE_BUCKETS = [("2", 2, 2), ("3", 3, 3), ("4", 4, 4), ("5-9", 5, 9), ("10+", 10, 10**9)]


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _top(counter: Counter, n: int = TOP_N) -> list[tuple[str, int]]:
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def summary(db: Session, days: int = 30) -> dict:
    days = max(1, min(int(days), MAX_DAYS))
    now = utcnow()
    since = (now - timedelta(days=days - 1)).date()

    total = db.query(func.count(Analysis.id)).scalar() or 0
    window = (db.query(Analysis.id, Analysis.created_at, Analysis.detection_score, Analysis.detection_verdict)
              .order_by(Analysis.created_at.desc(), Analysis.id.desc()).limit(MAX_WINDOW).all())
    ids = [w.id for w in window]
    considered = len(ids)

    # rule verdicts: whole table, portable GROUP BY
    verdicts = Counter({(v or "unknown"): n for v, n in
                        db.query(Analysis.detection_verdict, func.count(Analysis.id))
                        .group_by(Analysis.detection_verdict).all()})

    # analyses per UTC day over the last `days` days (Python bucketing; zero-filled)
    per_day = Counter()
    for w in window:
        d = _aware(w.created_at)
        if d is not None and d.date() >= since:
            per_day[d.date().isoformat()] += 1
    series = [{"date": (since + timedelta(days=i)).isoformat(),
               "count": per_day.get((since + timedelta(days=i)).isoformat(), 0)} for i in range(days)]

    # rule-score histogram
    hist = Counter()
    for w in window:
        s = int(w.detection_score or 0)
        for lo, hi in SCORE_BUCKETS:
            if lo <= s <= hi:
                hist[f"{lo}-{hi}"] += 1
                break
    histogram = [{"bucket": f"{lo}-{hi}", "count": hist.get(f"{lo}-{hi}", 0)} for lo, hi in SCORE_BUCKETS]

    # sender domains (whole table); generic/freemail providers labelled, not hidden
    from app.correlation.config import CorrelationConfig
    corr = CorrelationConfig()
    dom_rows = (db.query(Analysis.from_domain, func.count(Analysis.id))
                .filter(Analysis.from_domain.isnot(None), Analysis.from_domain != "")
                .group_by(Analysis.from_domain).order_by(func.count(Analysis.id).desc(), Analysis.from_domain)
                .limit(TOP_N).all())
    domains = [{"domain": d, "count": n, "generic": corr.is_stoplisted(d)} for d, n in dom_rows]

    # latest ML class per analysis in the window
    latest_ml: dict[str, tuple[int, dict | None]] = {}
    for chunk in _chunks(ids):
        for aid, version, ml in (db.query(AssessmentVersion.analysis_id, AssessmentVersion.version,
                                          AssessmentVersion.ml_json)
                                 .filter(AssessmentVersion.analysis_id.in_(chunk)).all()):
            if aid not in latest_ml or version > latest_ml[aid][0]:
                latest_ml[aid] = (version, ml)
    ml_classes = Counter()
    for aid in ids:
        ml = (latest_ml.get(aid) or (0, None))[1] or {}
        ml_classes[ml.get("label") if ml.get("status") == "ok" and ml.get("label") else "not_assessed"] += 1

    # ATT&CK technique frequency from the latest mapping version per analysis
    latest_map: dict[str, tuple[int, dict | None]] = {}
    for chunk in _chunks(ids):
        for aid, version, res in (db.query(AttackMapping.analysis_id, AttackMapping.version,
                                           AttackMapping.results_json)
                                  .filter(AttackMapping.analysis_id.in_(chunk)).all()):
            if aid not in latest_map or version > latest_map[aid][0]:
                latest_map[aid] = (version, res)
    techniques = Counter()
    names: dict[str, str] = {}
    for _, res in latest_map.values():
        for m in (res or {}).get("mappings") or []:
            tid = m.get("technique_id")
            if tid:
                techniques[tid] += 1
                names.setdefault(tid, m.get("name") or tid)
    attack = [{"technique_id": t, "name": names[t], "count": n} for t, n in _top(techniques, 15)]

    # campaigns: counts and member-size distribution (portable GROUP BY)
    camp_status = Counter({s: n for s, n in db.query(Campaign.status, func.count(Campaign.id))
                           .group_by(Campaign.status).all()})
    sizes = [n for _, n in (db.query(CampaignMember.campaign_id, func.count(CampaignMember.analysis_id))
                            .join(Campaign, Campaign.id == CampaignMember.campaign_id)
                            .filter(Campaign.status == "candidate")
                            .group_by(CampaignMember.campaign_id).all())]
    size_dist = [{"bucket": label, "count": sum(1 for s in sizes if lo <= s <= hi)} for label, lo, hi in SIZE_BUCKETS]

    # threat-intel coverage over the window
    runs = Counter()
    consented: set[str] = set()
    simulated_runs = 0
    for chunk in _chunks(ids):
        for aid, granted, res in (db.query(ThreatIntelRun.analysis_id, ThreatIntelRun.consent_granted,
                                           ThreatIntelRun.result_json)
                                  .filter(ThreatIntelRun.analysis_id.in_(chunk)).all()):
            runs["runs"] += 1
            if granted:
                consented.add(aid)
                simulated_runs += 1 if (res or {}).get("simulated") else 0
    intel = {"analyses_with_consented_lookups": len(consented), "analyses_considered": considered,
             "runs_total": runs["runs"], "simulated_runs": simulated_runs}

    # origin countries / ASNs from stored geo data only (bounded: one geo view per analysis in the window)
    countries, asns = Counter(), Counter()
    with_geo = 0
    geo_simulated = False
    for aid in ids:
        rec = db.get(Analysis, aid)
        g = analysis_geo(db, rec)
        if not g["points"]:
            continue
        with_geo += 1
        p = next((p for p in g["points"] if p["role"] == "origin_candidate"), g["points"][0])
        geo_simulated = geo_simulated or bool(p["simulated"])
        if p.get("country"):
            countries[p["country"]] += 1
        if p.get("asn") or p.get("org"):
            asns[p.get("asn") or p.get("org")] += 1
    geo = {"coverage": {"with_geo": with_geo, "analyses_considered": considered},
           "basis": "origin candidate if located, else the first located IP of each analysis",
           "simulated_present": geo_simulated,
           "countries": [{"country": c, "count": n} for c, n in _top(countries)],
           "asns": [{"asn": a, "count": n} for a, n in _top(asns)]}

    return {
        "generated_at": now.isoformat(),
        "window": {"days": days, "since": since.isoformat(), "total_analyses": total,
                   "analyses_considered": considered, "capped": total > considered, "max_window": MAX_WINDOW},
        "verdicts": [{"verdict": v, "count": n} for v, n in _top(verdicts, 20)],
        "ml_classes": [{"label": v, "count": n} for v, n in _top(ml_classes, 20)],
        "per_day": series,
        "score_histogram": histogram,
        "top_sender_domains": domains,
        "geo": geo,
        "attack_techniques": attack,
        "campaigns": {"by_status": dict(camp_status), "candidate_size_distribution": size_dist,
                      "candidates": camp_status.get("candidate", 0)},
        "intel_coverage": intel,
    }


def _chunks(ids: list[str], size: int = 500):
    for i in range(0, len(ids), size):
        yield ids[i:i + size]
