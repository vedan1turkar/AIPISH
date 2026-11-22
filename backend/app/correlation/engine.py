"""Correlation engine (P5c): persist observations, score links, detect candidate campaigns.

Determinism: every computation sorts its inputs (analysis created_at + id, entity type + value),
so recomputing on the same observations always yields the same campaigns, members, reasons,
confidence and fingerprints. Recompute is idempotent: unchanged campaigns keep their version.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

import networkx as nx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.models import (
    Analysis,
    Campaign,
    CampaignMember,
    CorrelationState,
    Entity,
    Observation,
    utcnow,
)
from app.correlation import DISCLAIMER
from app.correlation.config import (
    DOMAIN_TYPES,
    LINK_STRENGTH,
    MEDIUM,
    STRONG,
    TIER_RANK,
    WEAK,
    CorrelationConfig,
    get_correlation_config,
)
from app.correlation.extract import extract

logger = logging.getLogger(__name__)

LINK_RULE = ("Analyses are linked only by non-generic shared indicators, and only when they share at least "
             "one strong indicator, or at least two independent indicator types of which one is medium or "
             "strong. A single shared weak indicator never links analyses.")
_DOWN = {STRONG: MEDIUM, MEDIUM: WEAK, WEAK: WEAK}


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ── observations ─────────────────────────────────────────────────────────
def _upsert_entity(db: Session, etype: str, value: str, seen_at: datetime) -> Entity:
    ent = db.query(Entity).filter_by(type=etype, normalized_value=value).one_or_none()
    if ent is None:
        ent = Entity(type=etype, normalized_value=value, first_seen=seen_at, last_seen=seen_at)
        db.add(ent)
        db.flush()
    return ent


def _refresh_entity_times(db: Session, entity_ids: set[str]) -> None:
    for eid in sorted(entity_ids):
        lo, hi = (db.query(func.min(Observation.observed_at), func.max(Observation.observed_at))
                  .filter(Observation.entity_id == eid).one())
        ent = db.get(Entity, eid)
        if ent is not None and lo is not None:
            ent.first_seen, ent.last_seen = _aware(lo), _aware(hi)


def record_observations(db: Session, rec: Analysis, cfg: CorrelationConfig | None = None) -> int:
    """Replace this analysis's observations with a fresh, deterministic extraction."""
    cfg = cfg or get_correlation_config()
    seen_at = _aware(rec.created_at) or utcnow()
    touched = {o.entity_id for o in db.query(Observation).filter_by(analysis_id=rec.id).all()}
    db.query(Observation).filter_by(analysis_id=rec.id).delete(synchronize_session=False)
    n = 0
    for x in extract(rec, cfg):
        ent = _upsert_entity(db, x.type, x.value, seen_at)
        db.add(Observation(entity_id=ent.id, analysis_id=rec.id, role=x.role,
                           source_field=x.source_field, observed_at=seen_at))
        touched.add(ent.id)
        n += 1
    db.flush()
    _refresh_entity_times(db, touched)
    return n


# ── link strength ────────────────────────────────────────────────────────
@dataclass
class EntityStat:
    id: str
    type: str
    value: str
    df: int
    roles: dict[str, set[str]] = field(default_factory=dict)          # analysis → roles
    fields: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # analysis → [(role, field)]


@dataclass(frozen=True)
class Strength:
    tier: str
    weight: float
    generic_reason: str | None = None
    damped: bool = False


def strength(cfg: CorrelationConfig, stat: EntityStat, roles: set[str]) -> Strength:
    options = sorted((LINK_STRENGTH[(stat.type, r)] for r in roles if (stat.type, r) in LINK_STRENGTH),
                     key=lambda t: (TIER_RANK[t[0]], t[1]), reverse=True)
    tier, weight = options[0] if options else (WEAK, 0.0)
    if stat.type in DOMAIN_TYPES and cfg.is_stoplisted(stat.value):
        return Strength(tier, 0.0, "stop-listed generic provider/platform domain")
    if stat.df > cfg.df_max:
        return Strength(tier, 0.0, f"seen in {stat.df} analyses (more than {cfg.df_max}): treated as generic")
    if stat.df > cfg.df_soft:
        return Strength(_DOWN[tier], round(weight / 2, 4), None, True)
    return Strength(tier, weight)


def _pair_roles(stat: EntityStat, a: str, b: str) -> set[str]:
    """Conservative: score the pair by the weaker side's best role."""
    def best(x: str) -> tuple[int, float, str]:
        opts = [(TIER_RANK[LINK_STRENGTH[(stat.type, r)][0]], LINK_STRENGTH[(stat.type, r)][1], r)
                for r in stat.roles.get(x, ()) if (stat.type, r) in LINK_STRENGTH]
        return max(opts) if opts else (0, 0.0, "")
    return {min(best(a), best(b))[2]} - {""}


def evaluate_pair(cfg: CorrelationConfig, stats: list[EntityStat], a: str, b: str) -> dict:
    """Shared indicators between two analyses, link score and whether the link qualifies."""
    indicators, generic = [], []
    for st in sorted(stats, key=lambda s: (s.type, s.value)):
        roles = _pair_roles(st, a, b)
        s = strength(cfg, st, roles)
        item = {"entity_id": st.id, "type": st.type, "value": st.value, "roles": sorted(roles),
                "tier": s.tier, "weight": s.weight, "damped": s.damped, "df": st.df,
                "evidence": [{"analysis_id": x, "role": r, "source_field": f}
                             for x in (a, b) for r, f in sorted(st.fields.get(x, []))]}
        if s.generic_reason or s.weight <= 0:
            generic.append({**item, "generic_reason": s.generic_reason or "no link weight"})
        else:
            indicators.append(item)
    # independence: the same value seen in several roles/types counts once (its strongest form)
    groups: dict[str, dict] = {}
    for ind in indicators:
        cur = groups.get(ind["value"])
        if cur is None or (TIER_RANK[ind["tier"]], ind["weight"]) > (TIER_RANK[cur["tier"]], cur["weight"]):
            groups[ind["value"]] = ind
    kept = sorted(groups.values(), key=lambda i: (-TIER_RANK[i["tier"]], -i["weight"], i["type"], i["value"]))
    has_strong = any(i["tier"] == STRONG for i in kept)
    non_weak = any(i["tier"] in (STRONG, MEDIUM) for i in kept)
    types = {i["type"] for i in kept}
    qualifies = has_strong or (len(types) >= 2 and non_weak)
    prod = 1.0
    for i in kept:
        prod *= (1 - i["weight"])
    score = round(1 - prod, 4) if kept else 0.0
    if not kept:
        why = "only generic indicators are shared" if generic else "no shared indicators"
    elif qualifies:
        why = ("shares a strong indicator" if has_strong
               else f"shares {len(types)} independent indicator types ({', '.join(sorted(types))})")
    elif not non_weak:
        why = "only weak indicators are shared; weak indicators alone never link analyses"
    else:
        why = "only one indicator type is shared and it is not strong"
    return {"indicators": kept, "generic_overlaps": generic, "score": score, "qualifies": qualifies,
            "has_strong": has_strong, "independent_types": sorted(types), "explanation": why,
            "confidence": cfg.confidence_label(score, has_strong) if qualifies else None}


def entity_stats(db: Session, entity_ids: set[str] | None = None) -> dict[str, EntityStat]:
    q = db.query(Observation, Entity).join(Entity, Entity.id == Observation.entity_id)
    if entity_ids is not None:
        if not entity_ids:
            return {}
        q = q.filter(Observation.entity_id.in_(sorted(entity_ids)))
    stats: dict[str, EntityStat] = {}
    for obs, ent in q.all():
        st = stats.setdefault(ent.id, EntityStat(ent.id, ent.type, ent.normalized_value, 0))
        st.roles.setdefault(obs.analysis_id, set()).add(obs.role)
        st.fields.setdefault(obs.analysis_id, []).append((obs.role, obs.source_field))
    # Document frequency counts distinct *messages* (raw SHA-256), so re-uploading the same .eml
    # neither inflates damping nor creates links (see pair_links / duplicate submissions).
    sha = _analysis_sha(db, {a for st in stats.values() for a in st.roles})
    for st in stats.values():
        st.df = len({sha.get(a, a) for a in st.roles})
    return stats


def _analysis_sha(db: Session, ids: set[str]) -> dict[str, str]:
    if not ids:
        return {}
    rows = db.query(Analysis.id, Analysis.raw_sha256).filter(Analysis.id.in_(sorted(ids))).all()
    return {r.id: r.raw_sha256 for r in rows}


def _analysis_keys(db: Session, ids: set[str]) -> dict[str, tuple[str, str]]:
    rows = db.query(Analysis.id, Analysis.created_at).filter(Analysis.id.in_(sorted(ids))).all() if ids else []
    return {r.id: ((_aware(r.created_at) or utcnow()).isoformat(), r.id) for r in rows}


# ── campaigns ────────────────────────────────────────────────────────────
def pair_links(db: Session, cfg: CorrelationConfig) -> dict[tuple[str, str], dict]:
    """Links between analyses of *different* messages. Identical raw messages (same SHA-256,
    i.e. the same .eml submitted again) are duplicates, not independent evidence, and never link."""
    stats = entity_stats(db)
    sha = _analysis_sha(db, {a for st in stats.values() for a in st.roles})
    shared: dict[tuple[str, str], list[EntityStat]] = defaultdict(list)
    for st in stats.values():
        if st.df < 2 or st.df > cfg.df_max:
            continue
        members = sorted(st.roles)
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if sha.get(a) != sha.get(b):
                    shared[(a, b)].append(st)
    return {pair: evaluate_pair(cfg, sts, *pair) for pair, sts in sorted(shared.items())}


def _campaign_reasons(members: list[str], edges: list[tuple[str, str, dict]], distinct_messages: int) -> dict:
    shared: dict[str, dict] = {}
    for a, b, link in edges:
        for ind in link["indicators"]:
            cur = shared.setdefault(ind["entity_id"], {
                "entity_id": ind["entity_id"], "type": ind["type"], "value": ind["value"], "tier": ind["tier"],
                "weight": ind["weight"], "damped": ind["damped"], "analyses": set(), "evidence": set()})
            cur["analyses"].update((a, b))
            cur["evidence"].update((e["analysis_id"], e["role"], e["source_field"]) for e in ind["evidence"])
    indicators = []
    for ind in sorted(shared.values(), key=lambda i: (-TIER_RANK[i["tier"]], -i["weight"], i["type"], i["value"])):
        indicators.append({**ind, "analyses": sorted(ind["analyses"]),
                           "evidence": [{"analysis_id": x, "role": r, "source_field": f}
                                        for x, r, f in sorted(ind["evidence"])]})
    links = [{"a": a, "b": b, "score": link["score"], "explanation": link["explanation"],
              "indicators": [{"type": i["type"], "value": i["value"], "tier": i["tier"], "weight": i["weight"]}
                             for i in link["indicators"]]} for a, b, link in edges]
    lines = [f"{len(members)} analyses ({distinct_messages} distinct messages) share infrastructure through "
             f"{len(links)} qualifying link(s)."]
    for ind in indicators:
        lines.append(f"{ind['type']} {ind['value']} ({ind['tier']}) is shared by {len(ind['analyses'])} "
                     f"member analyses.")
    return {"summary": lines, "shared_indicators": indicators, "links": links, "rule": LINK_RULE,
            "distinct_messages": distinct_messages, "disclaimer": DISCLAIMER}


def _fingerprint(members: list[str], reasons: dict, score: float, label: str) -> str:
    blob = json.dumps({"m": members, "r": reasons, "s": score, "c": label}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def recompute_campaigns(db: Session, cfg: CorrelationConfig | None = None) -> dict:
    """Deterministically (re)derive candidate campaigns from persisted observations.

    Matching to existing campaigns keeps ids stable: a component keeps the id of the existing
    candidate campaign it overlaps most (ties → lowest number). If a new analysis bridges two
    candidates, they merge into that one; the others become ``merged`` (merged_into set).
    Candidates with no qualifying component left become ``dissolved``. Nothing is deleted.
    """
    cfg = cfg or get_correlation_config()
    links = pair_links(db, cfg)
    g = nx.Graph()
    for (a, b), link in links.items():
        if link["qualifies"]:
            g.add_edge(a, b, link=link)
    keys = _analysis_keys(db, set(g.nodes))
    sha_of = _analysis_sha(db, set(g.nodes))

    def k(x: str) -> tuple[str, str]:
        return keys.get(x, ("", x))

    comps = [sorted(c, key=k) for c in nx.connected_components(g) if len(c) >= 2]
    comps.sort(key=lambda c: k(c[0]))

    existing = {c.id: c for c in db.query(Campaign).filter_by(status="candidate").all()}
    existing_members: dict[str, set[str]] = defaultdict(set)
    for m in db.query(CampaignMember).filter(CampaignMember.campaign_id.in_(sorted(existing))).all():
        existing_members[m.campaign_id].add(m.analysis_id)
    next_no = (db.query(func.max(Campaign.number)).scalar() or 0) + 1
    claimed: set[str] = set()
    now = utcnow()
    stats = {"campaigns": 0, "created": 0, "updated": 0, "unchanged": 0, "merged": 0, "dissolved": 0}

    for comp in comps:
        cset = set(comp)
        overlaps = sorted(((len(cset & existing_members[cid]), -existing[cid].number, cid)
                           for cid in existing if cid not in claimed and cset & existing_members[cid]),
                          reverse=True)
        sub = g.subgraph(comp)
        edges = sorted(((a, b, d["link"]) if k(a) <= k(b) else (b, a, d["link"])
                        for a, b, d in sub.edges(data=True)), key=lambda e: (k(e[0]), k(e[1])))
        scores = [e[2]["score"] for e in edges]
        score = round(sum(scores) / len(scores), 4)
        has_strong = any(e[2]["has_strong"] for e in edges)
        label_conf = cfg.confidence_label(score, has_strong)
        reasons = _campaign_reasons(comp, edges, len({sha_of.get(a, a) for a in comp}))
        fp = _fingerprint(comp, reasons, score, label_conf)
        if overlaps:
            camp = existing[overlaps[0][2]]
            claimed.add(camp.id)
            for _n, _neg, other in overlaps[1:]:
                o = existing[other]
                o.status, o.merged_into, o.version, o.updated_at = "merged", camp.id, o.version + 1, now
                claimed.add(other)
                stats["merged"] += 1
            if camp.fingerprint == fp:
                stats["unchanged"] += 1
            else:
                camp.confidence, camp.confidence_score, camp.reasons, camp.fingerprint = label_conf, score, reasons, fp
                camp.version, camp.updated_at = camp.version + 1, now
                # "fetch" also drops the deleted rows from the session's identity map, so re-adding the same
                # (campaign_id, analysis_id) keys below does not raise SQLAlchemy identity-map warnings.
                db.query(CampaignMember).filter_by(campaign_id=camp.id).delete(synchronize_session="fetch")
                for aid in comp:
                    db.add(CampaignMember(campaign_id=camp.id, analysis_id=aid))
                stats["updated"] += 1
        else:
            camp = Campaign(number=next_no, label=f"Candidate campaign C-{next_no:04d}", status="candidate",
                            confidence=label_conf, confidence_score=score, reasons=reasons, fingerprint=fp,
                            version=1, created_at=now, updated_at=now)
            next_no += 1
            db.add(camp)
            db.flush()
            claimed.add(camp.id)
            for aid in comp:
                db.add(CampaignMember(campaign_id=camp.id, analysis_id=aid))
            stats["created"] += 1
        stats["campaigns"] += 1
    for cid, camp in existing.items():
        if cid not in claimed:
            camp.status, camp.version, camp.updated_at = "dissolved", camp.version + 1, now
            stats["dissolved"] += 1
    db.flush()
    return stats


# ── pipeline + rebuild ───────────────────────────────────────────────────
def _set_state(db: Session, analysis_id: str, status: str, error_type: str | None = None) -> None:
    st = db.get(CorrelationState, analysis_id)
    if st is None:
        db.add(CorrelationState(analysis_id=analysis_id, status=status, error_type=error_type, updated_at=utcnow()))
    else:
        st.status, st.error_type, st.updated_at = status, error_type, utcnow()


def correlate_analysis(db: Session, analysis_id: str) -> None:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        return
    record_observations(db, rec)
    recompute_campaigns(db)
    _set_state(db, analysis_id, "ok")


def correlate_safely(db: Session, analysis_id: str) -> str:
    """Pipeline hook. Never raises; the analysis (already committed) is never altered."""
    try:
        correlate_analysis(db, analysis_id)
        db.commit()
        return "ok"
    except Exception as exc:  # noqa: BLE001 — isolation is the point
        db.rollback()
        logger.warning("correlation failed for an analysis (%s); analysis result unaffected", type(exc).__name__)
        try:
            _set_state(db, analysis_id, "error", type(exc).__name__)
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        return "error"


def rebuild_all(db: Session) -> dict:
    """Backfill observations for every analysis and recompute campaigns. Idempotent."""
    ids = [r.id for r in db.query(Analysis.id).order_by(Analysis.created_at, Analysis.id).all()]
    observations = 0
    for aid in ids:
        observations += record_observations(db, db.get(Analysis, aid))
        _set_state(db, aid, "ok")
    live = {r.entity_id for r in db.query(Observation.entity_id).distinct().all()}
    orphans = db.query(Entity).filter(~Entity.id.in_(sorted(live))).delete(synchronize_session=False) if live \
        else db.query(Entity).delete(synchronize_session=False)
    camp = recompute_campaigns(db)
    db.commit()
    return {"analyses": len(ids), "observations": observations,
            "entities": db.query(Entity).count(), "orphan_entities_removed": orphans,
            "candidate_campaigns": db.query(Campaign).filter_by(status="candidate").count(), **{
                f"campaigns_{k}": v for k, v in camp.items()}}
