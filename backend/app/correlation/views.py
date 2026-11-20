"""Read models for the correlation API, UI and PDF (P5c). Never returns email bodies."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.models import Analysis, Campaign, CampaignMember, CorrelationState, Entity, Observation
from app.correlation import DISCLAIMER
from app.correlation.config import DOMAIN_TYPES, get_correlation_config
from app.correlation.engine import LINK_RULE, _aware, entity_stats, evaluate_pair, strength
from app.correlation.extract import normalize_display_name, normalize_domain, normalize_hash, normalize_public_ip


def analysis_brief(rec: Analysis | None) -> dict | None:
    if rec is None:
        return None
    created = _aware(rec.created_at)
    return {"id": rec.id, "created_at": created.isoformat() if created else None,
            "subject": (rec.subject or "")[:160], "from_domain": rec.from_domain,
            "detection_score": rec.detection_score, "detection_verdict": rec.detection_verdict,
            "sha256": rec.raw_sha256}


def campaign_brief(db: Session, c: Campaign) -> dict:
    n = db.query(CampaignMember).filter_by(campaign_id=c.id).count()
    return {"id": c.id, "label": c.label, "status": c.status, "confidence": c.confidence,
            "confidence_score": c.confidence_score, "member_count": n, "version": c.version,
            "merged_into": c.merged_into,
            "created_at": _aware(c.created_at).isoformat() if c.created_at else None,
            "updated_at": _aware(c.updated_at).isoformat() if c.updated_at else None}


def campaigns_for(db: Session, analysis_id: str) -> list[dict]:
    rows = (db.query(Campaign).join(CampaignMember, CampaignMember.campaign_id == Campaign.id)
            .filter(CampaignMember.analysis_id == analysis_id, Campaign.status == "candidate")
            .order_by(Campaign.number).all())
    return [campaign_brief(db, c) for c in rows]


def correlation_for(db: Session, analysis_id: str) -> dict:
    cfg = get_correlation_config()
    own = db.query(Observation).filter_by(analysis_id=analysis_id).all()
    stats = entity_stats(db, {o.entity_id for o in own})
    own_entities = []
    for st in sorted(stats.values(), key=lambda s: (s.type, s.value)):
        s = strength(cfg, st, st.roles.get(analysis_id, set()))
        own_entities.append({"entity_id": st.id, "type": st.type, "value": st.value, "df": st.df,
                             "roles": sorted(st.roles.get(analysis_id, ())), "tier": s.tier, "weight": s.weight,
                             "generic_reason": s.generic_reason, "damped": s.damped,
                             "evidence": [{"role": r, "source_field": f}
                                          for r, f in sorted(st.fields.get(analysis_id, []))]})
    others: dict[str, list] = {}
    for st in stats.values():
        for other in st.roles:
            if other != analysis_id:
                others.setdefault(other, []).append(st)
    related, generic_only, duplicates = [], [], []
    me = db.get(Analysis, analysis_id)
    for other, sts in others.items():
        other_rec = db.get(Analysis, other)
        brief = analysis_brief(other_rec)
        if brief is None:
            continue
        if me is not None and other_rec.raw_sha256 == me.raw_sha256:
            duplicates.append(brief)          # same .eml submitted again: not independent evidence
            continue
        link = evaluate_pair(cfg, sts, *sorted((analysis_id, other)))
        entry = {"analysis": brief, **{k: link[k] for k in (
            "score", "qualifies", "confidence", "explanation", "indicators", "generic_overlaps",
            "independent_types")}}
        (related if link["indicators"] else generic_only).append(entry)
    related.sort(key=lambda e: (not e["qualifies"], -e["score"], e["analysis"]["created_at"] or "", e["analysis"]["id"]))
    generic_only.sort(key=lambda e: (e["analysis"]["created_at"] or "", e["analysis"]["id"]))
    state = db.get(CorrelationState, analysis_id)
    generic_summary: dict[str, dict] = {}
    for e in generic_only + related:
        for g in e["generic_overlaps"]:
            cur = generic_summary.setdefault(g["entity_id"], {"type": g["type"], "value": g["value"],
                                                              "reason": g["generic_reason"], "analyses": 0})
            cur["analyses"] += 1
    return {
        "analysis_id": analysis_id,
        "status": state.status if state else "not_computed",
        "entities": own_entities,
        "related": related[: cfg.max_related],
        "related_total": len(related),
        "generic_only_overlaps": {"count": len(generic_only), "indicators": sorted(
            generic_summary.values(), key=lambda g: (g["type"], g["value"]))},
        "campaigns": campaigns_for(db, analysis_id),
        "duplicate_submissions": sorted(duplicates, key=lambda b: (b["created_at"] or "", b["id"]))[:20],
        "duplicate_submissions_total": len(duplicates),
        "rule": LINK_RULE,
        "disclaimer": DISCLAIMER,
    }


def campaign_detail(db: Session, c: Campaign) -> dict:
    members = [m.analysis_id for m in db.query(CampaignMember).filter_by(campaign_id=c.id).all()]
    briefs = [b for b in (analysis_brief(db.get(Analysis, a)) for a in members) if b]
    briefs.sort(key=lambda b: (b["created_at"] or "", b["id"]))
    reasons = c.reasons or {}
    nodes, edges = [], []
    for b in briefs:
        nodes.append({"id": f"a:{b['id']}", "kind": "analysis", "label": b["id"][:8],
                      "subject": b["subject"][:80],
                      "analysis_id": b["id"], "verdict": b["detection_verdict"], "score": b["detection_score"]})
    member_set = {b["id"] for b in briefs}
    for ind in reasons.get("shared_indicators", []):
        nid = f"e:{ind['entity_id']}"
        nodes.append({"id": nid, "kind": ind["type"], "label": ind["value"], "tier": ind["tier"],
                      "weight": ind["weight"]})
        per_analysis: dict[str, list[dict]] = {}
        for ev in ind.get("evidence", []):
            if ev["analysis_id"] in member_set:
                per_analysis.setdefault(ev["analysis_id"], []).append(ev)
        for aid, evs in sorted(per_analysis.items()):      # one edge per analysis–entity pair
            edges.append({"id": f"{nid}|{aid}", "source": f"a:{aid}", "target": nid,
                          "role": ", ".join(sorted({e["role"] for e in evs})),
                          "source_field": "; ".join(sorted({e["source_field"] for e in evs})),
                          "tier": ind["tier"]})
    return {**campaign_brief(db, c), "members": briefs, "reasons": reasons,
            "graph": {"nodes": nodes, "edges": edges}, "disclaimer": DISCLAIMER,
            "attack_aggregate": _attack_aggregate(db, [b["id"] for b in briefs])}


def _attack_aggregate(db: Session, member_ids: list[str]) -> dict:
    """P5d: technique counts aggregated from each member's latest ATT&CK mapping (labelled as such)."""
    from app.attack.service import latest
    counts: dict[str, dict] = {}
    mapped = 0
    for aid in member_ids:
        row = latest(db, aid)
        if row is None:
            continue
        mapped += 1
        for m in (row.results_json or {}).get("mappings") or []:
            cur = counts.setdefault(m["technique_id"], {"technique_id": m["technique_id"], "name": m["name"],
                                                        "tactics": m["tactics"], "members": 0})
            cur["members"] += 1
    return {"label": "Aggregated from member analyses' latest ATT&CK mappings; not a campaign-level mapping.",
            "members_with_mapping": mapped, "members_total": len(member_ids),
            "techniques": sorted(counts.values(), key=lambda t: (-t["members"], t["technique_id"]))}


NORMALIZERS = {
    "public_ip": normalize_public_ip, "attachment_hash": normalize_hash,
    "display_name_alias": normalize_display_name,
    **{t: normalize_domain for t in DOMAIN_TYPES},
}


def entity_neighbourhood(db: Session, etype: str, value: str) -> dict | None:
    norm = NORMALIZERS.get(etype)
    if norm is None:
        return None
    nv = norm(value)
    ent = db.query(Entity).filter_by(type=etype, normalized_value=nv).one_or_none() if nv else None
    if ent is None:
        return None
    cfg = get_correlation_config()
    st = entity_stats(db, {ent.id}).get(ent.id)
    s = strength(cfg, st, set().union(*st.roles.values())) if st else None
    analyses = []
    for aid in sorted(st.roles if st else []):
        b = analysis_brief(db.get(Analysis, aid))
        if b:
            analyses.append({"analysis": b, "evidence": [{"role": r, "source_field": f}
                                                         for r, f in sorted(st.fields[aid])],
                             "campaigns": campaigns_for(db, aid)})
    analyses.sort(key=lambda x: (x["analysis"]["created_at"] or "", x["analysis"]["id"]))
    return {"entity": {"id": ent.id, "type": ent.type, "value": ent.normalized_value,
                       "first_seen": _aware(ent.first_seen).isoformat(), "last_seen": _aware(ent.last_seen).isoformat(),
                       "df": st.df if st else 0, "tier": s.tier if s else None, "weight": s.weight if s else 0,
                       "generic_reason": s.generic_reason if s else None},
            "analyses": analyses[:100], "disclaimer": DISCLAIMER}


def case_indicators(db: Session, analysis_ids: list[str]) -> list[dict]:
    if not analysis_ids:
        return []
    cfg = get_correlation_config()
    obs = db.query(Observation).filter(Observation.analysis_id.in_(sorted(analysis_ids))).all()
    stats = entity_stats(db, {o.entity_id for o in obs})
    out = []
    for st in stats.values():
        in_case = sorted(a for a in st.roles if a in set(analysis_ids))
        s = strength(cfg, st, set().union(*(st.roles[a] for a in in_case)))
        out.append({"entity_id": st.id, "type": st.type, "value": st.value, "case_analyses": in_case,
                    "case_count": len(in_case), "df": st.df, "tier": s.tier, "weight": s.weight,
                    "generic_reason": s.generic_reason})
    out.sort(key=lambda e: (-e["case_count"], e["generic_reason"] is not None, e["type"], e["value"]))
    return out
