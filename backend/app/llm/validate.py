"""Post-validation of model output: grounding, no invented entities, no claims
that unavailable checks passed, no override of system verdicts."""
from __future__ import annotations

import json
import re

from app.llm.evidence import EvidencePack

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b", re.I)
_NEGATION = re.compile(r"\b(not|no|never|unavailable|unverified|cannot|can't|could not|did not|didn't|"
                       r"neither|without|absent|missing|unknown|unable)\b", re.I)
_SAFE_CLAIM = re.compile(r"\b(is|appears|seems|looks|be|considered|deemed)\s+(to\s+be\s+)?(safe|legitimate|benign|"
                         r"harmless|trustworthy|clean|genuine)\b|\bno\s+(threat|risk|indicators?)\b", re.I)
_NON_ENTITY_DOMAINS = {"e.g", "i.e", "etc", "u.s"}
_UNAVAILABLE_CLAIMS = {
    "threat_intelligence": re.compile(r"\b(clean|not\s+(?:listed|flagged|found|malicious)|no\s+(?:hits?|"
                                      r"detections?|reputation\s+issues?))\b.{0,60}\b(threat|reputation|blocklist|"
                                      r"virustotal|abuseipdb|intel)", re.I),
    "geolocation": re.compile(r"\b(located|originat\w*|sent)\s+(in|from)\s+[A-Z][a-z]+", re.I),
}


class InvalidOutput(Exception):
    pass


def parse(content: str) -> dict:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError) as exc:
        raise InvalidOutput("model output is not valid JSON") from exc
    if not isinstance(data, dict):
        raise InvalidOutput("model output is not a JSON object")
    for key, typ in (("summary", str), ("assessment", str), ("findings", list),
                     ("recommended_actions", list), ("limitations", list)):
        if not isinstance(data.get(key), typ):
            raise InvalidOutput(f"field '{key}' missing or not a {typ.__name__}")
    return data


def _unknown_entities(text: str, known: str) -> list[str]:
    known = known.lower()
    out = []
    for m in _IP.findall(text):
        if m not in known:
            out.append(m)
    for m in _DOMAIN.findall(text):
        d = m.lower().rstrip(".")
        if d in _NON_ENTITY_DOMAINS or "." not in d:
            continue
        if d not in known:
            out.append(d)
    return sorted(set(out))


def _clauses(text: str) -> list[str]:
    return [c for c in re.split(r"(?<=[.;!?])\s+|\n", text) if c.strip()]


def _unverified_pass_claims(text: str, pack: EvidencePack) -> list[str]:
    verified_pass = {i["source"].split(":", 1)[1] for i in pack.items
                     if i["source"].startswith("auth:") and "re-verified locally: PASS" in i["statement"]}
    bad = []
    for proto in ("spf", "dkim", "dmarc"):
        if proto in verified_pass:
            continue
        pat = re.compile(rf"\b{proto}\b[^.;]{{0,50}}\b(pass(?:ed|es)?|valid(?:ated)?|verified|succeeded|aligned|ok)\b|"
                         rf"\b(pass(?:ed|es)|validated|verified)\b[^.;]{{0,30}}\b{proto}\b", re.I)
        for clause in _clauses(text):
            if pat.search(clause) and not _NEGATION.search(clause) and "claim" not in clause.lower():
                bad.append(f"{proto.upper()} described as passed/verified but it was not locally verified")
                break
    unavailable = {u["check"] for u in pack.unavailable}
    for check, pat in _UNAVAILABLE_CLAIMS.items():
        if check in unavailable:
            for clause in _clauses(text):
                if pat.search(clause) and not (check == "threat_intelligence" and _NEGATION.search(clause)
                                               and "unavailable" in clause.lower()):
                    bad.append(f"result asserted for unavailable check '{check}'")
                    break
    return bad


def _threat_verdict(pack: EvidencePack) -> bool:
    ml = pack.system_verdicts.get("ml", {}).get("label")
    rules = pack.system_verdicts.get("rules", {}).get("verdict")
    return (ml not in (None, "legitimate")) or (rules not in (None, "minimal"))


def _contradicts_verdict(text: str, pack: EvidencePack) -> bool:
    if not _threat_verdict(pack):
        return False
    for clause in _clauses(text):
        if _SAFE_CLAIM.search(clause) and not re.search(
                r"\b(not|isn't|never|if|whether|determine|verify|confirm|check|unless)\b", clause, re.I):
            return True
    return False


def check_text(text: str, pack: EvidencePack) -> list[str]:
    problems = []
    ents = _unknown_entities(text, pack.known_text())
    if ents:
        problems.append("mentions entities not present in the evidence: " + ", ".join(ents[:5]))
    problems += _unverified_pass_claims(text, pack)
    if _contradicts_verdict(text, pack):
        problems.append("declares the email safe/legitimate, contradicting the system verdicts")
    return problems


def validate(data: dict, pack: EvidencePack) -> dict:
    ids = pack.ids
    accepted, rejected, downgraded = [], [], 0
    for f in data["findings"][:12]:
        if not isinstance(f, dict) or not isinstance(f.get("statement"), str):
            rejected.append({"statement": str(f)[:200], "reason": "malformed finding"})
            continue
        stmt = f["statement"].strip()[:400]
        cited = [e for e in (f.get("evidence_ids") or []) if isinstance(e, str)]
        if not cited:
            rejected.append({"statement": stmt, "reason": "no evidence cited"})
            continue
        unknown = [e for e in cited if e not in ids]
        if unknown:
            rejected.append({"statement": stmt, "reason": f"cites unknown evidence ids {unknown}"})
            continue
        problems = check_text(stmt, pack)
        if problems:
            rejected.append({"statement": stmt, "reason": "; ".join(problems)})
            continue
        cats = sorted({ids[e]["category"] for e in cited})
        basis = f.get("basis") if f.get("basis") in ("verified", "inferred") else "inferred"
        if basis == "verified" and not set(cats) <= {"verified", "provider"}:
            basis, downgraded = "inferred", downgraded + 1
        accepted.append({"statement": stmt, "evidence_ids": cited, "evidence_categories": cats, "basis": basis})

    flags = []
    summary, assessment = data["summary"].strip()[:1200], data["assessment"].strip()[:600]
    s_problems = check_text(summary, pack)
    a_problems = check_text(assessment, pack)
    if s_problems:
        flags.append({"field": "summary", "problems": s_problems, "text": summary[:300]})
        summary = None
    if a_problems:
        flags.append({"field": "assessment", "problems": a_problems, "text": assessment[:300]})
        assessment = None
    actions = []
    for act in data["recommended_actions"][:8]:
        if isinstance(act, str):
            p = check_text(act, pack)
            if p:
                flags.append({"field": "recommended_actions", "problems": p, "text": act.strip()[:200]})
            else:
                actions.append(act.strip()[:300])
    from app.llm.recommend import ground
    recommendations, rejected_recs = ground(actions, pack)
    actions = [r["text"] for r in recommendations if r["origin"] == "model"]
    limitations = [x.strip()[:300] for x in data["limitations"][:8]
                   if isinstance(x, str) and not check_text(x, pack)]
    return {"summary": summary, "assessment": assessment, "findings": accepted,
            "rejected_findings": rejected, "recommended_actions": actions,
            "recommendations": recommendations, "rejected_recommendations": rejected_recs,
            "limitations": limitations,
            "validation": {"summary_accepted": summary is not None, "assessment_accepted": assessment is not None,
                           "findings_accepted": len(accepted), "findings_rejected": len(rejected),
                           "basis_downgraded": downgraded, "flags": flags}}
