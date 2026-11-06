"""Email authentication analysis: SPF / DKIM / DMARC.

Statuses (exactly one per protocol):
- ``parsed``          — a header CLAIM exists, not verified locally (untrusted)
- ``verified_pass``   — locally re-verified against DNS
- ``verified_fail``   — locally re-verified and failed (with reason)
- ``unavailable``     — check could not run (DNS timeout / no resolver), reason given
- ``unknown``         — no evidence either way

A claim is NEVER accepted as verification. Header claims and local results are
reported separately and never merged. DNS access is read-only TXT lookups with
hard timeouts; no mail is ever sent.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from app.ingestion.parser import ParsedEmail

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 10.0

# A-R tokens of interest
_AR_TOKEN_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_AR_SMTPMAILFROM_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
_AR_HEADERFROM_RE = re.compile(r"header\.from=([^\s;]+)", re.IGNORECASE)
_DKIM_D_RE = re.compile(r"(?:^|[\s;])d=([a-z0-9.\-]+)", re.IGNORECASE)


@dataclass
class Status:
    """One protocol's result. Exactly one of status values above."""
    protocol: str
    status: str                      # parsed | verified_pass | verified_fail | unavailable | unknown
    claims: list[str] = field(default_factory=list)      # raw A-R claims (untrusted)
    claim_texts: list[str] = field(default_factory=list) # human summary of claims
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthAnalysis:
    spf: Status
    dkim: Status
    dmarc: Status
    alignment: dict[str, str]        # {"spf": aligned|misaligned|unknown, "dkim": ..., }

    def to_dict(self) -> dict:
        def s(d: Status) -> dict:
            return {
                "protocol": d.protocol,
                "status": d.status,
                "claims": d.claims,
                "reason": d.reason,
                "detail": d.detail,
            }
        return {
            "spf": s(self.spf),
            "dkim": s(self.dkim),
            "dmarc": s(self.dmarc),
            "alignment": self.alignment,
            "status_legend": STATUS_LEGEND,
        }


STATUS_LEGEND = {
    "parsed": "untrusted claim from a header — NOT verified by this system",
    "verified_pass": "re-verified locally against DNS and PASSED",
    "verified_fail": "re-verified locally against DNS and FAILED",
    "unavailable": "could not run (DNS/network); neither pass nor fail is asserted",
    "unknown": "no evidence either way",
}


# ── safe DNS query helper ─────────────────────────────────────────────────

def safe_dns_query(
    name: str,
    qtype: str,
    timeout: float = TIMEOUT_SECONDS,
    resolver: Any | None = None,
) -> tuple[list[str] | None, str | None]:
    """TXT/A/MX lookup returning (values, error). Never raises."""
    try:
        import dns.resolver
        rs = resolver or dns.resolver.Resolver()
        rs.lifetime = timeout
        rs.timeout = timeout
        answer = rs.resolve(name, qtype, lifetime=timeout)
        vals = [r.to_text().strip('"') for r in answer]
        return vals, None
    except Exception as exc:  # ANY failure is non-fatal: handled as unavailable
        name_t = type(exc).__name__
        return None, name_t


# ── claim extraction from Authentication-Results ─────────────────────────

def extract_ar_claims(parsed: ParsedEmail) -> dict[str, list[tuple[str, str]]]:
    """Returns {'spf': [('pass','example.com'), ...], 'dkim': [...], 'dmarc': [...]}."""
    out: dict[str, list[tuple[str, str]]] = {"spf": [], "dkim": [], "dmarc": []}
    for raw in parsed.authentication_results:
        for m in _AR_TOKEN_RE.finditer(raw):
            proto, verdict = m.group(1).lower(), m.group(2).lower()
            dom = ""
            if proto == "spf":
                sm = _AR_SMTPMAILFROM_RE.search(raw)
                if sm:
                    dom = sm.group(1)
            elif proto in ("dkim", "dmarc"):
                dm = _AR_HEADERFROM_RE.search(raw)
                if dm:
                    dom = dm.group(1)
            out[proto].append((verdict, dom))
    return out


def _from_domain(parsed: ParsedEmail) -> str | None:
    return parsed.from_.domain.lower() if parsed.from_ else None


def _returnpath_domain(parsed: ParsedEmail) -> str | None:
    rp = parsed.return_path or ""
    m = re.match(r"<?([^@\s>]+)@([^>\s]+)>?", rp.strip())
    return m.group(2).lower() if m else None


# ── SPF ───────────────────────────────────────────────────────────────────

def check_spf_live(
    sender: str,
    ip: str,
    helo: str,
    resolver: Any | None = None,
) -> tuple[str | None, str]:
    """Returns (verdict|None, reason). Verdict in pass/fail/softfail/neutral/none/temperror/permerror."""
    try:
        import spf
        res, _code, _txt = spf.check2(i=ip, s=sender, h=helo, querytime=TIMEOUT_SECONDS)
        return res.lower(), "live check"
    except Exception as exc:
        return None, f"spf_error:{type(exc).__name__}"


# ── DKIM ─────────────────────────────────────────────────────────────────

def check_dkim_live(raw_bytes: bytes, timeout: float = TIMEOUT_SECONDS) -> tuple[str | None, str]:
    """Verify all DKIM signatures on the raw message bytes."""
    try:
        import dkim
        ok = dkim.verify(raw_bytes, timeout=timeout)
        return ("pass" if ok else "fail"), "live check"
    except Exception as exc:
        return None, f"dkim_error:{type(exc).__name__}"


# ── DMARC ────────────────────────────────────────────────────────────────

_DMARC_P_RE = re.compile(r"(?:^|;)\s*p=([a-z]+)", re.IGNORECASE)
_DMARC_SP_RE = re.compile(r"(?:^|;)\s*sp=([a-z]+)", re.IGNORECASE)


def org_domain(domain: str) -> str:
    """Small heuristic org-domain: last two labels (documented MVP simplification)."""
    d = domain.lower().strip()
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def dmarc_record_lookup(
    from_domain: str,
    resolver: Any | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> tuple[str | None, str | None]:
    """Returns (record|None, error|None). Merges org-domain fallback."""
    vals, err = safe_dns_query(f"_dmarc.{from_domain}", "TXT", timeout, resolver)
    if vals:
        for v in vals:
            if "v=DMARC1" in v or "v=DMARC" in v:
                return v, None
    # org-domain fallback
    od = org_domain(from_domain)
    if od != from_domain:
        vals, err2 = safe_dns_query(f"_dmarc.{od}", "TXT", timeout, resolver)
        if vals:
            for v in vals:
                if "v=DMARC1" in v or "v=DMARC" in v:
                    return v, None
    return None, err or err2 or "not_found"


def parse_dmarc_policy(record: str) -> dict[str, Any]:
    p = _DMARC_P_RE.search(record)
    sp = _DMARC_SP_RE.search(record)
    return {
        "policy": p.group(1).lower() if p else None,
        "subdomain_policy": sp.group(1).lower() if sp else None,
        "record": record,
    }


# ── Main entry ───────────────────────────────────────────────────────────

def run_auth_analysis(
    parsed: ParsedEmail,
    raw_bytes: bytes,
    relay_origin_ip: str | None = None,          # from forensics (best-effort)
    live: bool = True,
    resolver: Any | None = None,
    timeout: float = TIMEOUT_SECONDS,
) -> AuthAnalysis:
    """Full SPF/DKIM/DMARC analysis. Claims first, live verification second.

    ``live=False`` short-circuits all network calls (used by tests and when
    DNS is explicitly disabled) — headers claims still get ``parsed`` status.
    """
    claims = extract_ar_claims(parsed)
    from_dom = _from_domain(parsed)
    rp_dom = _returnpath_domain(parsed)

    # ── SPF ──
    if claims["spf"]:
        spf = Status("spf", "parsed", claims=[c[0] for c in claims["spf"]],
                     claim_texts=[f"{v} ({d})" if d else v for v, d in claims["spf"]])
        spf.reason = "header claim only — not verified by this system"
    else:
        spf = Status("spf", "unknown")

    if live and from_dom:
        sender = claims["spf"][0][1] if claims["spf"] and claims["spf"][0][1] else (f"postmaster@{rp_dom}" if rp_dom else f"postmaster@{from_dom}")
        ip = relay_origin_ip or ""
        helo = from_dom
        if ip:
            verdict, reason = check_spf_live(sender, ip, helo)
            if verdict == "pass":
                spf = Status("spf", "verified_pass", spf.claims, spf.claim_texts, reason=None, detail={"ip": ip, "checked_domain": from_dom})
            elif verdict == "fail":
                spf = Status("spf", "verified_fail", spf.claims, spf.claim_texts, reason=reason, detail={"ip": ip, "checked_domain": from_dom})
            elif verdict in ("softfail", "neutral", "none"):
                spf = Status("spf", "unknown", spf.claims, spf.claim_texts, reason=f"live={verdict}", detail={"ip": ip})
            elif verdict in ("temperror", "permerror"):
                spf = Status("spf", "unavailable", spf.claims, spf.claim_texts, reason=reason)
            elif verdict is None:
                spf = Status("spf", "unavailable", spf.claims, spf.claim_texts, reason=reason)
            else:
                spf = Status("spf", "unknown", spf.claims, spf.claim_texts, reason=f"live={verdict}")
        else:
            spf.reason = "no public relay IP available from header forensics — cannot run live SPF"

    # ── DKIM ──
    if claims["dkim"]:
        dkim_st = Status("dkim", "parsed", claims=[c[0] for c in claims["dkim"]],
                          claim_texts=[f"{v} ({d})" if d else v for v, d in claims["dkim"]])
        dkim_st.reason = "header claim only — not verified by this system"
    elif parsed.dkim_signatures:
        dkim_st = Status("dkim", "unknown",
                          claim_texts=[sig[:60] for sig in parsed.dkim_signatures],
                          reason="signature present but no A-R mention; needs live check")
    else:
        dkim_st = Status("dkim", "unknown")

    if live and raw_bytes and parsed.dkim_signatures:
        verdict, reason = check_dkim_live(raw_bytes, timeout)
        if verdict == "pass":
            dkim_st.status = "verified_pass"
            dkim_st.reason = None
        elif verdict == "fail":
            dkim_st.status = "verified_fail"
            dkim_st.reason = reason
        else:
            dkim_st.status = "unavailable"
            dkim_st.reason = reason
        dkim_st.detail["signatures"] = len(parsed.dkim_signatures)

    # ── DMARC ──
    if claims["dmarc"]:
        dmarc = Status("dmarc", "parsed", claims=[c[0] for c in claims["dmarc"]],
                        claim_texts=[f"{v} ({d})" if d else v for v, d in claims["dmarc"]])
        dmarc.reason = "header claim only — not verified by this system"
    else:
        dmarc = Status("dmarc", "unknown")

    dmarc_policy: dict[str, Any] | None = None
    if live and from_dom:
        record, err = dmarc_record_lookup(from_dom, resolver, timeout)
        if record:
            dmarc_policy = parse_dmarc_policy(record)
            dmarc.detail["published_policy"] = dmarc_policy["policy"]
            dmarc.detail["subdomain_policy"] = dmarc_policy["subdomain_policy"]
            dmarc.detail["record_found_at"] = f"_dmarc.{from_dom}"
            # policy exists → claims get context, still not verified alignment below
            if dmarc.status == "unknown":
                dmarc.status = "parsed"
                dmarc.reason = "policy published locally, alignment not yet re-evaluated"
        elif err:
            # distinguish "definitively no record" (not_found) from "DNS broke":
            # a published absent record means nothing locally verifiable either
            # way → stays a claim (parsed), never a verdict.
            if err in ("not_found", "NoAnswer", "NXDOMAIN"):
                if dmarc.status == "unknown":
                    dmarc.reason = "no DMARC record published in DNS (checked, none found)"
                else:
                    dmarc.reason = f"claim only (untrusted); DNS record absent: {err}"
            else:
                dmarc.status = "unavailable"
                dmarc.reason = f"dmarc DNS lookup failed: {err}"

    # ── Alignment (relaxed, org-domain based; documented simplification) ──
    align_spf = "unknown"
    if from_dom and rp_dom:
        align_spf = "aligned" if org_domain(rp_dom) == org_domain(from_dom) else "misaligned"
    align_dkim = "unknown"
    for sig in parsed.dkim_signatures:
        m = _DKIM_D_RE.search(sig)
        if m and from_dom:
            align_dkim = "aligned" if org_domain(m.group(1).lower()) == org_domain(from_dom) else "misaligned"
            break

    return AuthAnalysis(
        spf=spf,
        dkim=dkim_st,
        dmarc=dmarc,
        alignment={"spf": align_spf, "dkim": align_dkim},
    )
