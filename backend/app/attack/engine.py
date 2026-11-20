"""Deterministic MITRE ATT&CK mapping and source-type hypotheses (P5d).

No LLM, no randomness: the same stored analysis (+ the same intel run and ML output) always
produces byte-identical results. Every mapping and hypothesis cites evidence ids (A1, A2, ...)
from an evidence list built here; each evidence item carries the exact ``source_field`` of the
stored analysis / intel run / assessment it came from, so it can be resolved and navigated.

basis
  observed  the behaviour is directly present in the artefacts (attachment, link, verified
            authentication failure). ML output can never create an "observed" mapping.
  inferred  a reasoned interpretation of content / header / provider signals.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.attack.catalog import get_catalog

ENGINE_VERSION = "attack-engine-1.1"

URL_RISK_RULES = ("ip_literal_url", "url_obfuscation", "suspicious_url_structure", "ip_url_risky_lookup")
CONTENT_RULES = ("payment_diversion", "credential_request")
DATA_STATUSES = {"malicious_or_flagged", "reported_clean_no_flags", "record_found", "no_record"}
ORIGIN_MARKERS = ("originating IP", "candidate origin IP", "relay-chain candidate IP")

DISCLAIMER = ("ATT&CK mappings and source-type hypotheses describe techniques and infrastructure suggested by "
              "the evidence. They never identify a person, group or physical location. ATT&CK describes "
              "intrusion tradecraft and only approximates business-email-compromise and financial fraud.")
EMPTY_TEXT = "No ATT&CK techniques could be mapped from the available evidence."


@dataclass
class Evidence:
    key: str
    kind: str              # rule_finding | authentication | header_inconsistency | url | attachment | reply_to | intel | ml
    category: str          # verified | heuristic | claimed | provider | model
    source_field: str
    statement: str
    tab: str               # dashboard tab that shows it: findings | auth | headers | intel | threat | ai


@dataclass
class Builder:
    items: dict[str, Evidence] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)

    def add(self, ev: Evidence) -> str:
        if ev.key not in self.items:
            self.items[ev.key] = ev
            self.order.append(ev.key)
        return ev.key


# ── inputs ───────────────────────────────────────────────────────────────
@dataclass
class Inputs:
    analysis: dict
    intel_run: dict | None = None
    ml: dict | None = None                 # assessment ml_json (status ok) + assessment_id


def _findings(a: dict) -> dict[str, tuple[int, dict]]:
    out: dict[str, tuple[int, dict]] = {}
    for i, f in enumerate(((a.get("detection_json") or {}).get("findings")) or []):
        out.setdefault(f.get("rule_id"), (i, f))
    return out


def _inconsistencies(a: dict) -> dict[str, tuple[int, dict]]:
    out: dict[str, tuple[int, dict]] = {}
    for i, x in enumerate(((a.get("forensics_json") or {}).get("inconsistencies")) or []):
        out.setdefault(x.get("rule_id"), (i, x))
    return out


def _clip(s: object, n: int = 180) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


class Ctx:
    """Evidence lookups shared by mapping rules and hypotheses."""

    def __init__(self, inp: Inputs):
        self.inp, self.a = inp, inp.analysis
        self.b = Builder()
        self.f = _findings(self.a)
        self.inc = _inconsistencies(self.a)
        self.suppressed: list[str] = []
        # Guard against the pre-P5d.1 forensics artefact (trailing '>' made identical domains look
        # different). Fixed upstream in P5d.1 for new analyses; kept because analyses stored before
        # the fix are not rewritten. Harmless on fixed data (the inconsistency is simply absent).
        if "returnpath_mismatch" in self.inc:
            rp = str(self.a.get("return_path") or "").strip().strip("<>").rpartition("@")[2].strip("<> .").lower()
            fd = str(self.a.get("from_domain") or "").strip(". ").lower()
            if rp and fd and rp == fd:
                del self.inc["returnpath_mismatch"]
                self.suppressed.append("returnpath_mismatch (From and Return-Path domains match after normalisation)")
        self.auth = self.a.get("auth_json") or {}
        self.urls = self.a.get("urls") or []
        self.atts = self.a.get("attachments") or []

    # evidence constructors ------------------------------------------------
    def finding(self, rule_id: str) -> str | None:
        if rule_id not in self.f:
            return None
        i, f = self.f[rule_id]
        cat = "verified" if f.get("knowledge") == "fact" else "heuristic"
        return self.b.add(Evidence(f"rule:{rule_id}", "rule_finding", cat, f"detection.findings[{i}]",
                                   _clip(f"Rule {rule_id} ({f.get('severity')}): {f.get('title')} — {f.get('evidence')}"),
                                   "findings"))

    def inconsistency(self, rule_id: str) -> str | None:
        if rule_id not in self.inc:
            return None
        i, x = self.inc[rule_id]
        return self.b.add(Evidence(f"inc:{rule_id}", "header_inconsistency", "verified",
                                   f"forensics.inconsistencies[{i}]",
                                   _clip(f"Header inconsistency {rule_id} ({x.get('severity')}): {x.get('evidence')}"),
                                   "headers"))

    def auth_status(self, proto: str) -> str | None:
        st = self.auth.get(proto) or {}
        if not st.get("status") or st.get("status") == "unknown":
            return None
        cat = "verified" if str(st["status"]).startswith("verified_") else "claimed"
        claims = ", ".join(st.get("claims") or []) or "none"
        return self.b.add(Evidence(f"auth:{proto}", "authentication", cat, f"auth.{proto}",
                                   _clip(f"{proto.upper()} status {st['status']} (header claims: {claims})"
                                         + (f"; {st['reason']}" if st.get("reason") else "")), "auth"))

    def alignment(self, proto: str) -> str | None:
        val = (self.auth.get("alignment") or {}).get(proto)
        if not val or val == "unknown":
            return None
        return self.b.add(Evidence(f"align:{proto}", "authentication", "verified", f"auth.alignment.{proto}",
                                   f"{proto.upper()} alignment with the From domain: {val}", "auth"))

    def url(self, i: int) -> str:
        u = self.urls[i] or {}
        return self.b.add(Evidence(f"url:{i}", "url", "verified", f"urls[{i}]",
                                   _clip(f"URL in message body: host {u.get('host')} ({u.get('scheme')})"), "intel"))

    def attachment(self, i: int) -> str:
        x = self.atts[i] or {}
        return self.b.add(Evidence(f"att:{i}", "attachment", "verified", f"attachments[{i}]",
                                   _clip(f"Attachment {x.get('filename')} ({x.get('content_type')}), "
                                         f"sha256 {str(x.get('sha256') or '')[:16]}…"), "overview"))

    def ml_label(self) -> str | None:
        ml = self.inp.ml or {}
        if ml.get("status") != "ok" or not ml.get("label"):
            return None
        return self.b.add(Evidence("ml:label", "ml", "model", f"assessment[{ml.get('assessment_id')}].ml",
                                   f"ML classifier label {ml['label']} (confidence {ml.get('confidence')}); "
                                   "statistical support only", "ai"))

    # intel ---------------------------------------------------------------
    def intel_results(self) -> list[tuple[str, dict, dict, int, int]]:
        """(evidence-ready) list of (indicator_type, indicator, result, i, j)."""
        run = self.inp.intel_run or {}
        out = []
        for i, ind in enumerate(run.get("indicators") or []):
            for j, r in enumerate(ind.get("results") or []):
                out.append((ind.get("indicator_type"), ind, r, i, j))
        return out

    def intel_ev(self, ind: dict, r: dict, i: int, j: int, note: str) -> str:
        run = self.inp.intel_run or {}
        sim = " [SIMULATED provider data]" if run.get("simulated") else ""
        stale = " (stale cache)" if r.get("cache_state") == "stale" else ""
        return self.b.add(Evidence(
            f"intel:{i}:{j}", "intel", "provider",
            f"threat_intel[{run.get('run_id')}].indicators[{i}].results[{j}]",
            _clip(f"{r.get('provider_label') or r.get('provider')}: {ind.get('indicator')} "
                  f"({ind.get('indicator_type')}) — {note}{stale}{sim}", 220), "threat"))


def is_origin(ind: dict) -> bool:
    return any(any(m in o for m in ORIGIN_MARKERS) for o in (ind.get("origins") or []))


# ── mapping rules ────────────────────────────────────────────────────────
@dataclass
class Mapping:
    technique_id: str
    basis: str
    confidence: str
    evidence: list[str]
    rationale: str
    rule_id: str
    limitations: str | None = None
    support: list[str] = field(default_factory=list)       # supporting-only refs (e.g. ML)


def _rules(c: Ctx) -> list[Mapping]:
    out: list[Mapping] = []
    has = lambda r: r in c.f  # noqa: E731
    url_idx = list(range(len(c.urls)))
    url_rules = [r for r in URL_RISK_RULES if has(r)]
    lookalike = has("lookalike_domain")
    ml = c.ml_label()
    ml_support = [ml] if ml and (c.inp.ml or {}).get("label") in ("phishing", "fraud", "impersonated") else []

    # intel flags (consented, provider data)
    flagged_urls, flagged_hashes, tor_origin = [], [], []
    for itype, ind, r, i, j in c.intel_results():
        if r.get("status") != "malicious_or_flagged":
            continue
        origins = " ".join(ind.get("origins") or [])
        if r.get("provider") in ("virustotal", "abuseipdb") and "URL host" in origins:
            flagged_urls.append(c.intel_ev(ind, r, i, j, "flagged by provider"))
        if r.get("provider") == "virustotal" and itype == "hash":
            flagged_hashes.append(c.intel_ev(ind, r, i, j, "flagged by provider"))
        if r.get("provider") == "tor_exit_list" and is_origin(ind):
            tor_origin.append(c.intel_ev(ind, r, i, j, "listed in the Tor exit list"))
        if r.get("provider") == "ipinfo" and is_origin(ind) and (r.get("data") or {}).get("is_tor"):
            tor_origin.append(c.intel_ev(ind, r, i, j, "IPinfo privacy flag: Tor"))

    # M01 attachment delivery (observed)
    if has("risky_attachment_type"):
        ev = [c.finding("risky_attachment_type")] + [c.attachment(i) for i in range(len(c.atts))]
        out.append(Mapping("T1566.001", "observed", "high" if flagged_hashes else "medium", ev + flagged_hashes,
                           "A risky (executable, macro-capable or container) attachment is present in the message.",
                           "M01_attachment_delivery",
                           "Shows delivery of a risky file type, not that the file is malicious unless a provider "
                           "flagged its hash."))
    # M02 link delivery (observed)
    if url_idx and (url_rules or flagged_urls or has("credential_request") or lookalike):
        ev = [c.url(i) for i in url_idx[:5]] + [c.finding(r) for r in url_rules] + flagged_urls
        if has("credential_request"):
            ev.append(c.finding("credential_request"))
        if lookalike:
            ev.append(c.finding("lookalike_domain"))
        conf = "high" if flagged_urls else "medium" if (url_rules or lookalike) else "low"
        out.append(Mapping("T1566.002", "observed", conf, ev,
                           "The message delivers a link, and the link or its context carries phishing indicators.",
                           "M02_link_delivery", None, ml_support))
    # M03 / M04 phishing for information
    if has("credential_request"):
        if url_idx:
            out.append(Mapping("T1598.003", "inferred", "medium",
                               [c.finding("credential_request")] + [c.url(i) for i in url_idx[:3]],
                               "Credential/information-seeking language together with a link suggests a link-based "
                               "attempt to collect credentials or information.", "M03_info_link",
                               "Language-based inference; the linked page was not visited.", ml_support))
        else:
            out.append(Mapping("T1598", "inferred", "low", [c.finding("credential_request")],
                               "Credential/information-seeking language without a link suggests the recipient is "
                               "asked to supply information directly.", "M04_info_request",
                               "Language-based inference only.", ml_support))
    # M05 impersonation
    imp_signals = [c.finding(r) for r in ("sender_reply_to_mismatch", "lookalike_domain") if has(r)]
    if "replyto_mismatch" in c.inc:
        imp_signals.append(c.inconsistency("replyto_mismatch"))
    content = [c.finding(r) for r in CONTENT_RULES if has(r)]
    impersonation = bool(imp_signals and content)
    if impersonation:
        strong = lookalike or (has("payment_diversion") and has("sender_reply_to_mismatch"))
        out.append(Mapping("T1684.001", "inferred", "medium" if strong else "low", content + imp_signals,
                           "Payment or credential requests combined with sender-identity indicators (diverging "
                           "Reply-To, look-alike domain) suggest the sender is posing as a trusted party.",
                           "M05_impersonation", "Interpretation of content and header signals; the impersonated "
                           "party is not identified.", ml_support))
    # M06 email spoofing
    verified_fail = [p for p in ("dmarc", "spf") if (c.auth.get(p) or {}).get("status") == "verified_fail"]
    if verified_fail:
        ev = [c.auth_status(p) for p in verified_fail] + ([c.finding("auth_verified_fail")]
                                                          if has("auth_verified_fail") else [])
        out.append(Mapping("T1684.002", "observed", "high" if "dmarc" in verified_fail else "medium", ev,
                           "Sender authentication for the From domain was re-verified locally and failed.",
                           "M06_spoofing_verified"))
    else:
        claimed_fail = has("auth_failure_support")
        mismatch = [x for x in (c.inconsistency("returnpath_mismatch") if "returnpath_mismatch" in c.inc else None,
                                c.finding("auth_dmarc_misaligned") if has("auth_dmarc_misaligned") else None) if x]
        if claimed_fail and mismatch:
            ev = [c.finding("auth_failure_support")] + mismatch + [x for x in (c.auth_status("spf"),
                                                                              c.auth_status("dmarc")) if x]
            out.append(Mapping("T1684.002", "inferred", "low", ev,
                               "Header-claimed authentication failure together with envelope/alignment mismatch "
                               "suggests the From identity may be forged.", "M06_spoofing_claimed",
                               "Based on Authentication-Results claims that this system did not re-verify."))
    # M07 financial theft (intent)
    if has("payment_diversion"):
        out.append(Mapping("T1657", "inferred", "medium" if impersonation else "low",
                           [c.finding("payment_diversion")] + (imp_signals if impersonation else []),
                           "The message asks for a payment or a change of payment details.", "M07_financial_theft",
                           "Shows intent only; no transfer or theft is observed. ATT&CK only approximates BEC fraud.",
                           ml_support))
    # M08 / M09 user execution (only with provider flags)
    if flagged_hashes and has("risky_attachment_type"):
        out.append(Mapping("T1204.002", "inferred", "medium", flagged_hashes + [c.finding("risky_attachment_type")],
                           "A provider flagged the attachment hash; opening it would require user execution.",
                           "M08_malicious_file", "Execution is not observable in an email; this is the intended "
                           "next step, not an observed event."))
    if flagged_urls and url_idx:
        out.append(Mapping("T1204.001", "inferred", "low", flagged_urls + [c.url(i) for i in url_idx[:3]],
                           "A provider flagged a linked host; the attack relies on the recipient clicking it.",
                           "M09_malicious_link", "Execution is not observable in an email."))
    # M10 compromised account (low only)
    passes = [p for p in ("spf", "dkim", "dmarc") if (c.auth.get(p) or {}).get("status") == "verified_pass"]
    aligned = [p for p in ("spf", "dkim") if (c.auth.get("alignment") or {}).get(p) == "aligned"]
    if passes and aligned and content and not lookalike:
        out.append(Mapping("T1586.002", "inferred", "low",
                           [c.auth_status(p) for p in passes] + [c.alignment(p) for p in aligned] + content,
                           "Sending authenticated and aligned for the From domain while the content is fraudulent "
                           "is consistent with a taken-over legitimate mailbox.", "M10_compromised_account",
                           "Low confidence by design: authenticated fraud can also come from a legitimate sender "
                           "acting under pressure or from a mail-provider misconfiguration."))
    # M11 attacker-controlled reply mailbox
    if has("sender_reply_to_mismatch") and content:
        out.append(Mapping("T1585.002", "inferred", "low", [c.finding("sender_reply_to_mismatch")] + content,
                           "Replies are redirected to a different mailbox while the content requests payment or "
                           "credentials, consistent with a mailbox set up to receive victim replies.",
                           "M11_reply_mailbox", "The reply mailbox could also be compromised rather than newly "
                           "created; registration data is not available."))
    # M12 domains
    if lookalike or has("domain_no_mx_shortlived"):
        ev = [c.finding(r) for r in ("lookalike_domain", "domain_no_mx_shortlived") if has(r)]
        out.append(Mapping("T1583.001", "inferred", "medium" if has("domain_no_mx_shortlived") else "low", ev,
                           "A look-alike or very recently registered domain suggests acquired attacker domains.",
                           "M12_domains", None if has("domain_no_mx_shortlived") else
                           "Look-alike similarity only; no registration evidence."))
    # M13 Tor
    if tor_origin:
        out.append(Mapping("T1090.003", "inferred", "medium", tor_origin,
                           "An origin-candidate IP is a Tor exit node, i.e. the message was sent through a "
                           "multi-hop anonymising network.", "M13_tor_origin",
                           "In ATT&CK this technique is listed under Command and Control; here it describes "
                           "anonymised sending infrastructure. Origin candidates can be forged before the "
                           "trusted boundary."))
    return out


# ── source-type hypotheses ───────────────────────────────────────────────
ERROR_STATUSES = {"provider_error", "rate_limited", "auth_failed", "timeout", "malformed_response",
                  "not_permitted", "quota_exhausted", "missing_credentials"}


def _intel_state(c: Ctx) -> tuple[str | None, list]:
    """(not-assessed reason or None, origin-IP results with data)."""
    run = c.inp.intel_run
    if not run:
        return "threat-intel lookup was not run for this analysis", []
    if not (run.get("consent") or {}).get("granted"):
        return "external lookups were declined for this analysis", []
    origin = [(ind, r, i, j) for _t, ind, r, i, j in c.intel_results() if is_origin(ind)]
    if not origin:
        return "no origin-candidate IP was eligible for lookup", []
    usable = [x for x in origin if x[1].get("status") in DATA_STATUSES]
    if not usable:
        if run.get("offline") or all(x[1].get("status") == "not_attempted_offline" for x in origin):
            return "offline mode: no provider data for the origin candidates", []
        if all(x[1].get("status") in ERROR_STATUSES for x in origin):
            return "provider lookups for the origin candidates failed or were unavailable", []
        return "no provider returned data for the origin candidates", []
    return None, usable


def _hyp(band: str, ev: list[str], rationale: str, missing: list[str] | None = None) -> dict:
    return {"band": band, "evidence": [e for e in ev if e], "rationale": rationale, "missing_data": missing or []}


def _hypotheses(c: Ctx) -> dict:
    has = lambda r: r in c.f  # noqa: E731
    st = {p: (c.auth.get(p) or {}).get("status") for p in ("spf", "dkim", "dmarc")}
    no_auth = all(s in (None, "unknown", "unavailable") for s in st.values())
    out: dict[str, dict] = {}

    # 1. spoofed domain
    vfail = [p for p in ("dmarc", "spf") if st[p] == "verified_fail"]
    spoof_ev = [c.inconsistency("returnpath_mismatch") if "returnpath_mismatch" in c.inc else None,
                c.finding("auth_dmarc_misaligned") if has("auth_dmarc_misaligned") else None,
                c.finding("auth_failure_support") if has("auth_failure_support") else None,
                c.finding("lookalike_domain") if has("lookalike_domain") else None]
    spoof_ev = [e for e in spoof_ev if e]
    if vfail:
        out["spoofed_domain"] = _hyp("likely", [c.auth_status(p) for p in vfail] + spoof_ev,
                                     "Authentication for the From domain was re-verified and failed.")
    elif len(spoof_ev) >= 2:
        out["spoofed_domain"] = _hyp("possible", spoof_ev, "Several header/authentication signals are consistent "
                                     "with a forged or look-alike sender domain.",
                                     ["Authentication was not re-verified locally."] if no_auth or
                                     all(s != "verified_fail" for s in st.values()) else [])
    elif spoof_ev:
        out["spoofed_domain"] = _hyp("possible", spoof_ev, "One header/authentication signal is consistent with a "
                                     "forged or look-alike sender domain.", ["Single signal only."])
    elif st["dmarc"] == "verified_pass" or (st["spf"] == "verified_pass" and st["dkim"] == "verified_pass"):
        out["spoofed_domain"] = _hyp("not_indicated", [c.auth_status("dmarc"), c.auth_status("spf"),
                                                       c.auth_status("dkim")],
                                     "Authentication for the From domain was re-verified and passed.")
    else:
        out["spoofed_domain"] = _hyp("undetermined", [], "No authentication result or header signal is available "
                                     "to assess sender-domain spoofing.",
                                     ["SPF/DKIM/DMARC were not verified (offline or no records)."])

    # 2. compromised legitimate account (possible at most)
    content = [c.finding(r) for r in CONTENT_RULES if has(r)]
    passes = [p for p in ("spf", "dkim", "dmarc") if st[p] == "verified_pass"]
    aligned = [p for p in ("spf", "dkim") if (c.auth.get("alignment") or {}).get(p) == "aligned"]
    if vfail:
        out["compromised_account"] = _hyp("not_indicated", [c.auth_status(p) for p in vfail],
                                          "The message failed authentication for the From domain, so it was not "
                                          "sent through that domain's legitimate mail service.")
    elif passes and aligned and content and not has("lookalike_domain"):
        extra = [c.finding("sender_reply_to_mismatch")] if has("sender_reply_to_mismatch") else []
        out["compromised_account"] = _hyp("possible", [c.auth_status(p) for p in passes] +
                                          [c.alignment(p) for p in aligned] + content + extra,
                                          "Authenticated, aligned sending combined with fraudulent content is "
                                          "consistent with a taken-over legitimate account.",
                                          ["No sender-history baseline is available to confirm behaviour changes."])
    elif no_auth or not passes:
        out["compromised_account"] = _hyp("undetermined", content,
                                          "Without verified, aligned authentication this hypothesis cannot be "
                                          "assessed.", ["SPF/DKIM/DMARC were not re-verified as passing."])
    else:
        out["compromised_account"] = _hyp("not_indicated", [c.auth_status(p) for p in passes],
                                          "Authentication passed, but no fraudulent content signals were found.")

    # 3 + 4 depend on threat intel
    reason, usable = _intel_state(c)
    if reason:
        na = {"band": "not_assessed", "reason": reason, "evidence": [], "rationale":
              f"Not assessed: {reason}. Absence of provider data is not evidence of safety.", "missing_data": [reason]}
        out["anonymised_infrastructure"] = dict(na)
        out["direct_malicious_infrastructure"] = dict(na)
        return out
    anon_likely, anon_possible, mal = [], [], []
    for ind, r, i, j in usable:
        data, prov = r.get("data") or {}, r.get("provider")
        if prov == "tor_exit_list" and data.get("listed"):
            anon_likely.append(c.intel_ev(ind, r, i, j, "listed in the Tor exit list"))
        if prov == "ipinfo":
            flags = [k[3:] for k in ("is_vpn", "is_proxy", "is_tor") if data.get(k)]
            if flags:
                anon_likely.append(c.intel_ev(ind, r, i, j, f"IPinfo privacy flags: {', '.join(flags)}"))
            soft = [k[3:] for k in ("is_relay", "is_hosting") if data.get(k)]
            if soft:
                anon_possible.append(c.intel_ev(ind, r, i, j, f"IPinfo flags: {', '.join(soft)}"))
        if prov == "abuseipdb" and "hosting" in str(data.get("usage_type") or "").lower():
            anon_possible.append(c.intel_ev(ind, r, i, j, f"usage type: {data.get('usage_type')}"))
        if prov in ("virustotal", "abuseipdb") and r.get("status") == "malicious_or_flagged":
            mal.append(c.intel_ev(ind, r, i, j, "flagged by provider"))
    caveat = "Absence of reports or flags is not evidence of safety."
    if anon_likely:
        out["anonymised_infrastructure"] = _hyp("likely", anon_likely + anon_possible,
                                                "An origin-candidate IP is a Tor exit or carries anonymiser flags.")
    elif anon_possible:
        out["anonymised_infrastructure"] = _hyp("possible", anon_possible, "An origin-candidate IP is hosting or "
                                                "relay infrastructure, which is often used to obscure senders.")
    else:
        out["anonymised_infrastructure"] = _hyp("not_indicated", [], f"No provider returned anonymiser flags for "
                                                f"the origin candidates. {caveat}")
    if len(mal) >= 2:
        out["direct_malicious_infrastructure"] = _hyp("likely", mal, "More than one provider flagged an "
                                                      "origin-candidate IP.")
    elif mal:
        out["direct_malicious_infrastructure"] = _hyp("possible", mal, "One provider flagged an origin-candidate IP.")
    else:
        out["direct_malicious_infrastructure"] = _hyp("not_indicated", [], f"No provider flagged the origin "
                                                      f"candidates. {caveat}")
    return out


HYPOTHESIS_LABELS = {
    "spoofed_domain": "Possible spoofed sender domain",
    "compromised_account": "Possible compromised legitimate account",
    "anonymised_infrastructure": "Anonymised sending infrastructure",
    "direct_malicious_infrastructure": "Directly malicious infrastructure",
}


def compute(inp: Inputs) -> dict:
    cat = get_catalog()
    c = Ctx(inp)
    maps = _rules(c)
    hyps = _hypotheses(c)
    # assign A1.. in first-use order: mappings first (in rule order), then hypotheses
    used: list[str] = []
    for m in maps:
        for k in m.evidence + m.support:
            if k and k not in used:
                used.append(k)
    for h in hyps.values():
        for k in h["evidence"]:
            if k and k not in used:
                used.append(k)
    ids = {k: f"A{n}" for n, k in enumerate(used, 1)}
    evidence = [{"id": ids[k], "kind": c.b.items[k].kind, "category": c.b.items[k].category,
                 "source_field": c.b.items[k].source_field, "statement": c.b.items[k].statement,
                 "tab": c.b.items[k].tab} for k in used]
    mappings = []
    for m in maps:
        t = cat.technique(m.technique_id)
        mappings.append({
            "technique_id": t["technique_id"], "name": t["name"], "tactics": t["tactics"], "url": t["url"],
            "basis": m.basis, "confidence": m.confidence,
            "evidence_ids": [ids[k] for k in dict.fromkeys(m.evidence) if k],
            "supporting_evidence_ids": [ids[k] for k in dict.fromkeys(m.support) if k],
            "rationale": m.rationale, "mapping_rule_id": m.rule_id, "limitations": m.limitations})
    hypotheses = []
    for key in HYPOTHESIS_LABELS:
        h = hyps[key]
        hypotheses.append({"hypothesis": key, "label": HYPOTHESIS_LABELS[key], "band": h["band"],
                           "evidence_ids": [ids[k] for k in dict.fromkeys(h["evidence"]) if k],
                           "rationale": h["rationale"], "missing_data": h.get("missing_data", []),
                           **({"reason": h["reason"]} if "reason" in h else {})})
    run = inp.intel_run or {}
    return {
        "engine_version": ENGINE_VERSION, "catalog_version": cat.version, "attack_version": cat.attack_version,
        "catalog_verified": cat.verified,
        "inputs": {"intel_run_id": run.get("run_id"), "intel_run_version": run.get("version"),
                   "intel_simulated": bool(run.get("simulated")),
                   "ml_assessment_id": (inp.ml or {}).get("assessment_id")},
        "mappings": mappings, "empty_state": None if mappings else EMPTY_TEXT,
        "source_type": hypotheses, "evidence": evidence, "informational_only": True,
        "suppressed_signals": c.suppressed,
        "disclaimer": DISCLAIMER,
        "note": "ATT&CK describes intrusion tradecraft and only approximates business-email-compromise and "
                "financial fraud.",
    }
