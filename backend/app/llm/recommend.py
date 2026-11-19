"""Ground model recommendations against the deterministic evidence (P4.1).

The model may suggest actions, but an action must not introduce an
unsupported factual claim about the email ("the phone number provided",
"the new supplier mentioned"). Each model action is classified:

  evidence_linked  every email artefact it mentions is present in evidence
                   items, whose ids are attached;
  general          it mentions no specific artefact, or mentions one without
                   asserting that the email contains it ("independently verify
                   any supplier details");
  rejected         it asserts the email contains an artefact that no evidence
                   item establishes.

Fixed, system-written general recommendations are added separately and are
labelled as such. Recommendations never become findings and never change a
verdict.
"""
from __future__ import annotations

import re

from app.llm.evidence import EvidencePack
from app.llm.redact import redact

# artefact -> (mention pattern, words whose presence in an evidence statement supports it)
ARTEFACTS: dict[str, tuple[re.Pattern, tuple[str, ...]]] = {
    "URL/link": (re.compile(r"\b(urls?|links?|hyperlinks?|web ?sites?)\b", re.I), ("url host", "url count: 1", "url")),
    "Reply-To address": (re.compile(r"\breply[- ]?to\b|\breply address", re.I), ("reply-to",)),
    "sender/From domain": (re.compile(r"\b(sender|from (address|domain|header)|sending domain|display name)\b", re.I),
                           ("from header sender domain", "sender domain")),
    "attachment": (re.compile(r"\battach(ment|ed)s?\b", re.I), ("attachment",)),
    "credential request": (re.compile(r"\b(passwords?|credentials?|log-?in|sign[- ]?in)\b", re.I),
                           ("credential", "password")),
    "urgency language": (re.compile(r"\b(urgen\w*|pressure|deadline)\b", re.I), ("urgen", "pressure")),
    "payment/wire request": (re.compile(r"\b(payments?|wire|transfers?|bank(ing)?|iban|invoices?|remittance|"
                                        r"beneficiar\w*)\b", re.I),
                             ("payment", "wire", "invoice", "bank", "beneficiar")),
    "phone number": (re.compile(r"\b(phone|telephone|mobile)( numbers?)?\b|\bcall[- ]?back\b", re.I), ("phone",)),
    "supplier/vendor": (re.compile(r"\b(suppliers?|vendors?|payees?)\b", re.I), ("supplier", "vendor", "payee")),
    "approval/security code": (re.compile(r"\b(approval codes?|codes?|pins?|otps?|tokens?)\b", re.I),
                               ("approval code", " pin ", "otp", "token")),
    "authentication results": (re.compile(r"\b(spf|dkim|dmarc|authentication)\b", re.I), ("spf", "dkim", "dmarc")),
    "headers/relay": (re.compile(r"\b(headers?|received|relay|routing|originating ip)\b", re.I),
                      ("header", "received", "relay")),
}
_ASSERTIVE = re.compile(r"\b(the|this|that|these|those|its|provided|mentioned|given|listed|included|stated|"
                        r"supplied|requested|specified|quoted|contained)\b", re.I)
_IN_EMAIL = re.compile(r"\b(in|from|within) (the|this) (e-?mail|message)\b", re.I)

SYSTEM_GENERAL = [
    "Verify any payment, supplier or bank-detail request independently through a contact channel that was "
    "already known before this email (never through contact details taken from the email itself).",
    "Do not use links, phone numbers or reply addresses from this email to verify it.",
    "Preserve the original .eml file and this report for the investigation record.",
]


def _supports(pack: EvidencePack, words: tuple[str, ...]) -> list[str]:
    hits = []
    for item in pack.items:
        if item["category"] == "model":       # ML/SHAP outputs never establish an email artefact
            continue
        text = f" {item['statement'].lower()} "
        if item["source"] == "parser" and "url count: 0" in text and "url" in words[0]:
            continue
        if any(w in text for w in words):
            hits.append(item["id"])
    return hits


def classify(action: str, pack: EvidencePack) -> dict:
    text = redact(action.strip(), pack.redactions)[:300]
    mentioned, supported, ids = [], [], []
    for name, (pat, words) in ARTEFACTS.items():
        m = pat.search(text)
        if not m:
            continue
        mentioned.append(name)
        hit = _supports(pack, words)
        if hit:
            supported.append(name)
            ids.extend(hit)
            continue
        before = text[max(0, m.start() - 40):m.start()]
        after = text[m.end():m.end() + 40]
        if _ASSERTIVE.search(before.split(",")[-1]) or _IN_EMAIL.search(after) or _IN_EMAIL.search(before):
            return {"text": text, "kind": "rejected",
                    "reason": f"asserts a detail of the email ({name}) that no deterministic evidence "
                              "item establishes"}
    if mentioned and len(supported) == len(mentioned):
        return {"text": text, "kind": "evidence_linked", "origin": "model",
                "evidence_ids": sorted(set(ids), key=lambda e: int(e[1:])), "artefacts": supported}
    return {"text": text, "kind": "general", "origin": "model", "evidence_ids": [],
            "artefacts": supported}


def ground(actions: list[str], pack: EvidencePack) -> tuple[list[dict], list[dict]]:
    """Return (recommendations, rejected_recommendations). System general items come last."""
    recs, rejected = [], []
    for a in actions:
        c = classify(a, pack)
        if c["kind"] == "rejected":
            rejected.append({"text": c["text"], "reason": c["reason"]})
        else:
            recs.append(c)
    recs += [{"text": t, "kind": "general", "origin": "system", "evidence_ids": [], "artefacts": []}
             for t in SYSTEM_GENERAL]
    return recs, rejected
