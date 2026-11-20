"""Safe, constrained investigative recommendations (P4.2).

The language model may *suggest* actions, but nothing it writes is shown as
advice verbatim. Every model action is mapped onto a closed set of
investigative categories, in this order:

1. UNSAFE   -> rejected. Replying to / contacting the alleged sender without an
               independent channel, using phone numbers, links, attachments or
               contact details from the email, or moving money / changing
               payment details on the strength of the email.
2. UNSUPPORTED -> rejected. Asserting that an email detail (supplier, phone
               number, approval code, account ...) exists when no
               deterministic evidence item establishes it.
3. EVIDENCE-LINKED -> accepted only when the category's required evidence is
               present; the shown text is a fixed system template and the
               evidence IDs are chosen deterministically from the evidence
               pack (never from the model's citations).
4. GENERAL  -> mapped onto fixed, system-written templates (never model text).
5. anything else -> rejected as unrecognised / ambiguous.

Matching runs on a normalised form of the text (Unicode NFKC, invisible
characters removed, punctuation and separators collapsed) and on a
"compact" letters-only form, so spacing and punctuation tricks such as
"r.e.p.l.y to the s-e-n-d-e-r" do not hide an unsafe instruction.
Recommendations never become findings and never change any verdict.
"""
from __future__ import annotations

import re
import unicodedata

from app.llm.evidence import EvidencePack
from app.llm.redact import redact

# ── fixed general templates (system-controlled) ──────────────────────────
GENERAL_TEMPLATES: dict[str, str] = {
    "independent_verification": (
        "Verify any unusual payment, bank-detail, invoice or supplier request through a previously established, "
        "independently verified communication channel (for example a phone number already on file), never through "
        "the email itself."),
    "do_not_use_email_contacts": (
        "Do not reply to the suspicious email, and do not use telephone numbers, links, attachments or contact "
        "details contained in it for verification."),
    "preserve_evidence": "Preserve the original email (.eml) and its associated evidence, including this report.",
    "escalate": "Escalate the suspected fraud through the organisation's established security or finance reporting "
                "procedure.",
    "hold_payments": "Do not transfer funds, approve invoices or change payment details until independent "
                     "verification is complete.",
}
SYSTEM_GENERAL = list(GENERAL_TEMPLATES.values())   # kept for callers/tests of the P4.1 API

# ── evidence-linked categories: (template, evidence selector) ────────────
EVIDENCE_TEMPLATES: dict[str, str] = {
    "reply_to_mismatch": "Investigate the mismatch between the From and Reply-To domains as a possible "
                         "reply-diversion attempt. Do not send anything to either address.",
    "sender_domain": "Investigate the sender domain for spoofing or look-alike registration using independent "
                     "sources (registry, DNS and threat-intelligence lookups). Do not contact the sender.",
    "url_analysis": "Analyse the URL host(s) listed in the evidence with threat-intelligence or sandbox tooling. "
                    "Do not open them from a normal workstation.",
    "attachment_analysis": "Analyse the attachment(s) only in an isolated sandbox. Do not open them on a "
                           "workstation.",
    "credential_request": "Treat the credential request as malicious. Check whether any recipient entered "
                          "credentials and, if so, reset them and review sign-in activity.",
    "payment_request": "Hold the payment request identified in the evidence and verify it only through a "
                       "previously established, independently verified channel.",
    "auth_verification": "Re-check SPF, DKIM and DMARC from the receiving mail server's own logs, because the "
                         "header claims were not verified by this system.",
    "header_anomaly": "Review the header inconsistencies recorded in the evidence with the mail administrator, "
                      "using server-side logs.",
}

_INVISIBLE = re.compile(r"[​-‏⁠﻿­]")


def normalise(text: str) -> str:
    t = unicodedata.normalize("NFKC", text or "").lower()
    t = _INVISIBLE.sub("", t)
    t = t.replace("’", "'").replace("‘", "'")
    t = re.sub(r"n't\b", " not", t)                      # don't -> do not
    t = re.sub(r"[^a-z0-9' ]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def compact(text: str) -> str:
    return re.sub(r"[^a-z]", "", normalise(text))


def _any(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text) for p in patterns)


# vocabulary (on normalised text)
NEG = r"\b(do not|does not|never|avoid|refrain from|must not|should not|without|no)\b"
INDEPENDENT = [r"\bindependent(ly)?\b", r"\bpreviously (established|known|verified)\b", r"\bknown (good|number|contact)\b",
               r"\bout of band\b", r"\balready on file\b", r"\bon file\b", r"\bseparate(ly)? (verified )?channel\b",
               r"\btrusted (directory|channel|contact)\b", r"\bofficial (directory|records)\b"]
FROM_EMAIL = [r"\b(in|from|within|inside|on|at the bottom of|at the end of|of) (the |this |that )?"
              r"(e ?mail|message|signature|footer|letter)\b", r"\b(provided|supplied|listed|given|included|mentioned|"
              r"quoted|shown|stated|contained)\b", r"\bsignature\b", r"\breply ?to\b", r"\breply address\b",
              r"\be ?mail'?s\b", r"\btheir (number|phone|contact)", r"\bthat (number|link|address)\b"]
CONTACT_VERB = r"\b(reply|respond|answer|write back|e ?mail back|(e ?mail|message|text) (the|them|her|him)|" \
               r"send (an? )?(e ?mail|message|reply) to|write to|contact|reach out|reach|" \
               r"get in touch|ping|ask|confirm with|check with|verify with|speak (to|with)|talk (to|with)|call|ring|" \
               r"phone|dial|text|sms|whatsapp)\b"
SENDER = r"\b(sender|senders|sending party|requester|requestor|originator|author|person who sent|whoever sent|" \
         r"the ceo|ceo|executive|boss|manager|them|her|him|the supplier|supplier|vendor)\b"
PHONE = r"\b(phone|telephone|number|mobile|cell|landline|extension|line)\b"
CALL_VERB = r"\b(call|ring|phone(?! numbers?\b)|dial|text|sms|whatsapp|use|contact|try|reach)\b"
LINK_OBJ = r"\b(link|links|url|urls|hyperlink|website|web site|site|portal|page|button|attachment|attachments|" \
           r"attached|file|document|pdf|invoice attached|qr code)\b"
OPEN_VERB = r"\b(click|open|visit|follow|press|hit|tap|use|go to|navigate|browse|access|download|run|execute|" \
            r"enable|log ?in|sign ?in|launch|load)\b"
SAFE_ANALYSIS = r"\b(sandbox|sandboxed|isolated|threat ?intel\w*|reputation|scan|detonat\w*|without (opening|" \
                r"visiting|clicking)|do not (open|visit|click)|block|blocklist|quarantine|defang\w*)\b"
MONEY_VERB = r"\b(transfer|wire|send|pay|process|approve|release|authori[sz]e|make|complete|execute|update|change|" \
             r"amend|switch|modify|go ahead with|proceed with|honou?r)\b"
MONEY_OBJ = r"\b(funds|money|payment|payments|wire|transfer|invoice|invoices|bank details|banking details|" \
            r"account details|payment details|beneficiary|remittance|bank account)\b"
HOLD = r"\b(do not|never|hold|pause|freeze|stop|until|before|unless|suspend|delay)\b"

# details a recommendation may claim exist in the email: name -> (pattern, evidence words)
DETAILS: dict[str, tuple[str, tuple[str, ...]]] = {
    "supplier": (r"\b(supplier|suppliers|vendor|vendors|payee|new account)\b", ("supplier", "vendor", "payee")),
    "phone number": (r"\b(phone|telephone|mobile|cell)( number)?\b|\bnumber\b", ("phone",)),
    "approval code": (r"\b(approval code|authori[sz]ation code|code|pin|otp|token)\b", ("approval code", "otp", "pin ")),
    "account": (r"\b(account number|bank account|iban|account details|beneficiary account)\b", ("iban", "bank account")),
    "invoice": (r"\binvoices?\b", ("invoice",)),
    "attachment": (r"\battach(ment|ments|ed)\b", ("attachment",)),
}
ASSERTIVE = r"\b(the|this|that|these|those|its|provided|mentioned|given|listed|included|stated|supplied|" \
            r"requested|specified|quoted|contained|referenced|named)\b"


# "Reply-To" used as a noun (the header) is not an instruction to reply.
_REPLY_TO_NOUN = re.compile(r"\b(the|a|its|their|from|and|or|of|in|mismatched?|differing|divergent) reply ?to\b|"
                            r"\breply ?to (address|addresses|domain|domains|header|headers|field|value|mismatch|"
                            r"differs|diverges|is|was|points)\b")
_IMPERATIVE_REPLY = re.compile(r"^(just |please |then |simply |quickly |now )*(reply|respond|answer|write back)\b")
_VERIFY_WITH = re.compile(r"\b(verify|confirm|check|validate|double check|clarify|discuss|query)\b.*\bwith\b.*" + SENDER)


def _unsafe_reason(n: str, c: str) -> str | None:
    """Return a rejection reason if the normalised text n / compact c is unsafe."""
    noun_reply_to = bool(_REPLY_TO_NOUN.search(n))
    n_verbs = _REPLY_TO_NOUN.sub(" replytoheader ", n)          # verbs are matched without the header noun
    negated = bool(re.search(NEG, n))
    independent = _any(INDEPENDENT, n)
    from_email = _any(FROM_EMAIL, n)

    # contact details taken from the email (phone / reply-to / signature / links)
    if re.search(CALL_VERB, n_verbs) and re.search(PHONE, n) and from_email and not negated:
        return "uses a phone number or contact detail taken from the suspicious email"
    if (noun_reply_to or re.search(r"\breply address\b", n)) and re.search(CONTACT_VERB, n_verbs) and not negated:
        return "contacts the Reply-To address of the suspicious email"
    if _IMPERATIVE_REPLY.search(n) and not negated:
        return "replies to the suspicious email"
    if _VERIFY_WITH.search(n_verbs) and not independent:
        return ("verifies the request with the alleged sender instead of through a previously established, "
                "independently verified channel")
    # opening links / attachments
    if re.search(OPEN_VERB, n) and re.search(LINK_OBJ, n) and not negated and not re.search(SAFE_ANALYSIS, n):
        return "opens or uses a link or attachment from the suspicious email"
    # moving money / changing payment details on the email's strength
    if re.search(MONEY_VERB, n) and re.search(MONEY_OBJ, n) and not re.search(HOLD, n) \
            and not re.search(r"\b(verify|investigate|review|analy[sz]e|check|report|escalate|flag|hold)\b", n):
        return "moves money or changes payment details based on the suspicious email"
    # contacting the alleged sender without an independent channel
    if re.search(CONTACT_VERB, n_verbs) and re.search(SENDER, n) and not negated:
        if from_email or not independent:
            return ("contacts the alleged sender without requiring a previously established, independently "
                    "verified channel")
    # compact fallback against spacing / punctuation obfuscation ("r e p l y", "s-e-n-d-e-r"); only used when
    # the text actually looks letter-spaced, so ordinary wording ("sender and reply-to domains") is not caught
    obfuscated = bool(re.search(r"\b[a-z]( [a-z]){3,}\b", n))
    if obfuscated and not negated and not independent:
        for verb in ("reply", "respond", "callthe", "dialthe", "clickthe", "openthe", "wirethe", "transferthe",
                     "contactthesender", "emailthesender", "messagethesender"):
            if verb in c and any(t in c for t in ("sender", "number", "link", "attachment", "funds", "money",
                                                  "payment", "email", "message")):
                return "unsafe instruction (detected after removing punctuation and spacing)"
    return None


def _evidence(pack: EvidencePack, *, sources: tuple[str, ...] = (), words: tuple[str, ...] = (),
              exclude_model: bool = True) -> list[str]:
    ids = []
    for item in pack.items:
        if exclude_model and item["category"] == "model":
            continue
        src = item["source"]
        text = item["statement"].lower()
        if any(src == s or src.startswith(s) for s in sources) or any(w in text for w in words):
            ids.append(item["id"])
    return ids


def _url_ids(pack: EvidencePack) -> list[str]:
    return [i["id"] for i in pack.items if i["source"] == "parser" and i["statement"].lower().startswith("url count:")
            and not i["statement"].lower().startswith("url count: 0")]


def evidence_for(category: str, pack: EvidencePack) -> list[str]:
    """Deterministic evidence IDs a category requires (empty list => category not supported)."""
    if category == "reply_to_mismatch":
        return _evidence(pack, sources=("rule:sender_reply_to_mismatch", "forensics:replyto_mismatch"))
    if category == "sender_domain":
        return [i["id"] for i in pack.items if i["source"] == "parser"
                and i["statement"].startswith("From header sender domain")]
    if category == "url_analysis":
        return _url_ids(pack)
    if category == "attachment_analysis":
        return [i["id"] for i in pack.items if i["source"] == "parser" and "attachment(s)" in i["statement"]]
    if category == "credential_request":
        return _evidence(pack, sources=("rule:credential_request",))
    if category == "payment_request":
        return _evidence(pack, sources=("rule:payment_diversion",)) or \
            [i["id"] for i in pack.items if i["source"] == "parser" and i["statement"].startswith("Subject:")
             and re.search(r"\b(wire|payment|invoice|transfer|bank|remittance)\b", i["statement"].lower())]
    if category == "auth_verification":
        return _evidence(pack, sources=("auth:spf", "auth:dkim", "auth:dmarc"))
    if category == "header_anomaly":
        return _evidence(pack, sources=("forensics:", "rule:header_inconsistency"))
    return []


# model wording -> category (checked on normalised text, after the unsafe checks)
EVIDENCE_PATTERNS: list[tuple[str, str]] = [
    ("reply_to_mismatch", r"\breply ?to\b.*\b(mismatch\w*|differ\w*|diverg\w*|domains?|address(es)?)\b|\b(mismatch\w*|differ\w*)\b.*\breply ?to\b"),
    ("url_analysis", r"\b(investigate|analy[sz]e|examine|scan|inspect|look up|research|block|defang|check)\b.*\b(url|urls|link|links|domain in the link|host)\b"),
    ("attachment_analysis", r"\b(investigate|analy[sz]e|examine|scan|inspect|sandbox|detonate)\b.*\battach\w*"),
    ("credential_request", r"\b(credential|password|login|log in|sign in)\b"),
    ("payment_request", r"\b(investigate|review|verify|examine|hold|check|flag|scrutini[sz]e)\b.*\b(payment|wire|transfer|invoice|remittance|bank)\b"),
    ("auth_verification", r"\b(spf|dkim|dmarc|authentication)\b"),
    ("header_anomaly", r"\b(header|headers|received|relay|routing|originating ip)\b"),
    ("sender_domain", r"\b(sender'?s?|from) (domain|address|account|identity)\b|\b(spoof\w*|look ?alike|impersonat\w*|typosquat\w*)\b"),
]
GENERAL_PATTERNS: list[tuple[str, str]] = [
    ("do_not_use_email_contacts", r"\b(do not|never|avoid)\b.*\b(reply|respond|click|open|call|use)\b"),
    ("hold_payments", r"\b(do not|never|hold|pause|freeze|until|before)\b.*\b(transfer|wire|pay|payment|funds|invoice|bank details|payment details)\b"),
    ("independent_verification", r"\b(independent\w*|previously established|known (good )?(number|contact|channel)|out of band|on file|separate channel)\b"),
    ("escalate", r"\b(escalat\w*|report|notify|inform|alert)\b.*\b(security|soc|it|finance|fraud|incident|team|management|department|cert|authorit\w*|recipient|users?|staff)\b"),
    ("preserve_evidence", r"\b(preserv\w*|retain|keep|save|archive|secure)\b.*\b(email|eml|message|evidence|original|headers|logs|report)\b"),
]


def _unsupported_detail(n: str, pack: EvidencePack) -> str | None:
    for name, (pat, words) in DETAILS.items():
        m = re.search(pat, n)
        if not m:
            continue
        if _evidence(pack, words=words):
            continue
        before = n[max(0, m.start() - 40):m.start()]
        after = n[m.end():m.end() + 40]
        if re.search(ASSERTIVE, before) or re.search(r"\b(in|from|within) (the|this) (e ?mail|message)\b", after):
            return f"asserts a detail of the email ({name}) that no deterministic evidence item establishes"
    return None


def classify(action: str, pack: EvidencePack) -> dict:
    """Classify one model action. Shown text is always a system template, never the model's words."""
    model_text = redact((action or "").strip(), pack.redactions)[:300]
    n, c = normalise(action), compact(action)
    if not n:
        return {"text": model_text, "kind": "rejected", "reason": "empty recommendation"}
    reason = _unsafe_reason(n, c)
    if reason:
        return {"text": model_text, "kind": "rejected", "category": "unsafe", "reason": f"unsafe: {reason}"}
    for category, pat in GENERAL_PATTERNS:          # negated/hold advice first: "do not wire ... until"
        if category in ("do_not_use_email_contacts", "hold_payments") and re.search(pat, n):
            return {"text": GENERAL_TEMPLATES[category], "kind": "general", "origin": "system",
                    "category": category, "evidence_ids": [], "model_text": model_text}
    if _any(INDEPENDENT, n) and not _any(FROM_EMAIL, n):   # explicit independent channel, nothing from the email
        return {"text": GENERAL_TEMPLATES["independent_verification"], "kind": "general", "origin": "system",
                "category": "independent_verification", "evidence_ids": [], "model_text": model_text}
    reason = _unsupported_detail(n, pack)
    if reason:
        return {"text": model_text, "kind": "rejected", "category": "unsupported", "reason": reason}
    for category, pat in EVIDENCE_PATTERNS:
        if re.search(pat, n):
            ids = evidence_for(category, pack)
            if not ids:
                return {"text": model_text, "kind": "rejected", "category": category,
                        "reason": f"refers to '{category.replace('_', ' ')}', but the evidence list contains no "
                                  "supporting item"}
            return {"text": EVIDENCE_TEMPLATES[category], "kind": "evidence_linked", "origin": "system_template",
                    "category": category, "evidence_ids": ids, "model_text": model_text}
    for category, pat in GENERAL_PATTERNS:
        if re.search(pat, n):
            return {"text": GENERAL_TEMPLATES[category], "kind": "general", "origin": "system",
                    "category": category, "evidence_ids": [], "model_text": model_text}
    return {"text": model_text, "kind": "rejected", "category": "unrecognised",
            "reason": "not a recognised investigative action; not shown as advice"}


# ── financial context (deterministic) ────────────────────────────────────
_FIN = re.compile(r"\b(wire|payment|payments|invoice|invoices|bank|banking|iban|beneficiary|remittance|transfer|"
                  r"supplier|vendor|payroll|gift ?cards?|funds|usd|eur|gbp)\b|\[redacted_iban\]|\[redacted_card\]",
                  re.I)


def _term(t: str) -> str:
    t = t.lower()
    return {"[redacted_iban]": "iban", "[redacted_card]": "card number"}.get(t, t)


def financial_context(pack: EvidencePack) -> dict:
    """Does the analysis concern payments / bank details / invoices / suppliers / urgent money requests?"""
    signals = []
    for i in pack.items:
        if i["category"] == "model":
            continue
        m = _FIN.search(i["statement"])
        if m:
            signals.append({"evidence_id": i["id"], "term": _term(m.group(0))})
    body_terms = sorted({_term(m.group(0)) for m in _FIN.finditer(pack.body_excerpt or "")})
    ml = (pack.system_verdicts.get("ml") or {}).get("label")
    detected = bool(signals or body_terms or ml == "fraud")
    return {"detected": detected, "evidence_signals": signals[:8], "email_text_terms": body_terms[:10],
            "ml_label_fraud": ml == "fraud",
            "warning": ("This email concerns payments, bank details, invoices or suppliers. Do not act on it. "
                        "Verify any request only through a previously established, independently verified "
                        "channel, never through contact details in the email.") if detected else None}


def general_recommendations(fin: dict) -> list[dict]:
    keys = ["do_not_use_email_contacts", "preserve_evidence", "escalate"]
    if fin.get("detected"):
        keys = ["independent_verification", "hold_payments"] + keys
    return [{"text": GENERAL_TEMPLATES[k], "kind": "general", "origin": "system", "category": k,
             "evidence_ids": []} for k in keys]


def ground(actions: list[str], pack: EvidencePack) -> tuple[list[dict], list[dict]]:
    """Return (recommendations, rejected). Evidence-linked items are deduplicated by category;
    general advice is always the fixed system set (model general suggestions only mark it)."""
    fin = financial_context(pack)
    linked: dict[str, dict] = {}
    general = {g["category"]: g for g in general_recommendations(fin)}
    rejected = []
    for a in actions:
        r = classify(a, pack)
        if r["kind"] == "rejected":
            rejected.append({"text": r["text"], "reason": r["reason"], "category": r.get("category")})
        elif r["kind"] == "evidence_linked":
            linked.setdefault(r["category"], {**r, "model_suggestions": []})["model_suggestions"].append(r["model_text"])
        else:
            g = general.setdefault(r["category"], {**r, "model_text": None})
            g["also_suggested_by_model"] = True
    for r in linked.values():
        r.pop("model_text", None)
    return list(linked.values()) + list(general.values()), rejected
