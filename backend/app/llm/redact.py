"""Redaction applied to every string before it reaches the LLM.

Removes credentials/secrets and unnecessary personal data while keeping the
forensically useful parts (sender/URL domains, rule names, counts).
"""
from __future__ import annotations

import re
from collections import Counter

_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED_PRIVATE_KEY]"),
    ("jwt", re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b"), "[REDACTED_TOKEN]"),
    ("api_key", re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|proj)?[-_]?[A-Za-z0-9]{16,}\b"), "[REDACTED_KEY]"),
    ("api_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED_KEY]"),
    ("api_key", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_KEY]"),
    ("api_key", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_KEY]"),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer [REDACTED_TOKEN]"),
    ("credential", re.compile(
        r"(?i)\b(password|passwd|pwd|passcode|pin|otp|secret|token|api[_ -]?key|access[_ -]?key)"
        r"(\s*(?:is|:|=)\s*)(\"[^\"]{1,80}\"|'[^']{1,80}'|\S{1,80})"), r"\1\2[REDACTED_SECRET]"),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b"), "[REDACTED_IBAN]"),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_ID]"),
]
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_PHONE = re.compile(r"(?<![\w.])\+?\d[\d ()-]{6,}\d(?![\w.])")
_LONG_NUMBER = re.compile(r"\b\d{8,}\b")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total, alt = total + d, not alt
    return total % 10 == 0


_EMAIL = re.compile(r"\b([A-Za-z0-9._%+'-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
_URL = re.compile(r"\b((?:https?|hxxps?)://)([^\s/?#<>\"']+)([^\s<>\"']*)", re.I)


def redact(text: str | None, counts: Counter | None = None) -> str:
    """Redact one string; per-kind counts are added to `counts`."""
    if not text:
        return ""
    c = counts if counts is not None else Counter()

    def url(m: re.Match) -> str:
        if m.group(3) and m.group(3) not in ("/",):
            c["url_path"] += 1
            return f"{m.group(1)}{m.group(2)}/[path]"
        return m.group(0)

    text = _URL.sub(url, text)

    def email(m: re.Match) -> str:
        c["email_local_part"] += 1
        return f"[user]@{m.group(2)}"

    text = _EMAIL.sub(email, text)
    for kind, pat, repl in _PATTERNS:
        text, n = pat.subn(repl, text)
        if n:
            c[kind] += n

    def card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            c["card"] += 1
            return "[REDACTED_CARD]"
        return m.group(0)

    def phone(m: re.Match) -> str:
        if _IPV4.match(m.group(0).strip()):   # IP addresses are forensic indicators, not personal data
            return m.group(0)
        c["phone"] += 1
        return "[REDACTED_PHONE]"

    def long_number(m: re.Match) -> str:
        c["long_number"] += 1
        return "[REDACTED_NUMBER]"

    text = _CARD.sub(card, text)
    text = _PHONE.sub(phone, text)
    return _LONG_NUMBER.sub(long_number, text)


def redact_obj(obj, counts: Counter):
    if isinstance(obj, str):
        return redact(obj, counts)
    if isinstance(obj, list):
        return [redact_obj(x, counts) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v, counts) for k, v in obj.items()}
    return obj
