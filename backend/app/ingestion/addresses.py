"""Safe address-domain extraction and normalisation for header comparisons (P5d.1).

Root cause fixed here: header comparisons took ``addr.rpartition("@")[2]`` of raw header text,
so ``<bounce@example.com>`` became ``example.com>`` and identical domains compared unequal.
Display names, comments, trailing dots and Unicode-vs-punycode forms caused the same class of
false mismatch.

All comparisons in the rule / forensics / auth paths now go through :func:`address_domain` and
:func:`normalize_mail_domain`. Alignment semantics are unchanged (callers keep their own exact or
org-domain comparison); only parsing and normalisation changed.

ML parity: the trained XGBoost model consumes rule contributions computed by the *legacy*
comparison. The original functions are kept, unchanged, in their modules
(``forensics.headers._legacy_dom`` and ``detection.fs_model._legacy_norm_domain``) and are
selected ONLY by ``app.ml.features.run_rules_offline`` via ``legacy_domain_compare=True``.
They are intentionally preserved to match training; remove them only together with a retrain.
"""
from __future__ import annotations

import re
from email.utils import getaddresses, parseaddr

HEADER_COMPARISON_VERSION = 2          # 1 = legacy (pre-P5d.1), 2 = parsed + normalised
_INVISIBLE_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")


def normalize_mail_domain(domain: str | None) -> str | None:
    """Lower-case, strip whitespace/invisible chars, brackets and trailing dots, IDNA → punycode."""
    if not domain:
        return None
    d = _INVISIBLE_RE.sub("", str(domain)).strip().strip("<>[]").strip().lower().rstrip(".")
    if not d:
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass                                # keep the lower-cased form rather than drop it
    return d or None


def address_domain(value: str | None) -> str | None:
    """Domain of the first address in a header value; None for empty / ``<>`` / no address.

    Handles ``Name <a@b.com>``, ``"Quoted, Name" <a@b.com>``, ``a@b.com (comment)``,
    ``<a@B.COM.>`` and the null reverse-path ``<>`` used by bounces.
    """
    if not value or not str(value).strip():
        return None
    _name, addr = parseaddr(str(value))
    if not addr or "@" not in addr:
        return None
    return normalize_mail_domain(addr.rpartition("@")[2])


def address_domains(value: str | None) -> list[str]:
    """Domains of every address in a (possibly multi-address) header value, in order."""
    if not value:
        return []
    out = []
    for _name, addr in getaddresses([str(value)]):
        if addr and "@" in addr:
            d = normalize_mail_domain(addr.rpartition("@")[2])
            if d:
                out.append(d)
    return out


def message_id_domain(value: str | None) -> str | None:
    """Right-hand side of a Message-ID (``<local@domain>``), normalised."""
    if not value or "@" not in value:
        return None
    return normalize_mail_domain(value.strip().strip("<>").rpartition("@")[2])
