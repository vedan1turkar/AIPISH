"""Parser cross-check (P5k-lite, R43): parse the same raw bytes with a second, independent parser
(mail-parser, which uses the stdlib compat32 policy) and compare normalised views with the primary parse
(stdlib email with ``policy=default``, ``app.ingestion.parser``).

INFORMATIONAL ONLY: the result never feeds the rule score, ML features, risk index or alerts.

Parser differentials can indicate evasion attempts (a gateway and a mail client reading different senders,
attachments or MIME structure) but are often harmless (decoding or folding differences).

The stored result holds field names, counts, severities and system-written descriptions only. It never
contains addresses, subjects, bodies, file names or header values, so it is safe for every role.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import logging
import re
from email import policy as email_policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from app.core.config import env

SECONDARY = "mail-parser"
PRIMARY = "python email (policy=default)"
SINGLE_INSTANCE = ("from", "sender", "reply-to", "to", "cc", "subject", "date", "message-id", "return-path",
                   "mime-version", "content-type")
SECURITY_DUPLICATES = ("from", "return-path", "reply-to", "sender")
_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]|\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="parser-crosscheck")
logging.getLogger("mailparser").setLevel(logging.ERROR)     # the library logs unhandled content types per message
NOTE = ("Informational: compares two independent parsers over the same bytes. Differences can indicate parser-"
        "differential evasion but are often harmless decoding differences. It never changes the rule score, ML "
        "output, combined risk or alerts.")


def _max_bytes() -> int:
    try:
        return int(float(env("PARSER_CROSSCHECK_MAX_MB", "10") or "10") * 1024 * 1024)
    except ValueError:
        return 10 * 1024 * 1024


def _timeout() -> float:
    try:
        return max(0.5, float(env("PARSER_CROSSCHECK_TIMEOUT_SECONDS", "5") or "5"))
    except ValueError:
        return 5.0


def _version() -> str | None:
    try:
        from importlib.metadata import version
        return version("mail-parser")
    except Exception:  # noqa: BLE001
        return None


# ── normalisation helpers ────────────────────────────────────────────────────
def _addr_list(values) -> list[str]:
    return sorted({a.strip().lower() for _n, a in values if a and "@" in a})


def _norm_path(v: str | None) -> str | None:
    if not v:
        return None
    _n, a = getaddresses([v])[0] if getaddresses([v]) else ("", v)
    a = (a or v).strip().strip("<>").strip().lower()
    return a or None


def _norm_date(v) -> str | None:
    if v is None:
        return None
    try:
        dt = v if hasattr(v, "isoformat") else parsedate_to_datetime(str(v))
        if dt.tzinfo is None:
            return dt.replace(microsecond=0).isoformat() + "naive"
        return dt.astimezone(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat()
    except Exception:  # noqa: BLE001
        return "unparseable"


def _norm_text(v) -> str | None:
    if v is None:
        return None
    return hashlib.sha256(" ".join(str(v).split()).encode("utf-8", "replace")).hexdigest()


def _hop(text: str) -> tuple[str, tuple[str, ...]]:
    """(by-host, sorted IPs in the from-clause) for one Received value, lower-cased."""
    t = " ".join(str(text or "").split())
    by = re.search(r"\bby\s+([^\s;()]+)", t, re.I)
    frm = re.split(r"\bby\s", t, maxsplit=1, flags=re.I)[0]
    ips = tuple(sorted({(m.group(1) or m.group(2)).lower() for m in _IP_RE.finditer(frm)}))
    return ((by.group(1).lower() if by else ""), ips)


def _leaf_parts(msg) -> list:
    return [p for p in msg.walk() if not p.is_multipart()]


def _structure(msg) -> dict:
    leaves = _leaf_parts(msg)
    return {"leaf_parts": len(leaves), "multipart_depth": _depth(msg),
            "charsets": sorted({(p.get_content_charset() or "").lower() for p in leaves if p.get_content_charset()}),
            "defects": sorted({type(d).__name__ for p in msg.walk() for d in getattr(p, "defects", [])})}


def _depth(msg, d: int = 0) -> int:
    if not msg.is_multipart():
        return d
    return max([_depth(p, d + 1) for p in msg.get_payload() if hasattr(p, "is_multipart")] or [d + 1])


def _raw_header_counts(raw: bytes) -> dict[str, int]:
    """Count header field names in the top-level header block (independent of both parsers)."""
    head = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0]
    counts: dict[str, int] = {}
    for line in re.split(rb"\r?\n", head):
        if not line or line[:1] in (b" ", b"\t"):
            continue
        m = re.match(rb"([!-9;-~]+)\s*:", line)
        if m:
            k = m.group(1).decode("ascii", "replace").lower()
            counts[k] = counts.get(k, 0) + 1
    return counts


# ── views ───────────────────────────────────────────────────────────────────
def primary_view(raw: bytes, parsed) -> dict:
    msg = BytesParser(policy=email_policy.default).parsebytes(raw)
    atts = [{"type": (a.content_type or "").lower(), "size": int(a.size_bytes or 0), "sha256": a.sha256,
             "name": hashlib.sha256((a.filename or "").strip().lower().encode()).hexdigest()}
            for a in parsed.attachments if not a.is_inline]
    return {
        "from": [parsed.from_.email.lower()] if parsed.from_ and parsed.from_.email else [],
        "to": sorted({a.email.lower() for a in parsed.to if a.email}),
        "cc": sorted({a.email.lower() for a in parsed.cc if a.email}),
        "reply_to": sorted({a.email.lower() for a in parsed.reply_to if a.email}),
        "return_path": _norm_path(parsed.return_path),
        "subject": _norm_text(parsed.subject),
        "date": _norm_date(msg["date"].datetime if msg["date"] is not None and getattr(msg["date"], "datetime", None)
                           else parsed.date),
        "message_id": (parsed.message_id or "").strip().strip("<>").lower() or None,
        "received": [_hop(h.raw) for h in parsed.received],
        "attachments": sorted(atts, key=lambda a: (a["sha256"] or "", a["name"])),
        **_structure(msg),
    }


def secondary_view(raw: bytes) -> dict:
    import mailparser
    m = mailparser.parse_from_bytes(raw)
    atts = []
    for a in m.attachments or []:
        if (a.get("content-disposition") or "").lower().startswith("inline") and a.get("content-id"):
            continue
        payload = a.get("payload") or ""
        try:
            data = base64.b64decode(payload) if a.get("binary") else payload.encode(a.get("charset") or "utf-8", "replace")
        except Exception:  # noqa: BLE001
            data = str(payload).encode()
        atts.append({"type": (a.get("mail_content_type") or "").lower(), "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest(),
                     "name": hashlib.sha256((a.get("filename") or "").strip().lower().encode()).hexdigest()})
    hops = [_hop(f"from {r.get('from') or ''} by {r.get('by') or ''}") for r in reversed(m.received or [])]
    hdr = m.message
    return {
        "from": _addr_list(m.from_ or []),
        "to": _addr_list(m.to or []),
        "cc": _addr_list(m.cc or []),
        "reply_to": _addr_list(m.reply_to or []),
        "return_path": _norm_path(hdr.get("Return-Path")),
        "subject": _norm_text(m.subject) if hdr.get("Subject") is not None else None,
        "date": _norm_date(m.date),
        "message_id": (m.message_id or "").strip().strip("<>").lower() or None,
        "received": hops,
        "attachments": sorted(atts, key=lambda a: (a["sha256"] or "", a["name"])),
        **_structure(hdr),
    }


# ── comparison ──────────────────────────────────────────────────────────────
def compare(a: dict, b: dict, raw_counts: dict[str, int]) -> list[dict]:
    diffs: list[dict] = []

    def add(field: str, severity: str, description: str) -> None:
        diffs.append({"field": field, "severity": severity, "description": description})

    for f, label, sev in (("from", "From address", "security_relevant"),
                          ("reply_to", "Reply-To address", "security_relevant"),
                          ("to", "To recipients", "info"), ("cc", "Cc recipients", "info")):
        if a[f] != b[f]:
            add(f, sev, f"{label} differs between parsers ({len(a[f])} vs {len(b[f])} address(es)).")
    if a["return_path"] != b["return_path"]:
        add("return_path", "security_relevant", "Return-Path differs between parsers.")
    for f, label in (("subject", "Subject"), ("date", "Date"), ("message_id", "Message-ID")):
        if a[f] != b[f]:
            add(f, "info", f"{label} decodes differently between parsers (value not stored).")
    ra, rb = a["received"], b["received"]
    if len(ra) != len(rb):
        add("received", "security_relevant", f"Received chain length differs ({len(ra)} vs {len(rb)} hops).")
    elif ra != rb:
        if sorted(ra) == sorted(rb):
            add("received", "security_relevant", "Received hops are the same but in a different order.")
        else:
            n = sum(1 for x, y in zip(ra, rb) if x != y)
            add("received", "security_relevant", f"{n} Received hop(s) differ in relay host or IP between parsers.")
    aa, ab = a["attachments"], b["attachments"]
    if len(aa) != len(ab):
        add("attachments", "security_relevant", f"Attachment count differs ({len(aa)} vs {len(ab)}).")
    else:
        if [x["sha256"] for x in aa] != [x["sha256"] for x in ab] or [x["size"] for x in aa] != [x["size"] for x in ab]:
            add("attachments", "security_relevant", "Attachment content (SHA-256 or size) differs between parsers.")
        if [x["type"] for x in aa] != [x["type"] for x in ab]:
            add("attachments", "security_relevant", "Attachment content type differs between parsers.")
        if [x["name"] for x in aa] != [x["name"] for x in ab]:
            add("attachments", "info", "Attachment file name decodes differently (names not stored).")
    if a["leaf_parts"] != b["leaf_parts"] or a["multipart_depth"] != b["multipart_depth"]:
        add("mime_structure", "security_relevant",
            f"MIME structure differs ({a['leaf_parts']} vs {b['leaf_parts']} body parts, nesting depth "
            f"{a['multipart_depth']} vs {b['multipart_depth']}).")
    if a["charsets"] != b["charsets"]:
        add("charsets", "info", "Declared body charsets differ between parsers.")
    boundary = {"StartBoundaryNotFoundDefect", "CloseBoundaryNotFoundDefect", "MultipartInvariantViolationDefect",
                "MissingHeaderBodySeparatorDefect", "MisplacedEnvelopeHeaderDefect"}
    amb = sorted(set(a["defects"] + b["defects"]) & boundary)
    if amb:
        add("mime_structure", "security_relevant", f"MIME boundary/nesting ambiguity reported: {', '.join(amb)}.")
    for h in SINGLE_INSTANCE:
        n = raw_counts.get(h, 0)
        if n > 1:
            add(f"duplicate_header:{h}", "security_relevant" if h in SECURITY_DUPLICATES else "info",
                f"Single-instance header '{h}' appears {n} times; parsers may pick different instances.")
    for i, d in enumerate(diffs, 1):
        d["evidence_id"] = f"P{i}"
    return diffs


def _status(diffs: list[dict]) -> str:
    if not diffs:
        return "agree"
    return "security_relevant_differences" if any(d["severity"] == "security_relevant" for d in diffs) \
        else "minor_differences"


def _run(raw: bytes, parsed) -> dict:
    a = primary_view(raw, parsed)
    b = secondary_view(raw)
    diffs = compare(a, b, _raw_header_counts(raw))
    return {"status": _status(diffs), "differences": diffs,
            "compared": {"received_hops": [len(a["received"]), len(b["received"])],
                         "attachments": [len(a["attachments"]), len(b["attachments"])],
                         "body_parts": [a["leaf_parts"], b["leaf_parts"]]}}


def unavailable(reason: str) -> dict:
    return {"status": "unavailable", "reason": reason[:200], "differences": [], "compared": None}


def run_crosscheck(raw: bytes, parsed) -> dict:
    """Bounded and failure-isolated. Never raises."""
    base = {"primary": PRIMARY, "secondary": SECONDARY, "secondary_version": _version(), "note": NOTE}
    try:
        if len(raw) > _max_bytes():
            return {**base, **unavailable(f"cross-check unavailable: message larger than the "
                                          f"{_max_bytes() // (1024 * 1024)} MB cross-check limit")}
        try:
            import mailparser  # noqa: F401
        except Exception as exc:  # noqa: BLE001 — ImportError or a broken install
            return {**base, **unavailable(f"cross-check unavailable: mail-parser could not be imported "
                                          f"({type(exc).__name__})")}
        fut = _EXECUTOR.submit(_run, raw, parsed)
        try:
            res = fut.result(timeout=_timeout())
        except concurrent.futures.TimeoutError:
            return {**base, **unavailable(f"cross-check unavailable: exceeded {_timeout():.0f}s")}
        return {**base, **res}
    except Exception as exc:  # noqa: BLE001
        return {**base, **unavailable(f"cross-check unavailable: parse failed ({type(exc).__name__})")}
