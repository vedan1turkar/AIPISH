"""Modular .eml parser built on Python's standard ``email`` package.

Design constraints (per requirements):
- stdlib only (``email``, ``hashlib``, ``re``, ``urllib.parse``)
- never executes attachments, never fetches URLs
- preserves raw bytes for hashing/evidence integrity
- returned structures contain metadata only, never attachment contents
- safe handling of malformed MIME: defects are recorded, never raised
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import default as default_policy
from urllib.parse import urlsplit

# ── Regexes (compiled once) ────────────────────────────────────────────────
_URL_RE = re.compile(
    r"""https?://[^\s<>"'`]+|www\.[^\s<>"'`]+""",
    re.IGNORECASE,
)
# Base64/quoted-printable wrappers already decoded by the email package; we
# still strip residual HTML entity noise.
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Obfuscation decoys: zero-width and invisible chars inside body text.
_INVISIBLE_CHARS_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


class ParseTimeout(Exception):
    """Raised when parsing exceeds the wall-clock budget (DoS guard)."""


@dataclass
class ParsedAddress:
    display_name: str
    email: str
    domain: str


@dataclass
class ParsedAttachment:
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    is_inline: bool
    content_id: str | None


@dataclass
class ParsedUrl:
    url: str
    host: str
    scheme: str
    in_html: bool
    in_text: bool


@dataclass
class HopData:
    # raw lines for forensics; parsing into from/by/ip happens later
    raw: str
    index: int


@dataclass
class ParsedEmail:
    # raw evidence
    raw_sha256: str
    raw_size_bytes: int

    # identity & meta
    subject: str | None = None
    date: str | None = None
    message_id: str | None = None
    from_: ParsedAddress | None = None
    to: list[ParsedAddress] = field(default_factory=list)
    cc: list[ParsedAddress] = field(default_factory=list)
    reply_to: list[ParsedAddress] = field(default_factory=list)
    return_path: str | None = None
    has_text_body: bool = False
    has_html_body: bool = False

    # routing & auth
    received: list[HopData] = field(default_factory=list)
    received_count: int = 0
    authentication_results: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)

    # content
    body_text: str | None = None
    body_html: str | None = None
    urls: list[ParsedUrl] = field(default_factory=list)
    attachments: list[ParsedAttachment] = field(default_factory=list)
    # count of URLs that contained invisible/zero-width obfuscation chars in
    # the *original* text (before the parser sanitised them out)
    obfuscated_url_count: int = 0

    # integrity of the parse itself
    parse_defects: list[str] = field(default_factory=list)

    # header summary (name → list of values), excluding bulky/binary ones
    headers: dict[str, list[str]] = field(default_factory=dict)

    # raw headers copied verbatim into a dict so forensic modules can differ
    header_counts: dict[str, int] = field(default_factory=dict)


# ── Internal helpers ───────────────────────────────────────────────────────

def _addr(obj: object) -> ParsedAddress:
    name = getattr(obj, "display_name", None) or ""
    addr = getattr(obj, "addr_spec", None) or ""
    domain = addr.rpartition("@")[2].lower() if "@" in addr else ""
    return ParsedAddress(display_name=name, email=addr, domain=domain)


def _unwrap(value: str | None) -> str | None:
    """Collapse whitespace and fold lines from header values."""
    if value is None:
        return None
    return re.sub(r"\s+", " ", value).strip()


def _safe_filename(filename: str | None) -> str:
    """Filename that is never an absolute path or traversal — drop path parts."""
    if not filename:
        return "unnamed"
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    return base or "unnamed"


def _INVISIBLE_RE_IN_URL(m: str) -> bool:
    """True if the matched URL contained at least one invisible character."""
    return bool(_INVISIBLE_CHARS_RE.search(m))


def _clean_text(text: str) -> str:
    text = _INVISIBLE_CHARS_RE.sub("", text)
    text = _CONTROL_CHARS_RE.sub(" ", text)
    return text.strip()


def _extract_urls(text: str, in_html: bool) -> list[ParsedUrl]:
    urls: dict[str, ParsedUrl] = {}
    for match in _URL_RE.finditer(text):
        raw = match.group(0)
        if raw.lower().startswith("www."):
            raw = "http://" + raw
        # strip trailing punctuation common in prose
        raw = raw.rstrip(".,;:!?)]}>\"'")
        parsed = urlsplit(raw)
        if not parsed.netloc:
            continue
        key = raw.lower()
        if key in urls:
            existing = urls[key]
            existing.in_html = existing.in_html or in_html
            existing.in_text = existing.in_text or not in_html
            continue
        urls[key] = ParsedUrl(url=raw, host=parsed.hostname or "", scheme=parsed.scheme, in_html=in_html, in_text=not in_html)
    return list(urls.values())


def _html_to_text(html: str) -> str:
    text = _HTML_COMMENT_RE.sub("", html)
    text = _HTML_TAG_RE.sub(" ", text)
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def _walk_parts(msg: Message, parsed: ParsedEmail) -> None:
    urls_by_key: dict[str, ParsedUrl] = {}
    text_parts = 0
    html_parts = 0
    text_chunks: list[str] = []
    html_chunks: list[str] = []
    obfuscated_url_count = 0

    for part in msg.walk():
        cte = part.get_content_type()
        disp = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename()
        is_attachment = "attachment" in disp or (filename is not None and cte != "multipart/*")

        if is_attachment:
            # ── attachment: hash bytes, never return them ──
            payload = b""
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001 — malformed encodings must not crash the parse
                parsed.parse_defects.append(f"attachment-decode-error:{_safe_filename(filename)}")
            digest = hashlib.sha256(payload).hexdigest()
            parsed.attachments.append(
                ParsedAttachment(
                    filename=_safe_filename(filename),
                    content_type=cte,
                    size_bytes=len(payload),
                    sha256=digest,
                    is_inline="inline" in disp,
                    content_id=part.get("Content-ID"),
                )
            )
            continue

        if cte == "text/plain":
            text_parts += 1
            try:
                data = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                decoded = data.decode(charset, errors="replace")
            except Exception:  # noqa: BLE001
                parsed.parse_defects.append("text-part-decode-error")
                decoded = ""
            text_chunks.append(decoded)
            body_text = _clean_text(decoded)
            # count obfuscated (zero-width char) URLs in the ORIGINAL text
            # before sanitisation: the cleaned copy has had them stripped.
            obfuscated_url_count += sum(1 for m in _URL_RE.finditer(decoded) if _INVISIBLE_RE_IN_URL(m.group(0)))
            for u in _extract_urls(body_text, in_html=False):
                if u.url.lower() in urls_by_key:
                    urls_by_key[u.url.lower()].in_text = True
                else:
                    urls_by_key[u.url.lower()] = u
        elif cte == "text/html":
            html_parts += 1
            try:
                data = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                decoded = data.decode(charset, errors="replace")
            except Exception:  # noqa: BLE001
                parsed.parse_defects.append("html-part-decode-error")
                decoded = ""
            html_chunks.append(decoded)
            for u in _extract_urls(decoded, in_html=True):
                if u.url.lower() in urls_by_key:
                    urls_by_key[u.url.lower()].in_html = True
                else:
                    urls_by_key[u.url.lower()] = u

    # merge URL maps back
    parsed.urls = list(urls_by_key.values())
    parsed.obfuscated_url_count = obfuscated_url_count

    if text_parts > 0:
        parsed.has_text_body = True
    if html_parts > 0:
        parsed.has_html_body = True
    if text_chunks:
        joined = "\n\n".join(_clean_text(c) for c in text_chunks)
        parsed.body_text = joined or None
    if html_chunks:
        joined = "\n\n".join(html_chunks)
        parsed.body_html = joined or None
        # derive fallback text from html when there is no plain part
        if not parsed.body_text:
            parsed.body_text = _clean_text(_html_to_text(joined)) or None


def parse_eml(raw: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a :class:`ParsedEmail`.

    Never raises for message content; malformed input produces
    ``parse_defects`` entries instead. Raises nothing for OOM-type limits
    (caller enforces size caps before this).
    """
    raw_size = len(raw)
    digest = hashlib.sha256(raw).hexdigest()

    parser = BytesParser(policy=default_policy)
    # Ideally a strict→defect policy walk; stdlib records defects instead of
    # raising by default, which is what we want.
    msg = parser.parsebytes(raw)

    parsed = ParsedEmail(raw_sha256=digest, raw_size_bytes=raw_size)

    # header defects from the parser itself
    try:
        for defect in getattr(msg, "defects", []):
            parsed.parse_defects.append(f"header:{type(defect).__name__}")
    except Exception:  # noqa: BLE001
        pass

    # ── headers ──
    counts: dict[str, int] = {}
    for key, value in msg.items():
        key_l = key.lower()
        counts[key_l] = counts.get(key_l, 0) + 1
        sval = _unwrap(str(value))
        if sval is not None:
            parsed.headers.setdefault(key_l, []).append(sval)

        if key_l == "subject":
            parsed.subject = sval
        elif key_l == "date":
            parsed.date = sval
        elif key_l == "message-id":
            parsed.message_id = sval
        elif key_l == "return-path":
            parsed.return_path = sval
        elif key_l == "received":
            parsed.received.append(HopData(raw=sval or "", index=len(parsed.received)))
        elif key_l == "authentication-results":
            parsed.authentication_results.append(sval or "")
        elif key_l == "dkim-signature":
            parsed.dkim_signatures.append(sval or "")

    parsed.header_counts = counts
    parsed.received_count = len(parsed.received)

    # ── addresses ──
    def _addrs(field_name: str) -> list[ParsedAddress]:
        out: list[ParsedAddress] = []
        val = msg.get(field_name)
        if val is None:
            return out
        try:
            import email.utils as _utils

            for a in _utils.getaddresses([str(val)]):
                addr = _addr(type("A", (), {"display_name": a[0], "addr_spec": a[1]})())
                if addr.email:
                    out.append(addr)
        except Exception:  # noqa: BLE001
            parsed.parse_defects.append(f"address-parse-error:{field_name}")
        return out

    parsed.from_ = _addrs("From")[0] if _addrs("From") else None
    parsed.to = _addrs("To")
    parsed.cc = _addrs("Cc")
    parsed.reply_to = _addrs("Reply-To")

    _walk_parts(msg, parsed)
    return parsed
