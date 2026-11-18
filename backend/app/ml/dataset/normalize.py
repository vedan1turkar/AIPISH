"""Turn one raw RFC 5322 message into a normalised, source-neutral record.

The same rules apply to every source so that a model cannot learn which
corpus a message came from via formatting artefacts:
- body: text/plain parts preferred, otherwise HTML converted to text;
- e-mail addresses in subject/body -> "<EMAIL>", URLs -> "<URL>" (the URL
  hosts are kept separately in `url_hosts`);
- Unicode NFC, invisible characters removed, whitespace collapsed;
- the recipient is never stored (Nazario/SpamAssassin sanitise it
  differently, which would otherwise leak the source).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import html
import re
import unicodedata
from dataclasses import dataclass
from email import message_from_bytes
from email.message import Message
from email.policy import compat32
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_BODY_CHARS = 20_000
MIN_BODY_CHARS = 20

_URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'`)\]]+""", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+'-]+@[\w-]+(?:\.[\w-]+)+")
_INVISIBLE_RE = re.compile(r"[​‌‍⁠﻿­]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_NL_RE = re.compile(r"\n{3,}")
_SUBJ_PREFIX_RE = re.compile(r"^\s*((re|fw|fwd|aw|tr)\s*(\[\d+\])?\s*:\s*)+", re.IGNORECASE)


@dataclass(frozen=True)
class RawMessage:
    source: str
    source_file: str
    source_member: str  # path inside archive or mbox index
    original_label: str
    raw: bytes
    synthetic_template: str | None = None  # template id for synthetic samples


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "head", "title"}
    _BLOCK = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "table", "hr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.hrefs: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip += 1
        if tag in self._BLOCK:
            self.parts.append("\n")
        if tag == "a":
            for k, v in attrs:
                if k == "href" and v:
                    self.hrefs.append(v)

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(markup: str) -> tuple[str, list[str]]:
    p = _TextExtractor()
    try:
        p.feed(markup)
        p.close()
    except Exception:  # malformed markup: fall back to tag stripping
        return html.unescape(re.sub(r"<[^>]+>", " ", markup)), []
    return "".join(p.parts), p.hrefs


def _decode(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "latin-1"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("latin-1", errors="replace")


def _header(msg: Message, name: str) -> str:
    value = msg.get(name)
    if value is None:
        return ""
    try:
        from email.header import decode_header, make_header
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def clean_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = _INVISIBLE_RE.sub("", text)
    text = _CONTROL_RE.sub(" ", text).replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(_WS_RE.sub(" ", line).strip() for line in text.split("\n"))
    return _NL_RE.sub("\n\n", text).strip()


def mask(text: str) -> str:
    text = _URL_RE.sub("<URL>", text)
    return _EMAIL_RE.sub("<EMAIL>", text)


def canonical_subject(subject: str) -> str:
    return _WS_RE.sub(" ", _SUBJ_PREFIX_RE.sub("", subject)).strip().lower()


def _host(url: str) -> str | None:
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def _parse_date(value: str) -> str | None:
    if not value:
        return None
    try:
        d = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if d is None:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    if not (1990 <= d.year <= 2027):
        return None
    return d.astimezone(dt.timezone.utc).isoformat(timespec="seconds")


def _msgid(value: str) -> str | None:
    m = re.search(r"<([^<>\s]+)>", value or "")
    return m.group(1).lower() if m else None


class Excluded(Exception):
    """Message rejected by a documented preprocessing rule."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def normalize(rm: RawMessage) -> dict:
    """Return a normalised record or raise Excluded(reason)."""
    try:
        msg = message_from_bytes(rm.raw, policy=compat32)
    except Exception as exc:  # pragma: no cover - compat32 is very tolerant
        raise Excluded("parse_error") from exc
    if not msg.keys():
        raise Excluded("no_headers")
    subject = _header(msg, "Subject")
    if "FOLDER INTERNAL DATA" in subject:
        raise Excluded("mbox_internal_record")

    plain, htmls, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        if "attachment" in disp or part.get_filename():
            name = part.get_filename() or ""
            attachments.append(name.rsplit(".", 1)[-1].lower() if "." in name else "")
            continue
        if ctype == "text/plain":
            plain.append(_decode(part))
        elif ctype == "text/html":
            htmls.append(_decode(part))

    hrefs: list[str] = []
    html_text = []
    for h in htmls:
        t, hr = html_to_text(h)
        html_text.append(t)
        hrefs.extend(hr)
    body_raw = "\n".join(plain) if any(p.strip() for p in plain) else "\n".join(html_text)
    body_clean = clean_text(body_raw)
    url_hosts = sorted({h for u in _URL_RE.findall(body_raw) + hrefs if (h := _host(u))})
    body = clean_text(mask(body_clean))[:MAX_BODY_CHARS]
    if len(body) < MIN_BODY_CHARS:
        raise Excluded("empty_or_tiny_body")

    subj = clean_text(mask(subject))
    froms = getaddresses([_header(msg, "From")])
    from_addr = froms[0][1].lower() if froms and froms[0][1] else ""
    from_domain = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
    refs = [_msgid(x) for x in re.findall(r"<[^<>\s]+>", _header(msg, "References"))]
    in_reply = _msgid(_header(msg, "In-Reply-To"))

    norm_key = (canonical_subject(subj) + "\n" + _WS_RE.sub(" ", body.lower())).encode()
    return {
        "source": rm.source,
        "source_file": rm.source_file,
        "source_member": rm.source_member,
        "original_label": rm.original_label,
        "is_synthetic": rm.source == "synthetic",
        "synthetic_template": rm.synthetic_template,
        "raw_sha256": hashlib.sha256(rm.raw).hexdigest(),
        "norm_sha256": hashlib.sha256(norm_key).hexdigest(),
        "date": _parse_date(_header(msg, "Date")),
        "from_address_sha256": hashlib.sha256(from_addr.encode()).hexdigest() if from_addr else "",
        "from_domain": from_domain,
        "subject": subj,
        "subject_canonical": canonical_subject(subj),
        "body": body,
        "url_hosts": url_hosts,
        "n_urls": len(url_hosts),
        "has_html": bool(htmls),
        "attachment_exts": sorted(attachments),
        "message_id": _msgid(_header(msg, "Message-ID")),
        "thread_refs": sorted({r for r in refs + [in_reply] if r}),
    }
