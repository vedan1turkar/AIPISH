"""Parser unit tests: headers, addresses, MIME, URLs, attachments, defects."""
from pathlib import Path

from app.ingestion.parser import parse_eml

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eml"


def test_benign_parse() -> None:
    parsed = parse_eml((FIXTURES / "benign.eml").read_bytes())
    assert parsed.subject == "Quarterly report attached below"
    assert parsed.from_ is not None
    assert parsed.from_.email == "alice@example.com"
    assert parsed.from_.domain == "example.com"
    assert [a.email for a in parsed.to] == ["bob@example.net"]
    assert [a.email for a in parsed.cc] == ["carol@example.org"]
    assert parsed.message_id == "<benign-001@example.com>"
    assert "spf=pass" in parsed.authentication_results[0]
    assert parsed.raw_size_bytes > 0
    assert parsed.raw_sha256 and len(parsed.raw_sha256) == 64


def test_benign_body_and_urls() -> None:
    parsed = parse_eml((FIXTURES / "benign.eml").read_bytes())
    assert parsed.body_text is not None
    assert "quarterly numbers" in parsed.body_text
    urls = [u.url for u in parsed.urls]
    assert "https://example.com/reports/2026-q3" in urls
    benign_url = next(u for u in parsed.urls if u.url.startswith("https://example.com"))
    assert benign_url.in_text is True
    assert benign_url.in_html is False


def test_phishing_multipart() -> None:
    parsed = parse_eml((FIXTURES / "phishing_multipart.eml").read_bytes())
    # addresses
    assert parsed.from_ is not None
    assert parsed.from_.email == "account-alerts@paypa1-secure.com"
    assert parsed.from_.display_name == "PayPal Security Team"
    assert [a.email for a in parsed.reply_to] == ["watermark5682@fastmail-temp.net"]
    assert parsed.return_path == "<bounce@paypa1-secure.com>"
    # headers
    assert parsed.received_count == 1
    assert any("spf=fail" in r for r in parsed.authentication_results)
    # both parts present
    assert parsed.has_text_body and parsed.has_html_body
    assert "LIMITED" in (parsed.body_text or "")
    assert parsed.body_html is not None and "<b>LIMITED</b>" in parsed.body_html
    # URLs from both parts, deduped
    urls = [u.url for u in parsed.urls]
    assert "https://paypa1-secure.com/verify" in urls
    # attachment: hashed, size recorded, content never returned
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "statement.txt"
    assert att.size_bytes > 0
    assert len(att.sha256) == 64


def test_html_only_url_extracted() -> None:
    parsed = parse_eml((FIXTURES / "multipart_html.eml").read_bytes())
    urls = {u.url: u for u in parsed.urls}
    assert "https://bulletin.example/maintenance" in urls
    assert urls["https://bulletin.example/maintenance"].in_html is True


def test_malformed_never_raises() -> None:
    raw = (FIXTURES / "malformed.eml").read_bytes()
    parsed = parse_eml(raw)  # must not raise
    assert parsed.raw_size_bytes == len(raw)
    assert len(parsed.raw_sha256) == 64


def test_malformed_garbage_bytes() -> None:
    parsed = parse_eml(b"\x00\xff\xfe garbage \x93\x94 not an email at all")
    assert parsed.subject is None
    assert parsed.from_ is None
    assert len(parsed.raw_sha256) == 64


def test_empty_body_no_urls() -> None:
    parsed = parse_eml(
        b"From: a@b.c\r\nSubject: empty\r\n\r\n"
    )
    assert parsed.subject == "empty"
    assert parsed.urls == []


def test_url_dedupe_across_parts() -> None:
    raw = (
        b"From: a@b.c\r\nSubject: dup\r\n"
        b"Content-Type: multipart/alternative; boundary=\"X\"\r\n\r\n"
        b"--X\r\nContent-Type: text/plain\r\n\r\n"
        b"see https://dup.example/path\r\n"
        b"--X\r\nContent-Type: text/html\r\n\r\n"
        b"<a href=\"https://DUP.example/path\">x</a>\r\n"
        b"--X--\r\n"
    )
    parsed = parse_eml(raw)
    dup_urls = [u for u in parsed.urls if "dup.example" in u.url.lower()]
    assert len(dup_urls) == 1
    assert dup_urls[0].in_html and dup_urls[0].in_text


def test_attachment_hash_differs_from_raw() -> None:
    parsed = parse_eml((FIXTURES / "phishing_multipart.eml").read_bytes())
    att = parsed.attachments[0]
    assert att.sha256 != parsed.raw_sha256
