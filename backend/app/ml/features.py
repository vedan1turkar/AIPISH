"""Feature extraction shared by training and inference (train/serve parity).

Every model input is derived from the same normalised record produced by
`app.ml.dataset.normalize.normalize` (masked subject/body, URL hosts, ...)
plus, optionally, the existing 18-rule engine run offline on the raw bytes.
"""
from __future__ import annotations

import ipaddress
import re

from app.detection.config import get_config
from app.ml.dataset.normalize import RawMessage, normalize

MAX_TEXT_CHARS = 4000
RULE_IDS: tuple[str, ...] = tuple(get_config().weights)  # the 18 weighted rules, fixed order

_RISKY_EXT = frozenset({"exe", "scr", "js", "vbs", "bat", "cmd", "com", "pif", "jar", "hta",
                        "html", "htm", "zip", "rar", "iso", "docm", "xlsm"})
_WORD_RE = re.compile(r"[A-Za-z]{2,}")

STRUCTURED_NAMES: tuple[str, ...] = (
    "n_url_hosts", "has_url", "url_ip_host", "url_many_subdomains", "url_host_has_digit",
    "url_host_has_hyphen", "has_html", "n_attachments", "risky_attachment",
    "body_chars_log", "subject_chars", "n_url_tokens", "n_email_tokens",
    "upper_ratio", "exclaim_count", "digit_ratio", "subject_upper_ratio", "has_sender_domain",
)


def text_input(rec: dict) -> str:
    """The text the NLP models see: masked subject + masked body."""
    return (rec.get("subject", "") + "\n\n" + rec.get("body", ""))[:MAX_TEXT_CHARS]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def structured_features(rec: dict) -> list[float]:
    import math
    hosts = rec.get("url_hosts") or []
    body = rec.get("body", "")
    subject = rec.get("subject", "")
    letters = [c for c in body if c.isalpha()]
    s_letters = [c for c in subject if c.isalpha()]
    exts = rec.get("attachment_exts") or []
    feats = {
        "n_url_hosts": float(len(hosts)),
        "has_url": float(bool(hosts)),
        "url_ip_host": float(any(_is_ip(h) for h in hosts)),
        "url_many_subdomains": float(any(h.count(".") >= 3 for h in hosts)),
        "url_host_has_digit": float(any(any(c.isdigit() for c in h) and not _is_ip(h) for h in hosts)),
        "url_host_has_hyphen": float(any("-" in h for h in hosts)),
        "has_html": float(bool(rec.get("has_html"))),
        "n_attachments": float(len(exts)),
        "risky_attachment": float(any(e in _RISKY_EXT for e in exts)),
        "body_chars_log": math.log1p(len(body)),
        "subject_chars": float(len(subject)),
        "n_url_tokens": float(body.count("<URL>")),
        "n_email_tokens": float(body.count("<EMAIL>")),
        "upper_ratio": sum(c.isupper() for c in letters) / len(letters) if letters else 0.0,
        "exclaim_count": float(body.count("!") + subject.count("!")),
        "digit_ratio": sum(c.isdigit() for c in body) / len(body) if body else 0.0,
        "subject_upper_ratio": sum(c.isupper() for c in s_letters) / len(s_letters) if s_letters else 0.0,
        "has_sender_domain": float(bool(rec.get("from_domain"))),
    }
    return [feats[n] for n in STRUCTURED_NAMES]


def run_rules_offline(raw: bytes) -> dict:
    """The existing 18-rule engine on raw bytes, offline (no DNS/auth/enrichment).

    Mirrors the upload pipeline minus live lookups: parse -> header forensics
    (medium/high findings bridge in) -> run_detection.

    ML PARITY (P5d.1): this is the ML *feature* path. It deliberately uses the legacy pre-P5d.1
    address-domain comparison (``legacy_domain_compare=True``) because the trained model's rule
    features were computed that way. Do not change without retraining. For rule output shown to
    people, use :func:`run_rules_offline_current`.
    """
    from app.detection import run_detection
    from app.forensics.headers import run_header_forensics
    from app.ingestion.parser import parse_eml

    try:
        parsed = parse_eml(raw)
        forensics = run_header_forensics(parsed, legacy_domain_compare=True)
        consequential = [i.rule_id for i in forensics.inconsistencies if i.severity in ("medium", "high")]
        return run_detection(parsed, forensic_inconsistencies=consequential, legacy_domain_compare=True).to_dict()
    except Exception as exc:  # the parser can fail on some real-world headers
        return {"error": f"{type(exc).__name__}: {exc}"[:200]}


def run_rules_offline_current(raw: bytes) -> dict:
    """The rule engine offline with the current (fixed) address comparison — for display only,
    never as model features."""
    from app.detection import run_detection
    from app.forensics.headers import run_header_forensics
    from app.ingestion.parser import parse_eml

    try:
        parsed = parse_eml(raw)
        forensics = run_header_forensics(parsed)
        consequential = [i.rule_id for i in forensics.inconsistencies if i.severity in ("medium", "high")]
        return run_detection(parsed, forensic_inconsistencies=consequential).to_dict()
    except Exception as exc:  # the parser can fail on some real-world headers
        return {"error": f"{type(exc).__name__}: {exc}"[:200]}


def rule_features(detection: dict) -> list[float]:
    """18 per-rule contributions (0 if not fired) + the bounded total score.

    If the rule engine failed on this message every value is NaN (missing,
    which XGBoost handles natively) rather than a fabricated "no rule fired"."""
    if "error" in detection:
        return [float("nan")] * (len(RULE_IDS) + 1)
    fired = {f["rule_id"]: float(f["contribution"]) for f in detection.get("findings", [])}
    return [fired.get(r, 0.0) for r in RULE_IDS] + [float(detection.get("score", 0))]


RULE_FEATURE_NAMES: tuple[str, ...] = tuple(f"rule_{r}" for r in RULE_IDS) + ("rule_score",)


def record_from_raw(raw: bytes) -> dict:
    """Normalise an arbitrary .eml exactly as the training corpus was normalised.

    Raises app.ml.dataset.normalize.Excluded for messages the corpus would
    also have excluded (e.g. empty body)."""
    return normalize(RawMessage("inference", "upload", "-", "unknown", raw))
