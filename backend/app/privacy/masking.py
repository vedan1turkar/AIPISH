"""Role-based personal-data masking (P5e). ONE serializer, used everywhere.

``mask_payload`` is applied
- by the ``pii_masking`` HTTP middleware to every JSON response under /api/v1 for a signed-in user whose
  role lacks ``pii:view`` (viewers), so new endpoints are covered automatically; and
- by the PDF report builder for the same roles ("MASKED VIEW").

What it masks (domains, IPs, hashes, verdicts, scores and evidence ids stay visible):
- email addresses anywhere in any string → first character of the local part + ``***@domain``;
- display names: values under ``display_name`` / ``from_display_name``, ``display_name_alias`` correlation
  entities/graph nodes, and the "(display name: …)" phrase used in evidence text → ``restricted``;
- message body: ``body_text`` → null with ``body_restricted: true``.
Every masked object gets ``pii_masked: true`` so the UI can show a "restricted for your role" state.
"""
from __future__ import annotations

import re
from typing import Any

from app.audit.sanitize import EMAIL

PII_PERMISSION = "pii:view"
RESTRICTED = "restricted"
_NAME_KEYS = {"display_name", "from_display_name"}
_BODY_KEYS = {"body_text", "body_preview"}
_ALIAS_TYPES = {"display_name_alias"}
_DISPLAY_PHRASE = re.compile(r"(display name:\s*)([^)\n]+)", re.IGNORECASE)


def _mask_text(s: str) -> str:
    s = EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", s)
    return _DISPLAY_PHRASE.sub(lambda m: m.group(1) + (m.group(2) if m.group(2).strip().lower() == "none" else RESTRICTED), s)


def mask_payload(value: Any) -> Any:
    """Return a masked deep copy. Pure function; never raises on unexpected shapes."""
    if isinstance(value, list):
        return [mask_payload(v) for v in value]
    if isinstance(value, str):
        return _mask_text(value)
    if not isinstance(value, dict):
        return value
    out: dict = {}
    masked = False
    alias = str(value.get("type") or value.get("kind") or value.get("entity_type") or "") in _ALIAS_TYPES
    for k, v in value.items():
        if k in _BODY_KEYS:
            out[k] = None
            out["body_restricted"] = True
            masked = True
        elif k in _NAME_KEYS and isinstance(v, str) and v.strip():
            out[k] = RESTRICTED
            masked = True
        elif alias and k in ("value", "label", "normalized_value") and isinstance(v, str):
            out[k] = RESTRICTED
            masked = True
        else:
            mv = mask_payload(v)
            masked = masked or (isinstance(v, str) and mv != v)
            out[k] = mv
    if masked:
        out["pii_masked"] = True
    return out


def role_sees_pii(role: str | None) -> bool:
    from app.security.permissions import role_allows
    return bool(role) and role_allows(role, PII_PERMISSION)
