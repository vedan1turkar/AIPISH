"""Audit-detail sanitiser (P5e): audit details never contain email bodies, subjects, recipient addresses,
passwords, tokens or keys. Applied by ``record_audit`` to every event before it is chained."""
from __future__ import annotations

import re
from typing import Any

FORBIDDEN_KEYS = re.compile(
    r"(password|passwd|secret|token|api_?key|authorization|cookie|body|subject|"
    r"to_emails|cc_emails|recipients?|reply_to_emails|from_email|display_name)", re.IGNORECASE)
ALLOWED_KEYS = {"key_required", "token_version", "username_attempted"}
EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
MAX_STR = 300


def mask_email(text: str) -> str:
    return EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            k = str(k)
            if FORBIDDEN_KEYS.search(k) and k not in ALLOWED_KEYS:
                out[k] = "[omitted]"
            else:
                out[k] = sanitize(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [sanitize(v, depth + 1) for v in list(value)[:200]]
    if isinstance(value, str):
        return mask_email(value)[:MAX_STR]
    return value
