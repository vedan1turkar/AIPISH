"""Password hashing (stdlib scrypt) and password policy.

Format: ``scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>`` with a 16-byte random
per-user salt and a 32-byte derived key. Verification is constant time
(``hmac.compare_digest``). No password material is ever logged or returned.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string

N, R, P = 2 ** 15, 8, 1          # ~32 MiB memory per hash
DKLEN = 32
MAXMEM = 64 * 1024 * 1024
MIN_LEN, MAX_LEN = 12, 128

# Small built-in deny list; the length/variety rules below catch most trivial passwords.
_COMMON = {
    "password", "password1", "password123", "password1234", "passw0rd", "qwerty", "qwertyuiop",
    "letmein", "welcome", "welcome1", "admin", "administrator", "changeme", "iloveyou", "monkey",
    "dragon", "football", "baseball", "sunshine", "princess", "trustno1", "abc123", "123456",
    "aipish", "phishing", "forensics",
}


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=MAXMEM, dklen=DKLEN)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(_derive(password, salt, N, R, P))}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = _derive(password[:MAX_LEN * 4], base64.b64decode(salt), int(n), int(r), int(p))
    except Exception:          # malformed hash → never authenticates; never echo the input
        return False
    return hmac.compare_digest(actual, expected)


# Computed once: verifying against it costs the same as a real verification, so an
# unknown username takes about as long as a wrong password (timing equalisation).
_DUMMY_HASH: str | None = None


def dummy_verify(password: str) -> None:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _DUMMY_HASH)


def _simplified(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def password_problems(password: str, username: str | None = None) -> list[str]:
    """Human-readable policy violations (empty list = acceptable). Never includes the password."""
    problems: list[str] = []
    if not isinstance(password, str):
        return ["Password must be text."]
    if len(password) < MIN_LEN:
        problems.append(f"Use at least {MIN_LEN} characters.")
    if len(password) > MAX_LEN:
        problems.append(f"Use at most {MAX_LEN} characters.")
    if len(set(password)) < 5:
        problems.append("Use more varied characters.")
    core = _simplified(password)
    if core in _COMMON or core.rstrip(string.digits) in _COMMON:
        problems.append("This password is too common.")
    seqs = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm")
    if len(core) >= 8 and any(core in s or core in s[::-1] for s in seqs):
        problems.append("Avoid simple keyboard or alphabet sequences.")
    if username:
        u = _simplified(username)
        if u and (core == u or (len(u) >= 4 and u in core and len(core.replace(u, "")) < 6)):
            problems.append("Password must not be based on the username.")
    return problems


def generate_password(length: int = 20) -> str:
    """Random strong password (used for dev seeding and admin resets; shown once, never logged)."""
    alphabet = string.ascii_letters + string.digits + "-_.!@#%"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and not password_problems(pw)):
            return pw
