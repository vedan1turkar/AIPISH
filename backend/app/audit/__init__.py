"""Tamper-evident audit log, custody views and audit helpers (P5e).

Honest scope (used verbatim in API responses, UI and docs):
"""
GUARANTEE = ("Tamper-evident (HMAC hash chain), not tamper-proof: an attacker with both database write access "
             "and the audit key could forge a chain; external checkpoints reduce that risk.")
INTEGRITY_NOTE = "SHA-256 detects change to the stored file; it does not make storage tamper-proof."
