"""Email header forensics — observed relay chains, IP classification, inconsistencies.

All confidence rules are documented in this package's config and notes:
see ``FORENSICS_NOTES.md`` for the evidence-table that goes with each rule.
"""
from app.forensics.headers import run_header_forensics, HeaderForensicsResult

__all__ = ["run_header_forensics", "HeaderForensicsResult"]
