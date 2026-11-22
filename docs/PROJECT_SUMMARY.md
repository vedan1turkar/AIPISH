# AIPISH: project summary

**AIPISH** is an email threat-forensics platform built as non-commercial university coursework (PBL, Group G7).
An analyst uploads a raw `.eml` message; AIPISH analyses it and presents explainable, evidence-linked
indicators for investigation. It supports an investigation; it does not decide what a message is or who sent it.

## Problem

Phishing and business email compromise (BEC) are investigated by hand from raw headers, scattered lookups and
judgement. Automated verdicts often hide their reasoning, and attribution claims ("the attacker is in country X")
are easy to over-state.

## Approach

Each layer produces a separate, labelled result; none silently overrides another:

1. **Deterministic forensics:** parsing, header and relay-chain analysis, SPF/DKIM/DMARC re-verification, and
   18 weighted detection rules (score 0–100 and verdict).
2. **Machine learning:** a DistilRoBERTa + XGBoost ensemble classifies five classes (legitimate, suspicious,
   impersonated, phishing, fraud); SHAP explains the XGBoost component; a local Mistral model (Ollama) writes a
   constrained, evidence-cited summary.
3. **Context:** consent-gated threat intelligence (VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor exit list),
   cross-message correlation into candidate campaigns (NetworkX), MITRE ATT&CK mapping and source-type
   hypotheses, and infrastructure geolocation.
4. **Decision support:** a combined risk index with an evidence list, risk-based alerts, PDF and HTML reports.
5. **Governance:** role-based access (viewer, analyst, admin), personal-data masking, a tamper-evident audit log,
   retention with legal holds.

## Architecture

React SPA → Nginx (CSP, security headers) → FastAPI backend (one worker) → PostgreSQL (SQLite in
development). Ollama and the trained models stay on the host. Docker Compose runs a one-command synthetic demo;
GitHub Actions runs tests on SQLite and PostgreSQL, frontend checks, image builds and security scans. Details:
[ARCHITECTURE.md](ARCHITECTURE.md).

## What was built

- 73 API routes behind a deny-by-default permission map; 23 database tables; 10 versioned migrations.
- 13 analysis tabs plus Overview, History, Alerts, Campaigns, Analytics, Search, Users, Audit and Retention pages.
- Requirements matrix: **38 VER, 7 IMP-U, 8 PART, 0 STUB, 4 MISS, 3 BLK** of 60
  ([REQUIREMENTS_SUMMARY.md](REQUIREMENTS_SUMMARY.md)).

## Key results (with caveats)

| Result | Value | Caveat |
|---|---|---|
| ML ensemble, test split (1,709 messages) | macro-F1 0.965; threat vs legitimate F1 0.948 (P 0.970, R 0.926) | 1998–2007 corpora; impersonated and fraud are synthetic; source/era confounded |
| ML ensemble, real messages only | macro-F1 0.954; threat vs legitimate F1 0.936 | Legitimate and phishing only |
| Rules alone, test split (offline) | `suspicious`+ F1 0.455 at 9.60 % FPR; `phishing_fraud_likely` recall 0.065 | No DNS/authentication in the study |
| Combined risk, test split | high+ F1 0.9475 at 1.51 % FPR (same as ML alone); medium+ F1 0.9463 at 3.02 % FPR | Thresholds from validation; an index, not a probability |
| Synthetic BEC demo sample | Rules 100 `phishing_fraud_likely`; ML impersonated 0.4355; combined HIGH 80 | One synthetic message |
| Threat intel live check (2026-11-22) | 16 requests, 4 approved indicators + Tor list; 3 response-shape defects fixed | Error and quota paths not exercised live |
| Tests (this release) | See [TESTING.md](TESTING.md) | No browser end-to-end suite |

Sources: [ml/FINAL_EVALUATION_v1.md](ml/FINAL_EVALUATION_v1.md), [risk/README.md](risk/README.md),
[intel/LIVE_VERIFICATION.md](intel/LIVE_VERIFICATION.md).

## Main limitations

Old, partly synthetic training data and no `suspicious` class; uncalibrated ML scores; SHAP covers only
XGBoost; low rule recall; heuristic correlation weights tuned on synthetic data; local authentication without
MFA or OAuth; data unencrypted at rest; subjects visible to viewers; a tamper-evident (not tamper-proof) audit
log; no mailbox ingestion, so alerts are not real-time. Full list: [LIMITATIONS.md](LIMITATIONS.md).

## Future work

Re-baseline the rules on modern labelled mail; real BEC and `suspicious` data and score calibration;
transformer explanations; mailbox ingestion with background workers; OAuth/OIDC with MFA and per-case access
control; encryption at rest; external timestamping of audit checkpoints; live verification of provider error
paths.
