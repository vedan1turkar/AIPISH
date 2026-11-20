# MITRE ATT&CK mapping and source-type hypotheses (P5d)

AIPISH maps the stored evidence of each analysis to MITRE ATT&CK techniques with a **deterministic,
rule-based engine**. No LLM and no randomness are involved. It also assesses four independent
**source-type hypotheses**.

Both are **informational only**:
- they never change the rule score, ML result, threat-intel run, correlation or verdict;
- they are never sent to the local LLM; a test checks that the evidence pack contains no ATT&CK data;
- they never identify a person, group or physical location.

> ATT&CK describes intrusion tradecraft and only approximates business-email-compromise and financial
> fraud. Every surface (API, UI, PDF) carries this note and the attribution disclaimer.

## Catalog (pinned)

| Item | Value |
|---|---|
| File | `backend/app/attack/data/techniques.json` (`catalog_version` `aipish-attack-catalog-1`) |
| Source | MITRE ATT&CK **Enterprise 20.1**, collection modified 2026-11-05, from `github.com/mitre-attack/attack-stix-data` (`enterprise-attack/enterprise-attack-20.1.json`) |
| Retrieved | 2026-11-20. Bundle SHA-256 `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |
| Verification | **IDs, names, tactics and URLs verified against the official STIX data.** A snapshot of the verified fields is committed at `backend/tests/fixtures/attack/verified_fields_enterprise_20.1.json`, and `test_catalog_matches_verified_official_snapshot` fails if any catalog entry differs from it or is revoked. |

Descriptions are short texts written for this project, not copied from ATT&CK. The catalog contains only
techniques the rules can evidence.

| ID | Name | Tactic |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access |
| T1566.002 | Phishing: Spearphishing Link | Initial Access |
| T1598 | Phishing for Information | Reconnaissance |
| T1598.003 | Phishing for Information: Spearphishing Link | Reconnaissance |
| T1684.001 | Social Engineering: Impersonation | Stealth |
| T1684.002 | Social Engineering: Email Spoofing | Stealth |
| T1657 | Financial Theft | Impact |
| T1204.001 | User Execution: Malicious Link | Execution |
| T1204.002 | User Execution: Malicious File | Execution |
| T1586.002 | Compromise Accounts: Email Accounts | Resource Development |
| T1585.002 | Establish Accounts: Email Accounts | Resource Development |
| T1583.001 | Acquire Infrastructure: Domains | Resource Development |
| T1090.003 | Proxy: Multi-hop Proxy | Command and Control |

### Changes in ATT&CK 20.x that affected the candidate list
- **T1656 Impersonation** and **T1672 Email Spoofing** are **revoked** in 20.1. They were replaced by
  **T1684.001** and **T1684.002** (parent T1684 Social Engineering), which are used here. A test checks that
  the engine never emits T1656 or T1672.
- Version 20 renamed the Defense Evasion tactic; these techniques are now under **Stealth**.
- **Considered but not used:** T1566.003, T1598.002, T1534, T1036, T1027, T1114 and others. AIPISH cannot
  evidence them from a single received message.

## Definitions

- **observed:** the behaviour is directly present in the artefacts, i.e. a risky attachment, a delivered
  link, or a locally re-verified authentication failure.
- **inferred:** a reasoned interpretation of content, header or provider signals.
- **ML:** classifier output can only appear in `supporting_evidence_ids`. It never forms the basis of a
  mapping, so on its own it creates nothing (tested).
- **No evidence, no mapping.** Without evidence the result says *"No ATT&CK techniques could be mapped
  from the available evidence."*

### Evidence references
Each result carries its own evidence list (`A1`, `A2`, …, numbered in order of first use). Each item has
a category (`verified` / `heuristic` / `claimed` / `provider` / `model`) and the exact `source_field` it
came from:
- `detection.findings[i]`
- `forensics.inconsistencies[i]`
- `auth.spf`, `auth.alignment.dkim`
- `urls[i]`, `attachments[i]`
- `threat_intel[run_id].indicators[i].results[j]`
- `assessment[id].ml`

Tests resolve every `source_field` back to the stored record. In the UI, the chips reuse the AI tab's
evidence navigation (`#evidence-<id>`, scroll and highlight), and each item can open the dashboard tab
that shows it.

## Mapping rules (`backend/app/attack/engine.py`, engine `attack-engine-1.1`)

| Rule | Technique | Basis | Fires when | Confidence |
|---|---|---|---|---|
| M01_attachment_delivery | T1566.001 | observed | `risky_attachment_type` fired (executable, macro-capable or container attachment) | medium; high if a provider flagged the hash |
| M02_link_delivery | T1566.002 | observed | ≥1 URL **and** a URL-risk rule, provider flag, credential request or look-alike domain. A link alone maps nothing. | high (provider flag) / medium (URL rule or look-alike) / low (credential language only) |
| M03_info_link | T1598.003 | inferred | `credential_request` and a URL | medium |
| M04_info_request | T1598 | inferred | `credential_request` without a URL | low |
| M05_impersonation | T1684.001 | inferred | (`payment_diversion` or `credential_request`) **and** (Reply-To mismatch, look-alike domain or `replyto_mismatch` inconsistency) | medium if look-alike, or payment plus Reply-To mismatch; else low |
| M06_spoofing_verified | T1684.002 | **observed** | SPF/DMARC **re-verified locally** and failed | high (DMARC) / medium (SPF) |
| M06_spoofing_claimed | T1684.002 | inferred | header-claimed failure **and** Return-Path mismatch or DMARC misalignment | low |
| M07_financial_theft | T1657 | inferred | `payment_diversion` (intent only) | medium with impersonation, else low |
| M08_malicious_file | T1204.002 | inferred | risky attachment **and** VirusTotal flagged its hash (consented intel) | medium |
| M09_malicious_link | T1204.001 | inferred | a provider flagged a linked host | low |
| M10_compromised_account | T1586.002 | inferred | SPF/DKIM/DMARC verified pass, aligned, fraud content, no look-alike | **always low** |
| M11_reply_mailbox | T1585.002 | inferred | Reply-To mismatch and payment or credential content | low |
| M12_domains | T1583.001 | inferred | look-alike domain, or `domain_no_mx_shortlived` (registration-age evidence) | low / medium (registration evidence) |
| M13_tor_origin | T1090.003 | inferred | an **origin-candidate** IP is in the Tor exit list, or IPinfo reports Tor | medium |

### Guard against a pre-existing upstream artefact (fixed upstream in P5d.1)

> **Update (P5d.1):** the forensics comparison is now fixed for all new analyses (see `docs/CHANGELOG.md`).
> The guard below is kept because analyses stored before the fix are not rewritten; on fixed data it is
> a no-op.

- **The bug:** the header-forensics `returnpath_mismatch` check (P2, `forensics/headers.py`) can keep a
  trailing `>` on the Return-Path domain. It then reports identical domains as different, e.g.
  `account-notice.test ≠ account-notice.test>`.
- **Why it isn't fixed here:** fixing it would change `header_inconsistency_forensics` and therefore rule
  scores, which P5d must not do.
- **Containment:** the ATT&CK engine re-checks the stored From and Return-Path domains. If they match after
  normalisation, it ignores the inconsistency and lists it under `suppressed_signals`.
- **Recommended:** fix the forensics comparison in a later phase, with a deliberate score re-baseline.

## Source-type hypotheses (independent, not a verdict)

Bands are `likely`, `possible`, `not_indicated`, `undetermined` (insufficient evidence) and
`not_assessed: <reason>`.

| Hypothesis | likely | possible | not_indicated | otherwise |
|---|---|---|---|---|
| Possible spoofed sender domain | SPF/DMARC re-verified fail | ≥1 of: Return-Path mismatch, DMARC misalignment, claimed auth failure, look-alike domain | DMARC verified pass (or SPF and DKIM verified pass) | undetermined (auth not verifiable) |
| Possible compromised legitimate account | *never* | verified pass, aligned, fraud content, no look-alike | verified auth failure, or pass without fraud content | undetermined |
| Anonymised sending infrastructure | origin IP in the Tor exit list or IPinfo VPN/proxy/Tor | IPinfo relay/hosting or AbuseIPDB hosting usage type | provider data present, no flags ("not evidence of safety") | not assessed |
| Directly malicious infrastructure | ≥2 providers (VirusTotal / AbuseIPDB) flag an origin IP | 1 provider flags | provider data present, no flags ("not evidence of safety") | not assessed |

**When the intel-dependent hypotheses are "not assessed".** If threat intel was not run, was declined,
ran offline without data, failed, or had no eligible origin candidate, these hypotheses report
**`not_assessed`** with the reason. They are never reported as "not indicated". Absence of reports is not
evidence of safety.

The hypotheses are not mutually exclusive (tested), and the wording covers infrastructure and accounts
only.

## Persistence and versioning

- **Table:** `attack_mapping`. Each row holds the version, source (`auto` / `recompute` / `backfill` /
  `intel_run`), engine and catalog versions, the intel run id and ML assessment id used, a fingerprint and
  the results JSON.
- **Append-only:** a new version is stored only when the fingerprint changes, so backfill and recompute
  are idempotent.
- **Migrations:** the additive migration runs at app start-up **and** in every CLI command.
- **When mappings are computed:**
  - **automatically after an upload** (after correlation; failure-isolated, a test forces a mapper error
    and compares the upload responses);
  - **automatically after a threat-intel run** (failure-isolated; the intel response is unchanged);
  - **on demand** via the API or UI;
  - **in bulk** with `python -m app.cli backfill-attack`.
- **Engine version bumps** (1.0 → 1.1 in P5d for the Return-Path guard) append one version per analysis;
  older versions stay readable.

## API (central permission map)

| Method and path | Permission | Roles |
|---|---|---|
| `GET /api/v1/analyses/{id}/attack[?version=n]` | `attack:read` | viewer, analyst, admin |
| `GET /api/v1/analyses/{id}/attack/history` | `attack:read` | viewer, analyst, admin |
| `POST /api/v1/analyses/{id}/attack/recompute` (audited `attack_recomputed`) | `attack:recompute` | analyst, admin |

**Related additions:**
- `GET /api/v1/campaigns/{id}` now includes `attack_aggregate`: technique counts from each member's latest
  mapping, labelled as aggregated and not a campaign-level mapping.
- The PDF endpoint accepts `?attack_id=` to pin the version printed, and the `report_generated` audit event
  records it.

## PDF

Section **7C "MITRE ATT&CK Mapping and Source-Type Hypotheses"** contains:
- mapping id and version, catalog and ATT&CK version with the verification state, engine, and inputs
  (including the SIMULATED label);
- the technique table, the source-type table (with "NOT ASSESSED: reason" and "NOT INDICATED (not proof of
  safety)"), and the evidence table;
- the note and the disclaimer.

All text is escaped (tested).

## Limits

- **Single-message view:** mappings describe what one received message evidences. Delivery and intent are
  observable; execution, compromise and theft are not.
- **Heuristic thresholds:** confidence bands are heuristic and validated on synthetic fixtures only.
- **Intel dependence:** the source-type hypotheses for infrastructure rely on consented threat intel. Live
  provider connectivity is still unverified (P5a); the browser walk-through used the SIMULATED loopback stub.
- **Upstream forensics artefact:** see "Guard against a pre-existing upstream artefact" above.
- **No analyst overrides:** analysts cannot override or annotate mappings yet.

## Attribution and terms of use

ATT&CK® is a registered trademark of The MITRE Corporation. Technique identifiers, names, tactics and URLs
are taken from MITRE ATT&CK Enterprise 20.1. © The MITRE Corporation. This work is reproduced and
distributed with the permission of The MITRE Corporation, under the ATT&CK Terms of Use
(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
