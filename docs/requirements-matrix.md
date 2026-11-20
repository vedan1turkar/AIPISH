# AIPISH requirements traceability matrix (R1–R60)

This matrix traces AIPISH against the PBL Review 0 document, Group G7. The P5 audit set its baseline at
`b6e4c67`. This version of the file was updated for **P5a: threat-intelligence provider integrations**.

**ID provenance:**
- R1–R40 come from the original project matrix.
- R41–R60 were re-derived during the P5 audit from PBL §4.6, §5 and §8 and the recommended stack, and are
  marked `*`.

Recommended technologies are listed for traceability. They are not functional scope.

## Status legend

| Code | Meaning |
|---|---|
| **VER** | Implemented and verified (tests plus a real-app run). |
| **IMP-U** | Implemented, verification incomplete. For P5a providers this means **mocked-verified**: unit/integration tests plus a real-app run against a SIMULATED loopback stub. **Live provider connectivity is not verified.** |
| **PART** | Partially implemented. |
| **STUB** | Stub or mock only. |
| **MISS** | Missing. |
| **BLK** | Blocked by an external dependency. |

## Counts (after P5a)

| Status | Before P5a | After P5a |
|---|---:|---:|
| VER | 16 | 16 |
| IMP-U | 3 | 7 |
| PART | 16 | 18 |
| STUB | 1 | 0 |
| MISS | 21 | 16 |
| BLK | 3 | 3 |
| **Total** | 60 | 60 |

## Changes made in P5a

| ID | Before | After | Why |
|---|---|---|---|
| R15 | MISS | PART | Tor exit-list membership, IPinfo VPN/proxy/Tor/relay/hosting flags (when the plan returns them; otherwise "unavailable"), Shodan risk tags and AbuseIPDB usage type. Open relay and botnet detection are still missing. Mocked-verified only. |
| R18 | MISS | PART | Threat-intel reputation correlation implemented (VT, AbuseIPDB, Shodan, IPinfo, Tor). Correlation with past incidents, clusters and campaigns is still missing (P5b). Mocked-verified only. |
| R44 | MISS | IMP-U | VirusTotal adapter: GET-only IP, domain and hash reputation; 4/min limiter and daily cap. Mocked-verified; live unverified. |
| R45 | STUB | IMP-U | AbuseIPDB adapter replaces the stub: score, reports, country, ISP, usage type, last reported. Mocked-verified; live unverified. |
| R46 | MISS | IMP-U | Shodan host adapter: ports, org, ASN, hostnames, tags; 404 maps to no_record. Mocked-verified; live unverified. |
| R49 | MISS | IMP-U | IPinfo adapter: geo, ASN/org, privacy flags; fields the plan does not return are shown as unavailable. Mocked-verified; live unverified. |

Related rows (R14, R16, R33, R59, R60) gained evidence but keep their status.

## Matrix

| ID | Requirement | Status | Evidence (code · tests) | Gaps / external dependency |
|---|---|---|---|---|
| R1 | NLP of subject/body: urgency, impersonation, social engineering | PART | `ml/transformer.py`, lexicon rules in `detection/` · `test_ml.py`, `test_detection.py` | No per-cue NLP output |
| R2 | Phishing indicators: spoofing, deceptive domains, attachments, links, obfuscation | VER | `detection/` rules · `test_detection.py` | `lookalike_domain` needs a reference domain |
| R3 | ML classes: legitimate / suspicious / impersonated / phishing / fraud | PART | `ml/train.py`, `ml/inference.py`, `/ml/classify` · `test_ml.py` | `suspicious` has no data; impersonated and fraud are synthetic only |
| R4 | SHAP explanations | PART | `ml/explain.py`, `ml/shap_view.py` · `test_explain.py`, `test_p41.py` | XGBoost half only |
| R5 | Labelled dataset | VER | `ml/dataset/*`, `data/DATA_CARD.md` · `test_dataset.py` | Era and source confound |
| R6 | BEC detection | PART | `payment_diversion` / `credential_request` rules, ML fraud class, P4.2 policy | No real BEC data; no executive-impersonation check |
| R7 | Combined risk score | PART | Rule score bridges forensics, auth and enrichment | ML not combined; no behavioural signal; threat intel deliberately informational in P5a |
| R8 | Header fields and alignment | VER | `forensics/headers.py`, `auth/` · `test_forensics.py`, `test_auth.py` | — |
| R9 | SPF/DKIM/DMARC verification | IMP-U | `auth/__init__.py` live checks · DNS stubbed in tests | Never verified live |
| R10 | Routing anomalies / forged fields | VER | `forensics/headers.py` · `test_forensics.py` | — |
| R11 | Authorised vs suspicious infrastructure | IMP-U | SPF result plus relay trust | Depends on live SPF (R9) |
| R12 | Relay-chain reconstruction | VER | `run_header_forensics` · `test_forensics.py` | Heuristic trust boundary |
| R13 | Candidate IPs / earliest reliable node | VER | `forensics/headers.py` · `test_forensics.py` | — |
| R14 | Geolocation: country, region, city, ISP, ASN, hosting | PART | `enrichment/engine.py:ipgeo_lookup`; P5a IPinfo geo/ASN/hosting flag · `test_intel.py` | MaxMind blocked (R48); live unverified |
| R15 | VPN / Tor / proxy / hosting / botnet / open-relay flags | PART | `intel/providers.py`: TorExitList, IPinfo privacy, Shodan tags, AbuseIPDB usage type · `test_intel.py` | No open-relay or botnet source; IPinfo privacy may need a paid plan; live unverified |
| R16 | WHOIS/RDAP, DNS, MX, registrar | PART | `dns_lookup`, `rdap_lookup`; VT domain registrar/creation (P5a) · `test_enrichment.py`, `test_intel.py` | Live unverified |
| R17 | Origin vs infrastructure vs identity separation | VER | Disclaimers in UI, PDF, LLM evidence and the threat-intel disclaimer · `test_llm.py`, `test_p41.py`, `test_intel.py` | — |
| R18 | Correlation with threat intel, reputation, past incidents, campaigns | PART | `intel/` service and router; Threat intel tab; PDF §7A · `test_intel.py`, `ThreatIntelPanel.test.tsx` | Cross-case and campaign correlation missing (P5b); live unverified |
| R19 | Relationship graph | PART | `frontend/.../trace/*` (Cytoscape) · `model.test.ts` | Single email only |
| R20 | Confidence-based attribution | PART | Per-hop confidence | No campaign-level attribution |
| R21 | Source-type classification | MISS | — | Rule-based classifier needed |
| R22 | Rule tests | VER | `test_detection.py` | — |
| R23 | MITRE ATT&CK mapping | MISS | — | — |
| R24 | Real-time alerts | MISS | — | Needs ingestion (R36) |
| R25 | Analyst dashboard | IMP-U | `ResultsDashboard.tsx` tabs, including Threat intel · `ThreatIntelPanel.test.tsx`, `AssessmentInteractions.test.tsx` | Geo shown only from live enrichment or IPinfo |
| R26 | Interactive trace map / graphs | PART | Cytoscape trace view | No Leaflet map (R57) |
| R27 | Structured forensic reports | VER | `reports/pdf.py` (incl. §7A) · `test_assessment_report.py`, `test_p41.py`, `test_intel.py` | — |
| R28 | Searchable case management / campaigns | PART | `cases/service.py`, `/investigations` · `test_investigations.py` | No search; one analysis per case via API |
| R29 | PDF tests incl. injection | VER | PDF escaping tests (also for provider strings in §7A) | — |
| R30 | Evidence preservation / chain-of-custody support | PART | SHA-256, optional raw retention, versioned assessments and intel runs | Not tamper-resistant |
| R31 | Retention, masking, redaction | PART | `CASE_EVIDENCE_RETENTION_DAYS`, `llm/redact.py` | Retention not enforced; body stored in clear |
| R32 | RBAC | MISS | — | API is anonymous |
| R33 | Tests | VER | Backend 421 passed / 6 skipped (5 opt-in live intel tests); frontend 71 passed | No CI; no browser E2E suite |
| R34 | Main database (PostgreSQL) | PART | SQLAlchemy and SQLite | No PostgreSQL or migrations tool |
| R35 | Background tasks / caching | MISS | In-process enrichment cache; DB intel cache (P5a) | No Celery/Redis; lookups run synchronously |
| R36 | Email integration (IMAP/SMTP/Graph) | MISS | — | Test mailbox or Azure tenant |
| R37 | Deployment (Docker/Nginx) | MISS | — | — |
| R38 | CI/CD | MISS | — | — |
| R39 | Frontend (React + Tailwind) | VER | Vite + React + Tailwind; tsc, ESLint and build pass | — |
| R40 | Attribution as investigative support | VER | Disclaimers in UI, PDF and evidence | — |
| R41* | Preprocessing / normalisation | VER | `ingestion/parser.py`, `enrichment/iocs.py`, `intel/validate.py` · `test_parser.py`, `test_intel.py` | — |
| R42* | Attachment metadata | VER | Parser SHA-256 and metadata · `test_parser.py` | — |
| R43* | mail-parser cross-check | MISS | — | — |
| R44* | VirusTotal | IMP-U | `intel/providers.py:VirusTotal` · `test_intel.py` | **Live unverified**; public API is non-commercial only |
| R45* | AbuseIPDB | IMP-U | `intel/providers.py:AbuseIPDB` · `test_intel.py` | **Live unverified** |
| R46* | Shodan | IMP-U | `intel/providers.py:Shodan` · `test_intel.py` | **Live unverified**; host lookups may need a paid plan (reported as not_permitted) |
| R47* | MISP | BLK | Reported as "not configured" | No MISP instance |
| R48* | MaxMind GeoIP2 | BLK | `geoip2_lookup` stub; reported as "not configured" | No licence key or database |
| R49* | IPinfo | IMP-U | `intel/providers.py:IPinfo` · `test_intel.py` | **Live unverified**; privacy flags depend on plan |
| R50* | Neo4j | MISS | — | Service not installed |
| R51* | NetworkX | MISS | — | — |
| R52* | Search (OpenSearch) | MISS | — | — |
| R53* | OAuth 2.0 | BLK | — | Provider not chosen |
| R54* | JWT authentication | MISS | — | — |
| R55* | Jinja2 report templates | MISS | ReportLab only | Low value |
| R56* | Plotly analytics | MISS | — | — |
| R57* | Leaflet geolocation map | MISS | — | Needs geolocation data |
| R58* | Local LLM forensic summaries | VER | `llm/*` · `test_llm.py`, `test_p41.py`, `test_p42.py` | — |
| R59* | Audit trails | PART | `audit_event`; P5a adds `threat_intel_lookup` (consent decision, providers, counts) and the intel run id on `report_generated` | No read API; no evidence-access or admin events |
| R60* | Controlled personal-data handling | PART | LLM redaction, local-only Ollama; P5a per-analysis consent, bare-indicator-only outbound requests, offline mode | No access control; body stored in clear |
