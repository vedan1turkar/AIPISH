# Forensic reports: PDF (ReportLab) and HTML (Jinja2)

AIPISH exports the forensic report in two formats built from **the same inputs**:

| Format | Endpoint | Permission | Engine |
|---|---|---|---|
| PDF | `GET /api/v1/investigations/{case_id}/report/{analysis_id}` | `report:download` (viewer+) | ReportLab (`backend/app/reports/pdf.py`), unchanged |
| HTML (P5k-lite) | `GET /api/v1/analyses/{analysis_id}/report.html` | `report:download` (viewer+) | Jinja2 3.1.6 templates (`backend/app/reports/templates/`), autoescape on |

Both endpoints take the same version pins: `assessment_id`, `intel_run_id`, `attack_id` and `risk_id`. With no
pin, the latest stored version is printed. An unknown pin returns 404. Anonymous requests get 401.

The HTML report does not need an investigation case: when the analysis belongs to one, the case number is
printed. If the raw-evidence key policy is active, both endpoints require `X-Evidence-Key`.

## Shared inputs, masking and audit

- **One builder:** `case_router.report_inputs()` builds the inputs for both formats.
  - It covers integrity re-verification, the "MASKED VIEW" and redaction notices, and the P5e masking
    serializer for roles without `pii:view`.
  - The stored, pinned assessment, intel run, correlation snapshot, ATT&CK mapping and combined-risk
    versions come from it as well.
  - The HTML renderer (`app/reports/html.py`) reuses the PDF's own wording helpers: intel status texts,
    provider facts, ATT&CK band texts, the SHAP component view and risk value formatting. The two formats
    therefore say the same thing.
- **Masking:** a viewer gets no addresses, display names or body in either format, and the notice
  "MASKED VIEW: personal data … masked for the requesting role." Tests check parity.
- **Redaction:** a redacted analysis prints "Content redacted per retention policy" and the cross-check
  subsection says "redacted per retention policy".
- **Audit:** each download records `report_generated` with:
  - the actor;
  - `format` (`html` on the HTML endpoint; the PDF event is unchanged);
  - the pinned versions: assessment, intel run, campaigns, ATT&CK mapping, risk;
  - `masked` and `redacted`.

## HTML security

- **Self-contained:**
  - no `<script>`, `<link>`, `<img>`, `<iframe>`, `<svg>` or `<object>`;
  - no `src`, `href` or `url()` that loads anything (the only `href`s are in-page `#section` anchors);
  - no remote fonts (system font fallbacks) and no images; inline CSS only.
- **Offline:** the saved file renders with no network access. It has a dark console look on screen and is
  black-on-white when printed.
- **Escaping:** Jinja2 autoescape is on for every variable, and the templates never use `|safe`.
  - Subjects, display names, file names, header values, provider strings, Mistral text and hostnames are
    escaped.
  - Tests inject `<script>`, `<img onerror>` and `<svg onload>` into each of these and parse the result
    with an HTML parser to confirm no markup gets through.
- **Response headers:**
  - `Content-Disposition: attachment`;
  - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  - `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- **In-document CSP:** the HTML also carries a `<meta>` CSP, so a saved copy stays locked down.

## Section parity (HTML vs PDF)

| Section | PDF | HTML | Note |
|---|---|---|---|
| Banner: report id, generated, rule verdict, rule score | ✓ | ✓ | |
| 1. Evidence & integrity | ✓ | ✓ | Same integrity wording |
| 2. Email metadata (masked for viewers) | ✓ | ✓ | |
| 3. Findings (rule, severity, points, fact/heuristic, evidence, rationale) | ✓ | ✓ | |
| 4. Authentication: claims vs verified, alignment | ✓ | ✓ | |
| 5. Header anomalies **+ parser cross-check subsection** | ✓ | ✓ | Cross-check added to both in P5k-lite |
| 6. Observed relay chain and trusted boundary | ✓ | ✓ | |
| 7. Infrastructure intelligence (candidates, enrichment) | ✓ | ✓ | |
| 7A. Threat-intel run (SIMULATED, stale, no-record wording) | ✓ | ✓ | Same status texts |
| 7B. Related analyses / campaigns (report-time snapshot) | ✓ | ✓ | |
| 7C. ATT&CK and source-type hypotheses | ✓ | ✓ | Technique IDs as plain text, not links |
| 7D. IOCs (URL hosts, attachment names, types, sizes and SHA-256) | — | ✓ | HTML only. Full URLs are not printed and are never links. |
| 7E. Infrastructure locations table (stored data, SIMULATED/stale flags) | — | ✓ | HTML only. Table, no map. |
| 8. ML (8.1), SHAP (8.2, "XGBoost only" note), local LLM (8.3, recommendations, evidence) | ✓ | ✓ | Same policies for evidence-linked, general and rejected recommendations |
| 8A. Combined risk (pinned) | ✓ | ✓ | |
| 8B. Custody and integrity note (tamper-evident wording) | — | ✓ | HTML only. The P5e guarantee sentence and the SHA-256 note. |
| 9. Confidence and limitations | ✓ | ✓ | Same substance. The HTML uses the P5e "tamper-evident, not tamper-proof" wording through section 8B instead of the PDF's older sentence. |

**Not in the HTML:** nothing from the PDF is omitted. The HTML adds 7D, 7E and 8B.

## Parser cross-check (R43)

See [docs/reports/parser-crosscheck.md](parser-crosscheck.md).
