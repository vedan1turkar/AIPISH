# Local LLM forensic summaries (P3): Ollama + Mistral

An AI-generated narrative is layered on top of the deterministic pipeline. The parser, the 18 rules, SPF/DKIM/DMARC, header forensics, enrichment, ML and SHAP all run without it. If the LLM fails, they are unaffected.

## Requirements

- Ollama, running locally (tested with 0.40.15).
- The model: `ollama pull mistral`. Tested with `mistral:latest`, 7.2B, Q4_K_M, digest `6577803a…`, Apache-2.0.
- Settings, all optional:

| Variable | Default |
|---|---|
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | `mistral` |
| `LLM_TIMEOUT_SECONDS` | `120` |
| `LLM_NUM_CTX` | `8192` |
| `LLM_SEED` | `7` |
| `OLLAMA_ALLOWED_HOSTS` | (empty) — extra non-loopback hosts, e.g. a Docker service name |

- **Only loopback endpoints are accepted by default.** Email data is never sent to a remote or cloud API.

## Endpoints (under `/api/v1`)

| Method and path | Purpose |
|---|---|
| `GET /llm/status` | Ollama reachability, model name and digest |
| `POST /llm/forensic-summary` (multipart `file`) | Runs and stores the normal analysis, then ML, SHAP and the LLM summary on the same bytes |
| `POST /analyses/{id}/forensic-summary` | Summary for a stored analysis. ML and SHAP need the raw bytes, so under the default `hash_only` evidence policy they are reported as unavailable, unless an earlier version already has them (then they are reused and `ml.reused_from_assessment` names the source version) |
| `GET /analyses/{id}/assessment` | The latest stored assessment version |
| `GET /analyses/{id}/assessments` | Assessment history, newest first |
| `GET /analyses/{id}/assessments/{assessment_id}` | One stored version |
| `GET /investigations/{case}/report/{id}?assessment_id=…` | PDF pinned to one assessment version. Without the parameter, the latest version is used, and the PDF identifies it |

**History (P4.1).**
- Every generation appends a new version, with its own id, version number, timestamp and source. Earlier versions are never updated.
- P4 single-row assessments are copied once into the versioned table at startup. The copy is idempotent, and the legacy table is left untouched.
- While a generation for an analysis is running, a second request gets `409 ASSESSMENT_IN_PROGRESS`.
- This is application-level history, not tamper-proof storage.

The response is `{analysis_id, ml, explanation, forensic_summary}`. `forensic_summary` contains:

- **Status and labelling:**
  - `status`: one of `ok`, `unavailable`, `timeout`, `invalid_output`.
  - `ai_generated: true`, and a `label` marking the text as an AI interpretation.
  - `model`: provider, name, digest and `local`.
- **Recommendations (P4.2, `recommendation_policy: "p4.2-constrained"`).** Model wording is never shown as advice. Each model action is mapped onto a closed set of categories:
  - **Rejected as unsafe:**
    - replying to or contacting the alleged sender without a previously established, independently verified channel;
    - using phone numbers, Reply-To addresses, signatures, links or attachments from the email;
    - moving money, approving invoices or changing payment details on the email's strength.
  - **Rejected as unsupported:** asserting a detail of the email (supplier, phone number, approval code, account …) that no deterministic evidence item establishes.
  - **Evidence-linked:** shown only as a fixed system template, with evidence IDs chosen deterministically from the evidence list. This happens only when the category's required evidence exists.
  - **General:** fixed system templates, labelled as standard practice and not as findings: independent verification, do not use the email's contacts, preserve evidence, escalate, and hold payments.
  - **Unrecognised or ambiguous:** rejected.
  - **How matching works:** on NFKC-normalised text with invisible characters and punctuation removed. A letters-only fallback runs when the text looks letter-spaced.
  - **Financial-context warning:** `financial_context` is deterministic, built from the evidence, the redacted body terms and the ML label. When it is detected, the dashboard and the PDF show a prominent independent-verification warning, even if the LLM failed.
- **The model's validated output:**
  - `summary` and `assessment`: set to null if they fail validation.
  - `findings`: each has a `statement`, cited `evidence_ids`, `evidence_categories`, and a `basis` of `verified` or `inferred`.
  - `rejected_findings`: each has a `statement` and the `reason` it was rejected.
  - `recommended_actions` and `limitations`.
  - `validation`: counts of accepted, rejected and downgraded items, plus flags.
- **Deterministic content, which no LLM writes:**
  - `evidence`: E1…En, each with a category (`verified`, `provider`, `heuristic`, `claimed` or `model`).
  - `unavailable_information`: checks that did not run.
  - `system_verdicts`: the rule engine and ML results.
- **`security`:** injection patterns detected, redaction counts, characters of body sent, and `endpoint_local_only`.
- **`reason` and `latency_ms`.**

## Safeguards

1. **Untrusted email text.** The email text is fenced between random-nonce markers. Any copy of those markers inside the email is stripped, so it cannot close the fence. The system prompt states that this text is data and never instructions.
2. **Injection phrasing.** Phrasing that resembles prompt injection is detected and recorded as evidence, and reported under `security`.
3. **Grounding.** A finding must cite existing evidence ids, or it is rejected. `verified` is downgraded to `inferred` unless every cited item is `verified` or `provider`.
4. **No invented entities.** Any IP or domain not present in the evidence rejects the finding, or nulls the summary or assessment.
5. **No false passes.** SPF, DKIM or DMARC described as passed without a local re-verification is rejected. So is threat intelligence called clean, or a location asserted, when that check is unavailable.
6. **No override of the verdict.** Declaring the email safe or legitimate while the ML or rules indicate a threat is rejected. The LLM never sets a verdict.
7. **Redaction before sending.** Passwords, tokens, API keys, JWTs, private keys, IBANs, Luhn-valid card numbers, phone numbers and long numbers are redacted. So are e-mail local parts (the domain is kept) and URL paths and queries (the host is kept). IP addresses are kept, since they are indicators. The body is capped at 1,500 characters. Recipient addresses are not sent.
8. **Logging.** Logs record only status, latency and counts, never email text.
9. **Generation settings.** Temperature 0, a fixed seed, and JSON-schema-constrained output. Truncated or invalid JSON gets one retry, then `invalid_output`.

## Example

The input is [`sample_bec_injection.eml`](sample_bec_injection.eml). It is synthetic: fictional people and reserved `.test`/`.example` domains. Its body includes an injected instruction to call the email safe, to claim SPF and DKIM passed, and to place an IP in Oslo. The real local Mistral output is in [`sample_bec_injection.response.json`](sample_bec_injection.response.json).

## Limitations

- **Speed.** About 40–60 s per summary on an M4 with 16 GB, using Mistral 7B Q4.
- **Wording.** The model can still misstate details. In the example it called the high-severity credential-request finding "medium severity". Always check the cited evidence items.
- **Validation is pattern-based.** It catches the hallucinations it was designed for (unknown entities, false passes, unwarranted "safe" verdicts), but not every wrong statement.
- **Personal names (partly addressed in P4.1).** Names taken from the message's own From/To/Cc headers are redacted in the body text, as are single names directly after a greeting or on the line after a sign-off. Recipients become `[RECIPIENT_NAME]` and the sender `[SENDER_NAME]`. Other names in the body, such as third parties, are **not** detected, because there is no local NER model, and may reach the local model. The sender's display name is kept in evidence item E1, because it is a sender-controlled header that impersonation analysis needs.
- **The recommendation policy is pattern-based and closed-world.** Unsafe or unrecognised model advice is rejected rather than shown, so useful but unusual suggestions may also be rejected. Novel phrasings of unsafe advice that match no pattern fall into "unrecognised" and are still rejected. Only fixed templates are ever displayed.
- **SHAP scope.** SHAP explains only the XGBoost component. When its raw margin moves away from the predicted class while the ensemble still predicts it, the dashboard, PDF and evidence item say so, quoting each component's probability.
- **Injection detection** uses known phrasing. Novel wording may go undetected, but it remains fenced, and the output validation still applies.
