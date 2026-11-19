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
| `POST /analyses/{id}/forensic-summary` | Summary for a stored analysis. ML and SHAP need the raw bytes, so under the default `hash_only` evidence policy they are reported as unavailable |

The response is `{analysis_id, ml, explanation, forensic_summary}`. `forensic_summary` contains:

- **Status and labelling:**
  - `status`: one of `ok`, `unavailable`, `timeout`, `invalid_output`.
  - `ai_generated: true`, and a `label` marking the text as an AI interpretation.
  - `model`: provider, name, digest and `local`.
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
- **Personal names.** Names inside the body excerpt, such as the recipient's first name, are not redacted, because there is no named-entity recognition.
- **Injection detection** uses known phrasing. Novel wording may go undetected, but it remains fenced, and the output validation still applies.
