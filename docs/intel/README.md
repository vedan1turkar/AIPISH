# Threat-intelligence provider integrations (P5a)

AIPISH can check an analysed email's public indicators against VirusTotal, AbuseIPDB, Shodan, IPinfo and the
Tor bulk exit list. The results are **informational only**: they never change the rule score, the ML
classification, the ensemble or the verdict.

MaxMind GeoIP2 and MISP are out of scope because they are blocked externally (no licence or database, no
instance). The status endpoint, the UI and the PDF all report them as **not configured**.

## Verification status

> **Live provider connectivity has not been verified.** Every provider path is covered by mocked tests
> (respx), and the full workflow was run in the real app against a loopback stub that is labelled
> **SIMULATED**. No call was made to a real provider while P5a was built. To run the opt-in live smoke
> tests (one lookup of `8.8.8.8` per provider), rotate the keys first, then run
> `AIPISH_RUN_LIVE=1 pytest tests/unit/test_intel.py -k live`.

## Consent and offline mode

- **Off by default.** Lookups run only after explicit consent for one analysis:
  - the upload-time checkbox, or
  - the consent checkbox plus **Run threat intel lookup** on the *Threat intel* tab.

  **Decline external lookups** records a refusal and sends nothing.
- **Each decision is recorded:** granted or refused, timestamp, source (`upload` / `on_demand`) and the
  provider list. It is stored in a `threat_intel_run` row, and a `threat_intel_lookup` audit event holds the
  decision and counts (no indicators).
- **Offline mode** blocks every external call. It is on when `APP_ENV=offline` or `INTEL_OFFLINE=1`.
  - Cached results are still shown.
  - Expired cache entries are shown as **STALE** with their age.
  - With no cache, the result is `not_attempted_offline`. Nothing is invented.

## What is sent

**Sent:** only the bare, validated indicator, in the request path or a single query parameter:
- a public IP address;
- a domain name;
- an attachment MD5, SHA-1 or SHA-256 hash.

**Never sent:**
- subject, body, sender or recipient addresses;
- raw headers, URL paths or query strings;
- attachments or email files;
- passwords, case IDs or analysis IDs.

**Request constraints:**
- All requests are HTTP GET with an empty body.
- VirusTotal is used only for read-only lookups: nothing is uploaded and no URL is submitted for scanning.
- The Tor exit list is downloaded once per TTL and checked locally, so no indicator is sent for that check.

### Validation before any network call

| Type | Rejected |
|---|---|
| IP | Private, loopback, link-local, multicast, reserved, unspecified, CGNAT (100.64/10), benchmark (198.18/15), documentation ranges, and IPv4-mapped / 6to4 / Teredo addresses pointing at them. A public IPv4-mapped address is normalised to its IPv4 form. |
| Domain | Fails IDNA/syntax checks, IP literal, `localhost`, single label, label longer than 63 characters, internal or reserved suffixes (`.local`, `.internal`, `.lan`, `.example`, `.test`, `.invalid`, `.onion`, …), `example.com/.net/.org`. |
| Hash | Anything that is not 32, 40 or 64 hex characters. |

Rejected indicators appear as **Not applicable … never sent to any provider**.

**Where indicators come from:** the stored analysis only.
- The verified or earliest candidate origin IP.
- Relay candidate IPs.
- URL hosts.
- Attachment SHA-256 hashes.
- The From, Reply-To and Return-Path domains.
- Other Received-hop IPs.

At most `INTEL_MAX_IOCS` eligible indicators are looked up (default 20). Indicators beyond the cap are shown as
**Not looked up: cap reached**.

## Statuses (never merged)

| Status | Meaning |
|---|---|
| `malicious_or_flagged` | The provider flagged the indicator. |
| `reported_clean_no_flags` | The provider evaluated it and returned no flags. **Not proof of safety.** |
| `record_found` | The provider returned data but no reputation verdict, e.g. Shodan, IPinfo without anonymity flags, or AbuseIPDB below the threshold. **Not proof of safety.** |
| `no_record` | No record or reports. **Not proof of safety.** |
| `provider_error`, `timeout`, `malformed_response` | No result. |
| `rate_limited`, `quota_exhausted` | Local or provider limit reached; nothing was sent. |
| `auth_failed`, `not_permitted` | The credential was rejected, or the plan or policy does not allow the lookup. |
| `missing_credentials` | No credential is configured. |
| `not_attempted_consent_disabled`, `not_attempted_offline`, `not_attempted_cap_reached` | Not attempted (no consent, offline mode, or over the indicator cap). |
| `not_applicable_indicator` | The provider does not handle this indicator type, or validation rejected the indicator. |

Each result also records:
- provider, indicator and indicator type;
- `fetched_at` and `expires_at`;
- `cache_state` (`fresh`, `stale` or `none`);
- the endpoint name (never a URL that contains a key);
- normalised data, `error_code` and message.

## Resilience and caching

- **Timeouts:** connect 5 s, read 10 s.
- **Retries:** exactly one, only for 5xx responses and transport errors or timeouts.
- **HTTP 429:** `Retry-After` is honoured as a per-provider cooldown with no further requests. A daily-quota
  signal sets `quota_exhausted`.
- **Limits:** each provider has a rate limiter and a daily quota counter. VirusTotal's public API allows
  4 requests per minute.

  > **Limitation:** the counters are in-process and reset when the backend restarts.
- **In-flight protection:**
  - identical lookups within one run are deduplicated;
  - only one run per analysis can be in flight (`409 INTEL_IN_PROGRESS`).
- **Cache:** the `intel_cache` table is keyed by provider, indicator type and indicator.
  - TTLs: IP and domain 24 h, hash 7 d, Shodan 24 h, Tor list 3 h.
  - A fresh hit makes no network call.
  - When a live lookup fails, an expired entry is returned labelled **STALE**, with its original fetch time.
  - Only results that describe the indicator are cached; errors are not.
- **Failure isolation:** a provider failure becomes that one result's status and never fails the run or the
  analysis.

## Secrets

- Keys are read from the environment or the repo-root `.env` only.
- They are excluded from `repr`, and never logged, stored, returned, printed in the PDF, or included in
  exception text. Only the exception type is recorded.
- The `httpx` and `httpcore` loggers are capped at WARNING because Shodan authenticates with a query parameter.
- `GET /api/v1/intel/status` returns booleans only.
- Endpoint overrides must use HTTPS, or HTTP to a loopback host only. Anything else disables that provider.

## Untrusted provider text

Provider strings such as hostnames, organisations and tags are treated as untrusted:
- Control, bidirectional and zero-width characters are stripped, and the text is truncated.
- The UI renders them as text.
- The PDF escapes them, using the same markup-injection protection as the other sections.
- They are never passed to Mistral: the LLM evidence pack is built from the analysis record, and intel is not
  part of it.

## API

Since P5b every endpoint below needs a bearer token: `GET /intel/status` is **admin** only, running a
lookup needs **analyst** or admin, and reading stored runs or the PDF is open to **viewer** and above
(see `docs/auth/README.md`).

| Method and path | Purpose |
|---|---|
| `GET /api/v1/intel/status` | Per-provider `configured` / `enabled` booleans, offline flag, consent default, IOC cap. |
| `POST /api/v1/analyses/{id}/threat-intel` | Body `{"consent": bool, "providers"?: [...], "source"?: "upload" \| "on_demand"}`. Appends a new versioned run and returns it (201). Unknown provider → 400 `UNKNOWN_PROVIDER`; concurrent run → 409 `INTEL_IN_PROGRESS`. |
| `GET /api/v1/analyses/{id}/threat-intel[?run_id=]` | Latest or pinned stored run. 404 `INTEL_NOT_RUN` / `INTEL_RUN_NOT_FOUND`. |
| `GET /api/v1/investigations/{case}/report/{id}?intel_run_id=` | PDF section **7A**, pinned to the run shown in the UI (latest if omitted). The run id is recorded in the `report_generated` audit event. |

## Local simulated verification

The P5a browser walk-through used a loopback stub on 127.0.0.1:8765 and the backend settings below.

- **Run mode:** `APP_ENV=test`, so live DNS, SPF and enrichment are off.
- **Simulation:** `INTEL_SIMULATED=1`, and fake keys of the form `test-key-not-real`.
- **Endpoints:** `INTEL_*_BASE` pointed at the stub.

Every run and PDF from that setup is labelled **SIMULATED providers (local stub) — not real provider data**.
