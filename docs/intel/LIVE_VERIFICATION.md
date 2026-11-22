# Live threat-intelligence verification (P5a-live)

**Date:** 2026-11-22. **Base commit:** `eceea44`. **Tier:** free/public API plans (non-commercial university
coursework).

This was the first time AIPISH called the real providers. Before this run, the adapters had been verified only
against mocks and a SIMULATED loopback stub. The run used rotated keys loaded from the local, gitignored `.env`
through the app's own config loader (`APP_ENV_FILE`). The keys were never copied into commands, files or logs.

## Scope: approved indicators only

| Kind | Indicator | Why it is safe to send |
|---|---|---|
| IP | `8.8.8.8`, `1.1.1.1` | Public DNS resolvers (Google, Cloudflare) |
| Domain | `example.com` | IANA reserved example domain |
| SHA-256 | `275a021b…651fd0f` | Standard EICAR test-file hash. **Hash lookup only**: the file and string were never created, stored or uploaded. |
| Tor | the public bulk exit list | Membership tested locally with `8.8.8.8` and one listed IP. The listed IP was never sent to any provider. |

No other indicator was sent to any provider. Every request was a `GET` with an empty body.

A temporary request hook recorded the method, host, path, query-parameter **names**, header **names** and body
length. The only values it recorded were the indicator parameters (`ipAddress`, `maxAgeInDays`, `minify`). It
proved that no other indicator was transmitted. The hook now ships disabled (see "Request audit hook" below).

## Requests per provider

The total was **16** outbound requests, under the target of about 20.

| Provider | Part A (adapter checks) | Part B (end-to-end UI) | Total |
|---|---:|---:|---:|
| VirusTotal | 4 (2 IP, 1 hash, 1 domain) | 1 | 5 |
| AbuseIPDB | 2 | 1 | 3 |
| Shodan | 2 | 1 | 3 |
| IPinfo | 2 | 1 | 3 |
| Tor bulk exit list | 1 | 1 | 2 |

VirusTotal calls were paced inside the public limit of 4 requests per minute. No provider returned 401, 403, 429
or a quota error, and the app's single retry was never needed.

## Results by provider

| Provider | Indicator | HTTP | AIPISH status | Notes on the real shape |
|---|---|---|---|---|
| VirusTotal | 8.8.8.8 | 200 | `record_found` (after the fix) | 1 malicious of 92 engines, reputation +567. **Previously `malicious_or_flagged`: defect 1.** |
| VirusTotal | 1.1.1.1 | 200 | `record_found` (after the fix) | 1 of 92 engines; same defect. |
| VirusTotal | EICAR SHA-256 | 200 | `malicious_or_flagged` | 65 of 67 verdict engines. The stats also include `type-unsupported`, `failure` and `confirmed-timeout`, which are correctly excluded from the total. |
| VirusTotal | example.com (service path) | none | `not_applicable_indicator` | Refused by policy (documentation domain) before any network call. This is correct. |
| VirusTotal | example.com (direct adapter fetch) | 200 | `reported_clean_no_flags` | 0 of 92 engines. One request was made to capture the domain shape. |
| AbuseIPDB | 8.8.8.8 / 1.1.1.1 | 200 | `record_found` | 217 and 290 reports, confidence 0 (below the threshold of 25), usage type "Content Delivery Network". |
| Shodan | 8.8.8.8 / 1.1.1.1 | 200 | `record_found` | The free plan **does** allow host lookups. Ports, org, ASN and hostnames were parsed. |
| IPinfo | 8.8.8.8 / 1.1.1.1 | 200 | `record_found` | City-level location and ASN. `anycast: true`. **No privacy block on the free plan**, so the VPN, proxy, Tor, relay and hosting flags stay `"unavailable"` (never `false`). |
| Tor list | 8.8.8.8 | 200 | `no_record` | The list held 1,263 IPs. |
| Tor list | one listed IP | (cached) | `malicious_or_flagged` | A local membership check; nothing was sent to other providers. |

**Rate-limit headers.** Only AbuseIPDB sent `X-RateLimit-Limit/Remaining/Reset`. VirusTotal, Shodan and IPinfo
sent none, so the local limiter is the only guard for those three.

## Behaviour verified with no extra requests

| Path | Result |
|---|---|
| Second run | Every lookup was served from the cache (`fresh`); 0 new requests. |
| VirusTotal limiter | A 5th call in the same minute was refused locally as `rate_limited`; 0 requests. |
| Missing credentials | With `IPINFO_TOKEN=""` in the process environment: `missing_credentials`; 0 requests. |
| Consent disabled | `not_attempted_consent_disabled`; 0 requests. |
| Offline with an empty cache | `not_attempted_offline`; 0 requests. |
| No record vs provider error | `no_record` (Tor 8.8.8.8) and `not_applicable_indicator` stay distinct from errors; no error paths were triggered live. |

## End-to-end run (Part B)

The fixture was the synthetic email `backend/tests/fixtures/eml/synthetic_public_hop_8888.eml`. Its only public
hop is `8.8.8.8`; every other name uses the `.test` suffix, which is refused before any network call. It was
uploaded to a throwaway SQLite database and backend. An analyst account gave on-demand consent and ran the lookup
from the **Threat intel** tab.

- **Threat intel tab.** It showed the real results with fetched timestamps:
  - VirusTotal, AbuseIPDB, Shodan and IPinfo: "Record found, no verdict";
  - Tor: "No record".
- **Geo tab.** It showed the real IPinfo location (Mountain View, AS15169), no SIMULATED label, and the new
  **Anycast** row.
- **Risk.** Combined risk stayed MINIMAL (2). The rules gave 15 (minimal) and ML gave legitimate (0.9795).
  Intel contributes nothing, because no provider flagged the IP.
- **Alerts.** None, as expected.
- **ATT&CK.**
  - **Before the fix:** the source type said *Anonymised sending infrastructure: likely*. **This is defect 3.**
  - **After the fix and a recompute** (from the stored run, with no new requests): *not indicated*, with no
    mappings.
- **Reports.** The PDF and HTML reports contain the real statuses and "not proof of safety", and no SIMULATED
  label.
- **Audit.** `threat_intel_lookup` recorded consent (`on_demand`), the providers and the counts, and no keys.
- **Screenshot QA.** Threat intel, Geo and ATT&CK were checked at 1440×900 and 1920×1080, with no horizontal
  overflow.

## Defects found and fixed

Each fix has an offline regression test built from a sanitised real-shape fixture in
`backend/tests/fixtures/intel/live_shapes/`. The tests are in `tests/unit/test_intel_live_shapes.py` and
`Geo.test.tsx`.

1. **VirusTotal flagged benign IPs on a single engine.**
   - **Defect:** for 8.8.8.8 and 1.1.1.1, one of 92 engines reported "malicious", and the adapter turned any
     non-zero count into `malicious_or_flagged`.
   - **Fix:** a new `INTEL_VT_FLAG_MIN_ENGINES` setting (default 3).
     - At or above the threshold, the result is `malicious_or_flagged`.
     - Between 1 and the threshold, it is `record_found`. The message says the detections are below the
       threshold, that isolated detections are often false positives, and that this is not proof of safety.
     - `flag_threshold` is stored in the result data.
   - **Effect:** the EICAR hash (65 engines) is still flagged.
2. **IPinfo anycast was not shown.**
   - **Defect:** the location of an anycast IP is only a representative point.
   - **Fix:** the adapter now stores `anycast` and adds a caveat to the message. The geo service passes the flag
     on, and the Geo tab's selected-IP panel shows an **Anycast** row.
3. **ATT&CK read "unavailable" IPinfo privacy flags as true.**
   - **Defect:** the free plan returns no privacy block, so `is_vpn`, `is_proxy` and `is_tor` hold the string
     `"unavailable"`. `attack/engine.py` tested them for truthiness and produced "IPinfo privacy flags: vpn,
     proxy, tor".
   - **Fix:** only an explicit `True` counts now. The Geo service and the frontend already required a real
     boolean.

## Request audit hook (off by default)

When `INTEL_REQUEST_LOG=/path/file.jsonl` is set, each outbound provider request appends one JSON line with
these fields:

- provider, method, host and path;
- query-parameter names;
- the values of `ipAddress`, `maxAgeInDays` and `minify` only;
- header names;
- body length.

Key values, `Authorization`/`key`/`x-apikey` header values and full URLs are never written; Shodan's `key` query
value is excluded. The hook is attached only to the app's own HTTP client. It is unset by default and is not set
in any shipped configuration.

## Secret scan

Each key value was loaded from `.env` and compared in code, raw and URL- or base64-encoded. No value was printed.
The scan covered:

- both throwaway databases (cache, intel runs, audit events);
- the backend log and both request logs;
- the raw response shapes;
- the PDF (raw and decompressed) and HTML reports;
- the browser session files;
- every test fixture;
- the full git diff, including new files.

**Result: not found** for all four keys in every location. All throwaway databases, logs, shapes, reports and
temporary accounts were then deleted.

## Still unverified live

- **Provider error mappings:** 401/403, 429, quota exhaustion, 5xx and timeouts were not triggered. They remain
  mocked-only.
- **Paid-plan fields:** IPinfo privacy flags and Shodan plan refusals (`not_permitted`).
- **VirusTotal:** domains through the service path (example.com is refused by policy) and URL lookups. The app
  does not look up URLs.
- **Network-wide behaviour:** the daily caps; and the Tor-listed IP was not sent to IPinfo, so how a Tor exit
  appears in IPinfo is unverified.
- **Other sources:** live upload-time ip-api enrichment, and MaxMind and MISP (blocked).

## Re-running

```
# rotate keys first; keep them only in the gitignored .env
AIPISH_RUN_LIVE=1 APP_ENV_FILE=/path/to/.env pytest tests/unit/test_intel.py -k live
```

The live test sends only the approved indicators above (11 cases) and paces VirusTotal at 16 s per call. It is
skipped by default and in CI.
