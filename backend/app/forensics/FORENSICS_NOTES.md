# Forensics & Authentication Documentation Summary

## Header Forensics Module (`app/forensics/headers.py`)

### Received-Header Order Convention
RFC 5321: the **bottom** Received header is the **first** hop (closest to the originator); the **top** one is the **last** (border MTA of the receiver). The engine iterates `parse()` output **reversed** so hop `#0` = first hop and the final hop = the receiver's own trace.

### Trusted-Boundary Rule
A hop is **trusted** when (evidence-based, documented rules):
- its `by` host matches a local-mx pattern (`mx.<receiver-domain>`, or receiver's own domain), **or**
- its `by` host's registrable domain equals the receiver's registrable domain.

Everything below (i.e. earlier in the chain) is `untrusted` — attacker-writable, per RFC 5321's own note that "an Internet mail program must not trust Received header text" before the receiver's own stamp.

### Confidence Rules (documented inline + in `LEARN/`)
| Signal | Points (0–100 on the hop) |
|---|---|
| Hop's `from` IP is a public address | +20 |
| Hop's from-host resolves == from-IP (or from-host present w/ matching IP) | +15 |
| Hop has TLS (`using TLS` in `with` or explicit `smtp.tls` keywords) | +10 |
| Hop has a parseable timestamp | +10 |
| Hop is at/after the trusted boundary | +25 |
| Hop is before boundary (untrusted zone) | cap at 0 authorized; score ≤ 40 |
| `from`/`by` hostnames both absent | −15 |
| Raw `Received` value contains binary garbage | −10 |
Clamped 0–100. The **earliest public candidate** is ranked by (trusted-first, hop-index, confidence).

### IP Classification (`classify_ip`)
- `private` (RFC1918 10/8, 172.16/12, 192.168/16),
- `loopback` (127/8, ::1),
- `link-local` (169.254/16, fe80::/10),
- `documentation` (RFC5737 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32),
- `reserved` (100.64/10, 192.0.0/24, 198.18/15, 240/4 etc.),
- else `public`.
Only **public** IPs may support a public-origin claim. Private/loopback/etc. are explicitly listed but **excluded** from origin claims.

### Candidate-Origin Logic
- **Candidate IPs** = all public from-IPs in the chain (there may be several).
- **Earliest candidate IP** = the earliest (lowest-index) public IP in the chain.
- **Verified originating IP** = earliest public IP whose hop *also* passes hop-confidence ≥ 60 and whose `from` host+IP pair agree.
These are distinct — the earliest candidate is a *candidate*; the verified origin requires extra evidence.

### Inconsistency Checks
- `reply_to_mismatch` (Reply-To domain ∉ sender's From domain),
- `returnpath_mismatch` (Return-Path domain ≠ From domain when both present). Since P5d.1 both sides
  are parsed with `email.utils` and normalised (case, trailing dot, IDNA); the null reverse-path `<>`
  never mismatches. The pre-fix comparison kept a trailing `>` and flagged almost every Return-Path; it
  survives only as the ML feature path's `legacy_domain_compare=True` (see docs/CHANGELOG.md),
- `messageid_domain_mismatch` (Message-ID's domain ≠ From's domain),
- `received_spf_mismatch` (Auth-Results `spf=fail` but Received header contains `spf=pass` or hairstory),
- `auth_results_spf_mismatch` (Auth-Results `spf=pass` vs Received `spf=fail`),
- `excess_hops` (>10 hops),
- `no_received` (no Received headers at all — can't reconstruct path),
- `gap_in_chain` (a trusted hop appears *below* an untrusted one).
Each finding carries `severity` (info/low/medium/high), `evidence` (quoted raw header excerpt), `rationale` (why it matters).

### Never Inferred
No human/physical location or identity is inferred from IPs. Output params only mention "originating **infrastructure**". A `disclaimer` field is always included in the result explaining IPv4's limits + forgery context and that no person/place is identified.

### Forgery Explanation
The result carries a `forgery_note`: Received headers added *before* the trusted boundary can be forged by the sender; only the receiving server's own trace is trustworthy — included verbatim in the response.

---

## Authentication Module (`app/auth/`)

### Status Vocabulary
Each of SPF, DKIM, DMARC is reported under exactly one of:
- `parsed` — a header **claim** exists but was not verified locally (untrusted claim, made by some intermediate server).
- `verified_pass` / `verified_fail` — locally **re-verified** against DNS.
- `unavailable` — the check couldn't run (DNS timeout, no resolver...), with `reason`.
- `unknown` — no evidence either way (no claim, nothing to verify).

A header claim is **never** accepted as verification: claims live in `claims`, local verification in `results`.

### SPF
1. Extract `mailfrom`/`from` domain from Authentication-Results claims (parsed status).
2. Live check via `pyspf.spf.check2(i, s, h)` against a real resolver (dnspython-backed) at **call time** (not at import; not in tests unless live).
3. Temp errors / DNS timeouts → `unavailable` with reason; no exception escapes.

### DKIM
1. Extract claims (parsed status).
2. Live check via `dkim.verify()` on the **original bytes**; requires that the message still carries its DKIM-Signature and the selector DNS key is fetchable.
3. Invalid tag/sig/bad base64/canonicalization errors → `verified_fail` with reason; missing DNS key or ns lookup failure → `unavailable`.

### DMARC
- Look up `_dmarc.<from-domain>` TXT.
- Organizational-domain fallback (3-label/suffix heuristic: for multi-label domains, try `org-domain` = slice to last 3 labels; no SILC needed for MVP).
- Parse policy (`p=`), subdomain policy (`sp=`), and pct.
- Checks alignment: **relaxed** mode — the RFC5321.MailFrom domain or its org-domain must match the From header's org-domain. Strict `aspf`/`adkim` mode → exact-match requirement is flagged as an admin config note.

### Alignment
`alignment` field: `aligned | misaligned | unknown`, computed for:
- SPF: envelope-from (Return-Path / received-SPF mailfrom) vs From domain (relaxed = same org domain).
- DKIM: any `d=` tag vs From domain (relaxed = same org domain).
- DMARC has its own pass/fail per policy; alignment is separate from DMARC status.

### Timeouts and Safe DNS
- A shared `safe_dns_query(name, type, timeout)` wraps `dns.resolver` with `timeout + lifetime` guards, catching `Timeout`, `NXDOMAIN`, `NoAnswer`, `NoNameservers`, and any other exception → return None + typed reason. Never raises to the caller.

### Threat-Score Integration
- 3 indicators bridge the auth result into detection:
  - `auth_conflict` = 20 (auth-Results claims conflict with locally-verified results).
  - `auth_alleged_fail` = 15 (a verified_fail in every protocol).
  - `auth_parse_only` = 0 — claims without verification add nothing.
  - Per protocol stats reflects statuses elsewhere in the report (explanation layer).
- Weights live in `app/detection/config.py` (one place), exactly like other rules.

### Privacy / Safety
No test emails are sent, no unauthorized mail-server actions; only read-only DNS queries. All network activity is limited to **policy record lookups** (DNS TXT / public-key TXT); nothing is sent to any mail server.
