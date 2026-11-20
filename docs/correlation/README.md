# Cross-case correlation and candidate campaigns (P5c)

AIPISH records the technical indicators of every analysis in a persistent store. It links analyses that
share **non-generic** infrastructure and groups linked analyses into **candidate campaigns**.

> **Shared infrastructure does not identify a human.** A candidate campaign groups emails that share
> technical indicators (IPs, domains, hashes). It is not proof of a common sender, attacker or person.
> The UI, API and PDF always say "shared infrastructure / candidate campaign", never "same attacker".

Correlation is **informational only**. It never changes the rule score, ML result, threat-intel run or
verdict of any analysis.

## Data model (source of truth)

All tables are additive. They are created by `run_additive_migrations()`, which runs at app start **and**
in every CLI command (lesson from P5b).

| Table | Contents |
|---|---|
| `corr_entity` | `type`, `normalized_value` (unique together), `first_seen`, `last_seen` |
| `corr_observation` | `entity_id`, `analysis_id`, `role`, `source_field` (the evidence reference), `observed_at`; unique on (entity, analysis, role, source_field) |
| `corr_campaign` | `number`, `label` ("Candidate campaign C-0001"), `status` (`candidate` / `merged` / `dissolved`), `confidence` (low / medium / high), `confidence_score`, structured `reasons`, `fingerprint`, `merged_into`, `version`, timestamps |
| `corr_campaign_member` | `campaign_id`, `analysis_id` |
| `corr_state` | per-analysis `status` (`ok` / `error`) and the error *type* only |

Search indexes are also added to `analysis(from_domain, detection_verdict, created_at)`, idempotently.

**Evidence references:** `source_field` is the exact field of the stored analysis an indicator came from,
for example:
- `forensics.verified_originating_ip`
- `forensics.relay_chain[3].from_ip`
- `reply_to[0]`
- `urls[2].host`
- `attachments[0].sha256`

The LLM evidence ids (E1, E2, …) are generated per prompt and are not persisted, so they are not used here.

## Entities and normalisation

| Type | Role(s) | Source |
|---|---|---|
| `public_ip` | `origin_candidate_ip` | Forensics engine's verified, earliest and candidate origin IPs |
| `public_ip` | `relay_ip` | From-IP of **untrusted** Received hops only |
| `public_ip` | `url_host_ip` | URL whose host is a bare public IP |
| `sender_domain`, `reply_to_domain`, `return_path_domain`, `message_id_domain` | same name | Headers |
| `url_host` | `url_host` | URL hosts |
| `attachment_hash` | `attachment_sha256` | Attachment SHA-256 |
| `display_name_alias` | `display_name` | From display name: NFKC, case-folded, punctuation and whitespace collapsed |

**Normalisation rules:**
- **IPs:** only addresses accepted by the P5a validation helper (`app.intel.validate.validate_ip`). That
  helper rejects private, loopback, link-local, CGNAT, documentation and reserved addresses, and
  normalises IPv4-mapped addresses.
- **Domains:** lower-case, IDNA / punycode, trailing dot stripped, at least two labels, never an IP literal.
- **Never entities:**
  - private or reserved IPs;
  - from-IPs of **trusted** hops that the forensics engine did not select as origin candidates (these
    are our own receiving relays);
  - IPs of hops whose host is on the stoplist (identifiable provider infrastructure, e.g.
    `*.outlook.com`, `*.amazonses.com`).
- **Not implemented:** lookalike and homoglyph similarity. It could not be made reliable cheaply.

## Link strength (`backend/app/correlation/config.py`)

| Indicator (type / role) | Tier | Weight |
|---|---|---|
| attachment_hash | **strong** | 0.90 |
| public_ip as origin candidate ("medium-strong") | medium | 0.60 |
| url_host | medium | 0.50 |
| public_ip as URL host | medium | 0.50 |
| reply_to_domain | medium | 0.50 |
| return_path_domain | weak | 0.30 |
| sender_domain (non-freemail; freemail is stop-listed) | weak | 0.30 |
| message_id_domain | weak | 0.15 |
| public_ip as untrusted relay | weak | 0.15 |
| display_name_alias | weak | 0.10 |

### How a pair of analyses is scored
- **Conservative roles:** an entity seen in different roles in the two analyses is scored at the weaker
  role. For example, an origin IP in one and a relay IP in the other counts as a relay (0.15).
- **Independence:** the same value seen in several roles counts once, at its strongest. For example,
  `corp.test` as sender, Return-Path and Message-ID domain is one indicator.
- **Score:** `1 − Π(1 − weight)` over the independent indicators.
- **Link rule:** a pair is linked only if it shares **at least one strong** indicator, **or at least two
  independent indicator types of which one is medium or strong**. Consequences:
  - one weak indicator never links;
  - two weak types never link;
  - one medium type alone never links.

  The spec asked for "one strong OR two types". Requiring one of the two types to be medium or strong is
  deliberately stricter.
- **Confidence:**
  - `high` if a strong indicator is shared or the score is at least 0.85;
  - `medium` if the score is at least 0.60;
  - otherwise `low`.
- **Example:** the synthetic demo campaign shares an origin IP (0.6), a reply-to domain (0.5) and a
  display name (0.1). That gives 1 − 0.4·0.5·0.9 = **0.82, medium**.

## Generic-indicator protection

1. **Stoplist:** a data file, `backend/app/correlation/stoplist.txt`.
   - Covers freemail, bulk mailers, large mail and cloud providers, link shorteners, document hosts and
     markup hosts.
   - Subdomains match (e.g. `fonts.gstatic.com` matches `gstatic.com`).
   - Extend it with `AIPISH_CORR_STOPLIST_EXTRA="a.com,b.net"`, or replace it with
     `AIPISH_CORR_STOPLIST_FILE=/path`.
   - Stop-listed values are still stored, so they remain searchable, but they carry **zero** link weight.
2. **Trusted relays:** never entities (see above).
3. **Document-frequency damping:** df = the number of **distinct messages** (raw SHA-256) observing an
   entity.
   - df > `AIPISH_CORR_DF_SOFT` (default 10): the weight is halved and the tier drops one step.
   - df > `AIPISH_CORR_DF_MAX` (default 25): the entity is treated as generic and never links.
4. **Identical re-submissions:**
   - The same `.eml` uploaded again (same SHA-256) is a duplicate, not independent evidence.
   - Such analyses never link to each other, never inflate df, and appear as "duplicate submissions" in
     the per-analysis view.
   - Background: the P5c backfill of the dev database found 9 apparent "campaigns" that were each one
     test fixture uploaded many times. This rule removed them.
5. **Freemail-only overlap:** shares only generic indicators, so it never links. The per-analysis view
   says so explicitly.

## Campaign detection (NetworkX)

1. Build links between all pairs of analyses that share non-generic entities (`pair_links`).
2. Build a `networkx.Graph` of the qualifying links. Every **connected component** with at least 2
   analyses is one candidate campaign.
3. Keep campaign ids stable across recomputes:
   - a component keeps the id of the existing candidate it overlaps most (tie: lowest number);
   - **merge:** if a new analysis bridges two candidates, they become one (the older keeps its id); the
     others become `merged`, with `merged_into` set;
   - a candidate left with no qualifying component becomes `dissolved`;
   - rows are never deleted, so PDFs and audit references stay resolvable.
4. **Determinism and idempotency:**
   - all inputs are sorted;
   - each campaign stores a fingerprint of members, reasons, score and confidence;
   - an unchanged campaign keeps its version, and any real change bumps it;
   - `rebuild-correlation` run twice gives identical results.
5. **Campaign confidence** is the mean score of its qualifying links, labelled with the thresholds above.
   **Reasons** list every shared entity with its type, tier, weight, member analyses and evidence
   references, plus every link with its explanation.

## Pipeline integration and failure isolation

- After `POST /api/v1/analyses` (and the upload-and-assess path) has committed the analysis **and**
  built its response, `correlate_safely()` records observations and recomputes campaigns.
- Any exception is caught: correlation is rolled back, `corr_state` is set to `error` with only the
  exception type, and a safe log line is written. The analysis and its response are unchanged; a test
  forces a failure and compares the responses.
- Each upload triggers a full, deterministic recompute. This took about 1.1 s on the dev database
  (1,303 analyses, about 80,000 candidate pairs); see Limits.

## API (central permission map)

| Method and path | Permission | Roles |
|---|---|---|
| `GET /api/v1/analyses/{id}/correlation` | `correlation:read` | viewer, analyst, admin |
| `GET /api/v1/campaigns[?status=all]` | `correlation:read` | viewer, analyst, admin |
| `GET /api/v1/campaigns/{id}` (members, reasons, graph nodes and edges) | `correlation:read` | viewer, analyst, admin |
| `GET /api/v1/graph/entities/{type}/{value}` (entity neighbourhood) | `correlation:read` | viewer, analyst, admin |
| `GET /api/v1/search?q=&type=&verdict=&entity_type=&date_from=&date_to=&limit=&offset=` | `search:read` | viewer, analyst, admin |
| `GET /api/v1/investigations/{case}/analyses` | `case:read` | viewer, analyst, admin |
| `GET /api/v1/investigations/{case}/indicators` | `case:read` | viewer, analyst, admin |
| `POST /api/v1/investigations/{case}/analyses` body `{"analysis_id"}` (409 if already a member) | `case:write` | analyst, admin |
| `DELETE /api/v1/investigations/{case}/analyses/{analysis}` | `case:write` | analyst, admin |
| `POST /api/v1/correlation/rebuild` | `correlation:rebuild` | **admin** |

**Search details:**
- Uses indexed `LIKE` / prefix matching with bound parameters only; `%`, `_` and `\` in input are escaped.
- `limit` is at most 50 and `offset` at most 10,000; queries are at most 200 characters.
- Email bodies are never searched or returned.

**Audit events:**
- `case_analysis_added` and `case_analysis_removed`, with the actor;
- `correlation_rebuilt`, with the actor (via the API) or `source: cli`;
- `report_generated` now records the campaign ids and versions printed in the PDF.

**Not implemented:** linking a case to a campaign directly. The case page shows each member's campaigns
instead.

## PDF

Section **7B "Related Analyses / Candidate Campaigns"** is a snapshot of the correlation at report time
(the snapshot time is printed). It contains:
- campaign label, confidence, member count, id and **version**;
- related analyses, whether each is linked, the score and the shared indicators;
- a note on any generic-only overlaps;
- the link rule and the disclaimer.

Without links it prints *"No related analyses recorded at report time. This is not a claim that the
message is unique."* All text is escaped.

## CLI

```bash
python -m app.cli rebuild-correlation   # backfill + recompute; idempotent, deterministic
python -m app.cli seed-demo-campaign    # APP_ENV=dev only; synthetic emails through the real pipeline
python -m app.cli disable-user --username NAME   # used to retire temporary verification accounts
```

### Synthetic demo data (`backend/tests/fixtures/demo/campaign/`)

- All domains use the reserved `.test` TLD.
- Names, invoices and infrastructure are invented, and every message and the demo case are marked
  SYNTHETIC.
- The IP addresses reuse the project's existing fixture conventions, and say nothing about their real
  operators.
- The seed runs the emails through `upload_eml` with external lookups off, and skips emails already
  present (by SHA-256).

| File | Shares | Expected result |
|---|---|---|
| `campaign_member_1..4.eml` | Origin IP 96.7.128.175 and Reply-To `vendor-remit-portal.test` (sender `outlook.com`, stop-listed) | One candidate campaign, medium (0.82) |
| `freemail_only.eml` | Only `outlook.com`, via an `outlook.com` relay host that is excluded as provider infrastructure | Not linked; shown as a generic-only overlap |
| `unrelated.eml` | Nothing | No related analyses |

## Limits

- **Heuristic thresholds:** the weights and thresholds are tuned on synthetic data only. There are no
  real-world campaign labels to validate them against.
- **No analyst overrides:** analysts cannot confirm, reject or rename a campaign, and no such decision is
  stored.
- **Full recompute per upload:** each upload recomputes all campaigns synchronously (about 1 s at
  1,300 analyses). It needs incremental updates or a background job beyond a few thousand analyses
  (R35).
- **Connected components can chain:** A–B and B–C put A and C together even if A and C share nothing.
  The reasons list each link so this is visible.
- **Shared hosting and NAT:** an origin IP can still be shared hosting or carrier NAT, and the stoplist
  catches only known providers.
- **Dev database inflation:** the dev DB contains hundreds of re-uploads of a few project fixtures from
  earlier phases. They now count as duplicates, but campaign member counts include them.
- **Storage choice:** SQLite plus in-process NetworkX; no Neo4j (R50) or OpenSearch (R52).
