# Infrastructure geolocation map and analytics (P5g)

> Approximate infrastructure location from IP data. It is not the sender's physical location and does
> not identify a person. VPN, proxy, hosting and Tor distort results.

This disclaimer is shown on every map and geo surface: the analysis Geo tab, the campaign panel, the
analytics geo charts and the API responses.

## What is shown

| Surface | Endpoint (permission) | Content |
|---|---|---|
| Analysis → **Geo** tab | `GET /api/v1/analyses/{id}/geo` (`analysis:read`, viewer+) | Map of located IPs; table of every IP, including those with **no location data**; selected-IP facts; anonymity signals |
| Campaign detail → **Infrastructure locations** | `GET /api/v1/campaigns/{id}/geo` (`correlation:read`, viewer+) | Member IPs deduplicated, with the number of member messages per IP |
| **Analytics** page | `GET /api/v1/analytics/summary?days=N` (`analysis:read`, viewer+; N is 1–365) | Verdicts, ML classes, analyses per day, score histogram, top sender domains (generic ones labelled), origin countries and ASNs with a coverage figure, ATT&CK technique frequency, campaign sizes, threat-intel coverage |
| Status bar | `GET /api/v1/system/info` (`analysis:read`) and `GET /api/v1/health/ready` (anonymous) | Version, environment and database for signed-in users. P5g hardening: anonymous `GET /api/v1/health` now returns only `{"status"}`. |

None of these endpoints is anonymous, and none performs a lookup.

## Data rules

- **No new external lookups.** The geo views read only data already stored. Per IP, in this order:
  1. The latest *consented* threat-intel run: IPinfo `approx_coordinates`, country, region, city, ASN
     and org; IPinfo privacy flags; Tor exit-list membership; AbuseIPDB Tor flag and usage type.
     Declined runs are ignored.
  2. The upload-time IP-geolocation enrichment (`ipgeo_http`, ip-api.com; see its licence caveats in
     `.env.example`).
  3. Stored `geo_observation` rows. Today these are **only SIMULATED demo data** (see below).
- **Which IPs:** only public (globally routable) IPs from:
  - the relay chain (`trusted_relay` / `untrusted_relay`, with the hop number);
  - the origin candidate (`origin_candidate`);
  - IP-literal URL hosts, and recorded DNS A records of URL hosts (`url_host_ip`).

  Private and reserved addresses are never returned, and no recipient data is used.
- **No coordinates:** an IP without stored coordinates (or with invalid ones) appears in the table as
  "no location data", never on the map.
- **Every point carries:**
  - IP, role(s), hop;
  - latitude/longitude, country, region/city, ASN/org/ISP when present;
  - source and provider, `fetched_at`;
  - `stale` (served from an expired provider cache) and `simulated` flags;
  - an accuracy note.

  Stale and SIMULATED points are tagged in the UI.
- **Anonymity signals** (Tor, VPN, proxy, relay, hosting) are `reported` / `not reported` only when a
  stored provider result backs them. Otherwise they show **"not available"**; a missing result is never
  read as "no VPN".
- **Relay order:** no route line is drawn by default. A "Show relay order" toggle (off by default) draws
  a dashed line labelled "relay order, not a physical route".
- **Analytics:**
  - Server-side and bounded: the most recent 2,000 analyses are used for JSON-derived aggregates, at most
    365 days, and top-10/15 lists.
  - Dialect-safe: portable `GROUP BY`; date buckets and histograms are computed in Python. Verified on
    SQLite and PostgreSQL.
  - Counts only: no subjects, bodies or addresses.
  - Countries and ASNs use the origin candidate if it is located, else the first located IP, with a
    coverage figure ("x of y analyses have geo data").

## SIMULATED demo data

The demo seeding (`python -m app.cli init-demo` and `seed-demo-campaign`; opt-in, refused in production,
offline) stores `geo_observation` rows with `source="simulated-demo"` and `simulated=true`:
- They cover only the public IPs of the committed synthetic fixtures (matched by SHA-256).
- Locations are generic city centroids (Frankfurt, Amsterdam, Ashburn, Singapore, …).
- ASNs come from the RFC 5398 documentation range (AS64496–AS64511), and organisations are named
  "SIMULATED …".
- The UI tags them **"SIMULATED demo data"** everywhere: map header, table, side panel, anonymity table
  and analytics notes.

The synthetic BEC sample carries no public IP (no `Received` hops, no IP URL hosts), so its Geo tab
correctly shows the "no public IP addresses" state.

**Real-data verification:**
- **Rendering and data shaping:** verified with tests and in the browser (SIMULATED data).
- **Real locations:** depend on the upload-time ip-api enrichment (live; offline/demo modes skip it) or
  on consented live IPinfo results. **Live IPinfo was not verified** (no live provider calls in this
  phase).
- **MaxMind GeoIP2 (R48)** remains blocked (no licence or database).

## Privacy and the no-tiles decision

- **Outline only:** the map is a dark vector outline of country borders bundled in the build. There are
  no map tiles, tile servers, CDNs or geocoding calls.
- **No external requests:** opening a map makes zero external requests (checked in the browser network
  panel). Under the strict nginx CSP, `connect-src 'self'` and `img-src 'self' data: blob:` would block
  them anyway.
- **Why:** this avoids sending the analyst's viewing activity (which IPs and regions they look at) to
  third parties, and keeps the app working offline.
- **Plotly** is loaded lazily from the build. Its mode bar, links and "send data" features are disabled,
  and it makes no requests.
- **CSP:** unchanged from P5i. Leaflet and Plotly need no `unsafe-eval`; inline `style` attributes were
  already permitted (`style-src 'self' 'unsafe-inline'`). Verified through nginx with zero CSP violations.

## Attributions and licences

| Component | Licence | Use |
|---|---|---|
| [Leaflet](https://leafletjs.com) 1.9.4 | BSD-2-Clause | Map rendering (lazy chunk) |
| [world-atlas](https://github.com/topojson/world-atlas) 2.0.2 (`countries-110m`) | ISC; data from [Natural Earth](https://www.naturalearthdata.com), public domain | Country outline |
| [topojson-client](https://github.com/topojson/topojson-client) 3.1.0 | ISC | TopoJSON → GeoJSON |
| [plotly.js-basic-dist-min](https://github.com/plotly/plotly.js) 4.3.0 | MIT | Analytics charts (lazy chunk) |

The in-UI attribution line under every map reads: "Outline: Natural Earth (public domain) via world-atlas
· Map: Leaflet (BSD-2-Clause) · no map tiles or external requests".

## Bundle impact

| Asset | Before P5g | After P5g |
|---|---|---|
| Main JS | 774.91 kB (gzip 239.94) | 796.67 kB (gzip 246.81) |
| Main CSS | 22.42 kB | 24.20 kB |
| `GeoMap` chunk (lazy) | — | 260.09 kB JS (gzip 84.14) + 15.04 kB CSS |
| Plotly chunk (lazy) | — | 1,217.86 kB (gzip 406.39) |

The two lazy chunks load only when a Geo tab, a campaign detail page or the Analytics page is opened.
