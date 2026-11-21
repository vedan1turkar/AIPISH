# AIPISH design system (P5u-1, P5u-2, P5g, P5e, P5h)

The goal is a calm, dense security-engineering console: information-rich, organised and easy to scan.
Hierarchy comes from type weight and tonal surface steps, not from boxes, shadows or colour.

The reference products studied were Snyk, Tailscale and Wiz. They were used for density, grid and rhythm
only; nothing (logos, text, imagery, icons, colours or branding) was copied. Takeaways:
- one strong accent on near-black;
- small uppercase mono labels;
- strict left-aligned grid edges;
- quiet body text beside a single focal element.

## Design balance: clean AND dense (binding rules)

The target is information-rich but calm. Intentional breathing room is good; dead blank space is not.

1. **One focal element per screen.** Secondary information is quieter (muted, smaller) and never competes.
2. **Spacing scale 4/8/12/16/24/32.** Panel padding 12–16px; 16px between panels; 12–16px between groups;
   table rows 32–36px. Never squeeze to fit more in.
3. **Progressive disclosure.** Essentials first; detail behind tabs, "show details" or "view all". Raw dumps
   are collapsed.
4. **12-column grid.** Aligned left edges, label and value columns in KV rows, numbers right-aligned.
5. **Fewer boxes.** A panel has a title strip and a 1px border; inside, use dividers or whitespace. At most
   page › panel › rows; no cards inside cards.
6. **Restrained colour.** Neutral everywhere; colour only for status and the single cyan accent (links,
   active tab, primary button).
7. **Restrained type.** Four sizes and two weights (600 for headlines). Mono for data and labels, never for
   prose.
8. **Subtle retro cues.** Only title strips, square LEDs, the status bar, mono data and KV rows.
9. **Overview.** At most five panels in a tidy grid; every panel has real data or one clean empty line.
10. **Review both ways.** Look for blank regions that look like missing content, and for areas that are
    crowded or have competing borders or colours. Prefer fewer, better-organised elements.

## Tokens

All tokens are CSS variables in `frontend/src/index.css`, mapped in `frontend/tailwind.config.js`. Dark is
the only theme.

| Token | Value | Use |
|---|---|---|
| `bg` | `#0a0e13` | Page background |
| `surface` | `#10161d` | Panels, top bar, status bar |
| `surface-2` | `#151c25` | Inset groups, table header hover, skeletons |
| `surface-3` | `#1b2430` | Hover / active tonal step |
| `line` | `#2a3441` | 1px borders and dividers |
| `line-strong` | `#3a4757` | Control borders, popover offset |
| `fg` | `#dbe3ea` | Body text |
| `muted` | `#8593a1` | Secondary text, labels |
| `accent` | `#4cc9f0` | Links, active tab, primary button (the only decorative colour) |
| `ok` / `warn` / `danger` | `#3fb950` / `#e3a008` / `#f0524f` | Status only, always with a text label |
| `*-weak`, `*-line` | dark tints | Badge and alert fill and border for each status colour |

**Contrast (WCAG AA ≥ 4.5:1, computed):**

| Pair | Ratio |
|---|---|
| `fg` on every surface | 12.1–14.9 |
| `muted` on every surface | 5.0–6.2 |
| `accent` / `ok` / `warn` / `danger` on `surface` | 9.5 / 7.2 / 8.1 / 5.2 |
| Each status colour on its own weak tint | ≥ 5.0 |
| Dark text on accent / danger / ok / warn fills (buttons) | ≥ 5.2 |

No pair fails.

**Other scales:**
- **Type:** IBM Plex Sans (UI) and IBM Plex Mono (data, IDs, IPs, hashes, timestamps, evidence refs, panel
  labels, table headers).
  - Self-hosted with `@fontsource` (Latin subset; sans 400/500/600, mono 400/500); there are no CDN calls,
    so the app works offline.
  - Tabular numerals are on globally.
- **Sizes:** exactly four: `xs` 11px (mono labels), `sm` 13px (meta / table), `base` 14px (body), `lg`/`xl`
  18–20px (headlines). Larger utilities are clamped to 20px.
- **Weights:** 400 / 500, and 600 for headlines (`bold` maps to 600).
- **Radius:** every `rounded-*` utility resolves to `0`; `rounded-sm` is 2px, for small badges only.
- **Shadows:** all off. `shadow-pop` (a 1px hard offset) is reserved for popovers.
- **Spacing:** 4 / 8 / 12 / 16 / 24 / 32.
  - Panel padding 12px.
  - 16px between panels; 12–16px between groups inside a panel.
  - Table rows 34px (`h-row`).
  - Content maximum 1680px (`max-w-content`), centred.

## Primitives (`frontend/src/components/ui/`)

| Primitive | Purpose |
|---|---|
| `Panel` | 1px border, title strip (11px mono uppercase label left, meta / actions right, bottom border), body padding 12px |
| `DataTable` | Sticky mono header, 34px rows, right-aligned numbers, hover tonal row, one-line empty state; optional sortable headers (`sortValue`, `aria-sort`), compact pagination (`pageSize`), `hideBelow` for secondary columns on narrow screens, `rowTestId` |
| `StatusTag` / `Badge`, `StatusBadge`, `SeverityChip` | Square LED + text label, toned border and tint (2px max radius) |
| `LED` | 8×8 square status light (never used alone) |
| `Button` | `primary` (accent fill) / `secondary` / `danger` / `ghost`; square; `sm` 28px, `md` 32px |
| `Field`, `Input`, `Select` | Mono uppercase label above a 32px square control |
| `KV` / `MetaRow` | Key-value register row: aligned label column, value column |
| `StatCell` | Label (+ LED), mono number, muted sub-line |
| `Tabs` | Square tab strip; active = tonal fill + accent top rule; arrow-key navigation |
| `EmptyLine` / `EmptyState` | One compact line: what is missing, why, and the next action |
| `CodeBlock` | Raw dumps (headers, hex, JSON), collapsed by default |
| `Mono` | Mono value that copies itself on click; can display a shortened form while copying the full value |
| `SkeletonRows` | Compact loading rows (`role=status`, labelled) |
| `PageNotice` | Whole-page state (404, 403, no analysis open): title strip, status code, one line, actions |
| `Label` | Mono label |

Shell components:
- `shell/StatusBar` is the bottom status bar. It polls every 30 s and shows API and ML for everyone, and LLM
  and intel mode only for roles holding `config:status`. Failures appear as text.
- `VerdictStrip` is the focal element of an analysis.

## Rules

**Do:**
- Give every screen one focal element: the posture row on Overview, the verdict strip on an analysis.
- Keep secondary information quieter (muted, 13px).
- Use a 12-column grid with aligned left edges; panels in a row either size to content (`items-start`) or
  share equal height without dead space.
- Inside a panel, separate groups with 1px dividers or whitespace, with at most two nesting levels
  (page › panel › rows).
- Use progressive disclosure: limits plus "view all", tabs, and collapsed raw dumps.
- Pair colour with text every time (LED + label). Keep rule-based and ML/AI results in separate,
  labelled cells.
- Keep a visible 2px square focus outline; hover changes tone only; respect `prefers-reduced-motion`.

**Don't:**
- Use rounded corners above 2px, gradients, blur or glass, glow, soft shadows, emoji, hero sections or
  decorative illustrations.
- Put cards inside cards inside panels; build tall blank empty states; use decorative colour or more than
  one accent per area.
- Use mono for running prose.
- Use retro clichés: Matrix rain, typing or boot animations, scanlines, blinking cursors, neon,
  skeuomorphic hardware.
- Add an icon library. Use text labels, square LEDs, or short mono codes (for example the threat-intel
  status codes `FLG`, `ERR`, `RTL`).

**Guards** (`components/ui/Primitives.test.tsx`) scan every non-test file under `src` (a test asserts the
pages, graph and shell modules are in the scanned set) and fail the suite on:
- any `rounded`, `rounded-md/lg/xl/2xl/3xl/full` class;
- any emoji pictograph;
- any legacy Tailwind palette class (`text-gray-500`, `bg-white`, `ring-indigo-400`…): semantic tokens only;
- any hex colour outside `index.css` and the graph theme module;
- a change to the radius or shadow scale.

## Compatibility layer (removed in P5u-2)

Part 1 mapped legacy palette names onto the dark tokens so unmigrated pages stayed on-theme. In P5u-2 every
class was migrated to the semantic tokens (690 classes in 16 files) and the mapping was deleted from
`tailwind.config.js`; the colour scale now holds only the tokens above. The palette guard keeps it that way.

## Graphs

Both Cytoscape graphs (relay trace and campaign) use one theme module, `components/graph/style.tsx`.
Cytoscape cannot read CSS variables, so it mirrors the token hex values.

- **Shapes encode kind, never colour:**
  - message / analysis: rectangle (on `surface-3`);
  - IP: diamond;
  - domain or host: square;
  - URL: dashed square;
  - relay host, hash, display name: small flat rectangle.
  - No hexagons, ellipses or rounded shapes; unknown kinds fall back to a square.
- **Nodes:** `surface-2` fill; 1px border coloured by provenance (observed = ok, enriched = accent,
  inferred = muted and dimmed); 2px border coloured by finding severity or indicator tier; IBM Plex Mono
  labels at 10px.
- **Edges:** 1px, muted (`line-strong`, or `muted` for observed evidence), with mono type labels at 8px;
  inferred edges are dashed.
- **Selection:** accent border and edge.
- **Canvas:** `surface`, on the dark page.
- **Controls:** square `+`, `−`, `fit` (and `rst` for the trace) buttons, top right.
- **Fit:** zoom is capped (1.25 on the trace, 1.0 on campaigns) so small graphs never inflate labels.
- **Legend:** an inline-SVG shape glyph plus a text label per kind, with evidence and edge keys.
- **Sizing:** the canvas stretches to the height of its row (side column) and follows container resizes.
- **Behaviour:** layouts, tap/hover handlers and navigation are unchanged.

## Maps and charts (P5g)

**Map** (`components/geo/GeoMap.tsx`, lazy chunk):
- **Layers:** Leaflet with **no tile layer**. The only layer is the bundled Natural Earth outline: land
  `surface-2`, borders `line-strong` at 0.6px, sea `bg`.
- **Markers:** **diamonds**, 10px, with a 1px `bg` border; diamond means IP, matching the graph legend.
  Colour by role is always paired with text (legend, table, side panel):

  | Role | Colour |
  |---|---|
  | origin candidate | accent |
  | untrusted relay | warn |
  | trusted relay | ok |
  | URL host IP | fg |

  Hop numbers and campaign counts (`×4`) sit in small mono square labels. The selected marker gets a 2px
  accent outline; focused markers get the 2px accent focus ring.
- **Controls:** the shared square `+` / `−` / `fit` controls from `graph/style`. No Leaflet zoom or
  attribution controls and no popups, so nothing rounded. Attribution is a mono line under the map.
- **Relay order:** a dashed 1px `muted` line, **off by default**, labelled "relay order, not a physical
  route".
- **Layout:** map panel (8 columns, stretches to the row) beside a 4-column side column: a compact IP
  table, including IPs without coordinates, and the selected IP's KV rows. The first IP is preselected so
  the side column is never empty. The anonymity-signals table runs full width below.
- **Required text:** the disclaimer strip (warn LED) is always first, in every state; SIMULATED and stale
  are warn `StatusTag`s.

**Charts** (`components/analytics/Chart.tsx`, Plotly basic, lazy chunk):
- **Theme:**
  - transparent paper and plot backgrounds;
  - IBM Plex Mono 10–11px in `muted`; grid `line`, axes `line-strong`;
  - square bars with no outline;
  - accent for neutral counts; status colours only for verdict bars (danger, warn, muted);
  - generic (stop-listed) domains in `muted` and labelled "(generic)".
- **Behaviour:** integer ticks on count axes. No mode bar, logo, links, animation or legends; text labels
  carry the meaning.
- **Accessibility:** every chart has a `role="img"` text summary and a square "table / chart" toggle
  (`aria-pressed`). Empty data is one `EmptyLine`. If Plotly cannot load, the table is shown.
- **Layout:** a 12-column grid whose rows stretch to equal height (no ragged edges), led by a four-cell
  stat strip. Coverage notes and SIMULATED tags appear under the relevant charts.

## Audit, retention, custody and masking (P5e)

**Audit page** (`components/admin/AuditPage.tsx`, admin):
- Row 1 is a stretched 6 + 6 grid: **Chain integrity** (KV rows, `Verify now`) beside **External
  checkpoint** (latest tip, create, CSV / JSON export).
- The chain state is one `StatusTag`: ok "chain OK" or danger "chain BROKEN". A broken chain always
  shows the first broken seq and the reason in text.
- Below is the events panel: a filter form (7 columns at xl), then a `DataTable` with server pagination
  (Newer / Older). Seq and hash prefixes are mono, outcome is a `StatusTag`, and details are truncated to
  one line with the full text in `title`.
- The guarantee sentence sits under the `h1` in `muted`. Never use "immutable", "WORM" or
  "tamper-proof" as a claim.

**Retention page** (`components/admin/RetentionPage.tsx`, admin):
- A four-cell stat strip, then **Policy** (5 columns; an enabled or disabled tag) beside **Run**
  (7 columns).
- **Run** always previews first (dry run). Apply opens a dialog that names the mode and counts and is
  enabled only when `APPLY` is typed. The button is the `danger` variant.
- Legal holds: a 12-column inline form (target, id, reason of 3 characters or more), then a table with a
  per-row clear that requires a reason.
- The page states that there is no built-in scheduler.

**Custody tab** (analysis page, `custody:read`): a stretched 8 + 4 grid. The timeline `DataTable` has the
audit guarantee as its footer. The **Evidence integrity** KV panel (`h-full`) ends with the SHA-256
integrity note.

**Retention and masking states** (`components/audit/badges.tsx`):

| State | Treatment |
|---|---|
| redacted | warn `StatusTag` "redacted" |
| evidence purged | neutral "evidence purged" |
| legal hold | accent "legal hold" |
| masked field | neutral "restricted" tag (title explains role restriction vs redaction) in place of the value |

- Tags appear in the analysis header, the History "Retention" column and Case member rows.
- Redacted (warn LED) and masked (neutral LED) analyses get a one-line banner strip above the tabs.
- Colour is always paired with text.

## Combined risk (P5h)

- **Verdict strip:**
  - The cells are rule engine · ML classifier · **Combined risk · index** · source type · threat intel ·
    evidence.
  - The strip is 3 × 2 below 2xl and a single row of six at 2xl, so no cell truncates the rule verdict.
  - The combined cell is its own labelled cell (LED + score + level, sub-line "confidence … · not a
    probability"). It never merges with or replaces the rule or ML cells.
  - The ML cell falls back to the stored upload-time classification, labelled as such.
- **Level tones** (`components/risk/level.tsx`):

  | Level | Tone |
  |---|---|
  | minimal | ok |
  | low | neutral |
  | medium | warn |
  | high, critical | danger |
  | indeterminate | neutral |

  Tones are always shown with the level text.
- **Risk tab:**
  - An optional conflict strip (warn LED) shows both views.
  - Then a stretched 4 + 8 row: **Combined risk** (headline, KV rows, version select, recompute) and **Why
    this level** (numbered explanation, content cues, disclaimers pinned to the bottom).
  - Then an `items-start` 8 + 4 row: **Components** (one divided row per component: label, status and role
    tags, value and effect, reason, evidence chips) and **Evidence** (K-ids, anchor targets for the chips).
- **History, Overview and Search:** a "Combined risk" `StatusTag` column next to the unchanged rule
  verdict. Overview hides "From domain" below 2xl and History hides "Received" below xl, so the tables fit
  at 1280 and 1024.
- **Analytics:** a "Combined risk levels (index, not a probability)" bar chart beside "Rule verdicts" in
  the first row.

## Accessibility

- **Automated:** `components/A11y.test.tsx` runs axe-core (devDependency) on login, change password,
  overview, upload, history, campaign list and detail, search, admin users, and the full shell with the 404
  notice. jsdom has no layout, so `color-contrast` is off there; it is covered by the computed ratios above
  and by an in-browser axe run (all rules) during visual QA.
- **Structure:**
  - one `main` landmark and one `h1` per page;
  - panels are labelled `section`s;
  - tables carry `aria-label`, sortable headers `aria-sort`;
  - loading rows are labelled `role=status`;
  - tabs use arrow keys.
- **Focus and motion:** a 2px accent `:focus-visible` outline everywhere; `prefers-reduced-motion` disables
  animation and transitions.

## Visual QA checklist

Run this for every page at 1920×1080, 1440×900, 1280×720 and 1024×768, as viewer, analyst and admin, on
a throwaway database seeded with `python -m app.cli seed-demo-campaign` plus the BEC fixture.

- **Dead space:**
  - side-by-side panels differ by less than about 100px in height, or the shorter one is a
    data-dependent list;
  - a graph canvas stretches to its row instead of leaving a gap;
  - nothing on the page looks like missing content.
- **Clutter:**
  - no competing borders inside panels (dividers only);
  - at most one accent per area;
  - IDs and hashes shortened with copy-on-click;
  - long labels truncate.
- **Tables:**
  - 34px rows; headers on one line;
  - mono ID / IP / hash / time columns; numbers right-aligned;
  - no character-by-character wrapping;
  - secondary columns hidden below `xl` rather than scrolling.
- **Overflow:** no horizontal page scroll at any width; a header or status-bar cell never wraps or clips
  (secondary status cells hide below `xl`).
- **Shape:** no element with a radius above 2px (DOM audit: computed `border-radius`).
- **Graphs:**
  - shapes match the legend;
  - labels legible at the capped zoom; no overlapping nodes;
  - zoom and fit work.
- **Roles:**
  - viewers see no Analyse, Users, create-case, generate, add or remove controls; deep links to
    `#upload` and `#users` land on History;
  - the status bar shows LLM and intel only to admins.
- **States:** each page has a loading line or skeleton, a one-line empty state and a one-line error; an
  unknown hash shows the 404 notice.
- **Honesty text:** every disclaimer is present verbatim (relay visualization, map, correlation,
  AI / ML / SHAP notes, footer).
- **Accessibility:** in-browser axe (all rules) reports 0 violations; the tab order follows the visual
  order.
