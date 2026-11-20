# AIPISH design system (P5u-1)

The goal is a calm, dense security-engineering console: information-rich, organised and easy to scan.
Hierarchy comes from type weight and tonal surface steps, not from boxes, shadows or colour.

The reference products studied were Snyk, Tailscale and Wiz. They were used for density, grid and rhythm
only; nothing (logos, text, imagery, icons, colours or branding) was copied. Takeaways:
- one strong accent on near-black;
- small uppercase mono labels;
- strict left-aligned grid edges;
- quiet body text beside a single focal element.

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
| `DataTable` | Sticky mono header, 34px rows, right-aligned numbers, hover tonal row, one-line empty state |
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
| `SkeletonRows` | Compact loading rows |
| `Kbd`, `Label` | Keyboard hint, mono label |

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

**Guards** (`components/ui/Primitives.test.tsx`), which fail the test suite on:
- any `rounded`, `rounded-md/lg/xl/2xl/3xl/full` class in `src`;
- any emoji pictograph in UI source;
- a change to the radius or shadow scale.

## Compatibility layer (to be removed in part 2)

Components not yet migrated still use legacy Tailwind palette names such as `bg-white`, `text-gray-500`
and `bg-red-50`. `tailwind.config.js` maps these onto the dark tokens:
- **Neutrals** map onto surfaces and lines.
- **Status families:** red/rose → `danger`, amber/orange → `warn`, emerald/green/teal → `ok`,
  sky/blue/indigo/violet → `accent`.
- **Shades:** 50–100 → weak tint, 200–300 → line, 400–900 → the colour itself.

This keeps every page on-theme and contrast-safe while part 2 migrates the remaining pages (History,
Campaigns, Case, Search, Admin, Upload) to semantic tokens and primitives. New code must use the semantic
tokens.

## Graphs

Cytoscape cannot read CSS variables, so the trace and campaign graphs use the token hex values directly:
- light labels on the dark canvas;
- node kinds told apart by shape and label, with the message/analysis node in accent;
- provenance borders: observed = ok, enriched = accent, inferred = muted;
- severity borders follow the status colours.
