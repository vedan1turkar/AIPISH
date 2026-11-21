// Analytics (P5g): server-side aggregates rendered as token-themed Plotly charts (lazy-loaded).
// Every chart has a text summary and a table toggle. Counts only; no message content.
import { useEffect, useMemo, useState } from 'react'
import { getAnalyticsSummary, type AnalyticsSummary } from '../../api/client'
import { ErrorAlert, Field, Panel, Select, SkeletonRows, StatCell, StatusTag, verdictTone } from '../ui'
import { CHART_THEME } from '../graph/style'
import Chart from './Chart'
import { LEVEL_TONE } from '../risk/level'

const WINDOWS = [7, 30, 90, 180]
const TONE_COLOR = { danger: CHART_THEME.danger, warn: CHART_THEME.warn, ok: CHART_THEME.ok, neutral: CHART_THEME.neutral, accent: CHART_THEME.bar }
const human = (s: string) => s.replace(/_/g, ' ')
const pct = (a: number, b: number) => (b ? `${Math.round((a / b) * 100)}%` : '—')

function list<T>(rows: T[], key: (r: T) => string, val: (r: T) => number) {
  return { x: rows.map(key), y: rows.map(val) }
}

export default function AnalyticsPage() {
  const [days, setDays] = useState(30)
  const [data, setData] = useState<AnalyticsSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    const ctl = new AbortController()
    setError(null)
    getAnalyticsSummary(days, ctl.signal).then(setData).catch((err) => {
      if (!(err instanceof DOMException && err.name === 'AbortError'))
        setError(err instanceof Error ? err.message : 'Analytics could not be loaded.')
    })
    return () => ctl.abort()
  }, [days])

  const charts = useMemo(() => {
    if (!data) return null
    const verdicts = list(data.verdicts, (v) => human(v.verdict), (v) => v.count)
    const ml = list(data.ml_classes, (v) => human(v.label), (v) => v.count)
    const domains = list(data.top_sender_domains, (d) => d.generic ? `${d.domain} (generic)` : d.domain, (d) => d.count)
    return {
      verdicts: { ...verdicts, colors: data.verdicts.map((v) => TONE_COLOR[verdictTone(v.verdict)]) },
      ml: { ...ml, colors: data.ml_classes.map((m) => m.label === 'not_assessed' ? CHART_THEME.neutral : CHART_THEME.bar) },
      perDay: list(data.per_day, (d) => d.date.slice(5), (d) => d.count),
      hist: list(data.score_histogram, (h) => h.bucket, (h) => h.count),
      domains: { ...domains, colors: data.top_sender_domains.map((d) => d.generic ? CHART_THEME.neutral : CHART_THEME.bar) },
      countries: list(data.geo.countries, (c) => c.country, (c) => c.count),
      asns: list(data.geo.asns, (a) => a.asn, (a) => a.count),
      attack: list(data.attack_techniques, (t) => `${t.technique_id} ${t.name}`, (t) => t.count),
      sizes: list(data.campaigns.candidate_size_distribution, (b) => `${b.bucket} members`, (b) => b.count),
      // P5h: combined risk levels (latest version per analysis); "not computed" = analyses stored before P5h
      combined: {
        ...list(data.combined_levels ?? [], (l) => human(l.level), (l) => l.count),
        colors: (data.combined_levels ?? []).map((l) => l.level === 'not_computed' ? CHART_THEME.neutral : TONE_COLOR[LEVEL_TONE[l.level]]),
      },
    }
  }, [data])

  const header = (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold text-fg">Analytics</h1>
        <p className="text-sm text-muted">Aggregates over stored analyses. Counts only: no message content. Heuristic scores are indicators, not proof.</p>
      </div>
      <div className="w-40">
        <Field label="Window">
          <Select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Analytics window">
            {WINDOWS.map((d) => <option key={d} value={d}>last {d} days</option>)}
          </Select>
        </Field>
      </div>
    </div>
  )

  if (error) return <div className="space-y-4">{header}<ErrorAlert message={`Analytics could not be loaded: ${error}`} /></div>
  if (!data || !charts) {
    return (
      <div className="space-y-4">{header}
        <div className="grid gap-4 xl:grid-cols-3">
          {[0, 1, 2].map((i) => <Panel key={i} title="Loading"><SkeletonRows rows={6} label="Loading analytics…" /></Panel>)}
        </div>
      </div>
    )
  }

  const w = data.window
  const geoCov = data.geo.coverage
  const intel = data.intel_coverage
  const tbl = (s: { x: (string | number)[]; y: number[] }): [string, string][] => s.x.map((x, i) => [String(x), String(s.y[i])])
  const t = (h: [string, string], s: { x: (string | number)[]; y: number[] }) => ({ headers: h, rows: tbl(s) })

  return (
    <div className="space-y-4" data-testid="analytics-page">
      {header}
      <section aria-label="Totals" className="grid grid-cols-2 divide-x divide-y divide-line border border-line bg-surface md:grid-cols-4 md:divide-y-0">
        <StatCell label="Analyses" value={w.total_analyses}
                  sub={w.capped ? `latest ${w.analyses_considered} used for derived charts` : 'all stored'} />
        <StatCell label="With geo data" value={`${geoCov.with_geo} / ${geoCov.analyses_considered}`}
                  sub={`${pct(geoCov.with_geo, geoCov.analyses_considered)} coverage${data.geo.simulated_present ? ' · includes SIMULATED' : ''}`} />
        <StatCell label="Consented intel lookups" value={`${intel.analyses_with_consented_lookups} / ${intel.analyses_considered}`}
                  sub={`${intel.runs_total} runs${intel.simulated_runs ? ` · ${intel.simulated_runs} SIMULATED` : ''}`} />
        <StatCell label="Candidate campaigns" value={data.campaigns.candidates} sub="shared infrastructure, not identity" />
      </section>

      {/* rows share their height (panels stretch), so notes under some charts never leave ragged edges */}
      <div className="grid items-stretch gap-4 xl:grid-cols-12">
        <Chart className="xl:col-span-4" title={`Analyses per day (last ${w.days} days)`} kind="line" series={charts.perDay}
               summary={`Analyses per day over the last ${w.days} days: ${charts.perDay.y.reduce((a, b) => a + b, 0)} in total, peak ${Math.max(0, ...charts.perDay.y)} on one day.`}
               table={t(['Day', 'Analyses'], charts.perDay)} />
        <Chart className="xl:col-span-4" title="Rule verdicts" kind="hbar" series={charts.verdicts}
               summary={`Rule-engine verdicts: ${data.verdicts.map((v) => `${human(v.verdict)} ${v.count}`).join(', ')}.`}
               table={t(['Verdict', 'Analyses'], charts.verdicts)} />
        <Chart className="xl:col-span-4" title="Combined risk levels (index, not a probability)" kind="hbar" series={charts.combined}
               summary={`Combined risk level per analysis (latest version): ${(data.combined_levels ?? []).map((l) => `${human(l.level)} ${l.count}`).join(', ') || 'none'}. Shown beside, never instead of, the rule verdict.`}
               table={t(['Level', 'Analyses'], charts.combined)} empty="No combined risk assessments stored yet." />

        <Chart className="xl:col-span-4" title="Rule score distribution" kind="bar" series={charts.hist}
               summary={`Rule-score histogram in buckets of ten: ${data.score_histogram.map((h) => `${h.bucket}: ${h.count}`).join(', ')}.`}
               table={t(['Score', 'Analyses'], charts.hist)} />
        <Chart className="xl:col-span-4" title="ML class (latest assessment)" kind="hbar" series={charts.ml}
               summary={`Latest ML classification per analysis: ${data.ml_classes.map((m) => `${human(m.label)} ${m.count}`).join(', ')}.`}
               table={t(['Class', 'Analyses'], charts.ml)}
               note="Separate from the rule verdict; “not assessed” = no AI assessment was run." />
        <Chart className="xl:col-span-4" title="Candidate campaign sizes" kind="bar" series={charts.sizes}
               summary={`Candidate campaigns by member count: ${data.campaigns.candidate_size_distribution.map((b) => `${b.bucket}: ${b.count}`).join(', ')}.`}
               table={t(['Size', 'Campaigns'], charts.sizes)} empty="No candidate campaigns yet." />

        <Chart className="xl:col-span-4" title="Top sender domains" kind="hbar" series={charts.domains}
               summary={`Most frequent sender domains: ${data.top_sender_domains.map((d) => `${d.domain}${d.generic ? ' (generic)' : ''} ${d.count}`).join(', ')}.`}
               table={t(['Domain', 'Analyses'], charts.domains)}
               note="“generic” = stop-listed shared provider (freemail, large ESPs): shown, never used to link analyses." />
        <Chart className="xl:col-span-4" title="Origin countries (stored geo)" kind="hbar" series={charts.countries}
               summary={`Origin countries from stored geolocation, ${geoCov.with_geo} of ${geoCov.analyses_considered} analyses located: ${data.geo.countries.map((c) => `${c.country} ${c.count}`).join(', ') || 'none'}.`}
               table={t(['Country', 'Analyses'], charts.countries)}
               empty="No stored location data. Locations come from upload enrichment or consented threat-intel lookups."
               note={<span className="inline-flex flex-wrap items-center gap-2">Coverage {geoCov.with_geo} of {geoCov.analyses_considered} analyses. Infrastructure location, not a person.
                 {data.geo.simulated_present && <StatusTag tone="warn">SIMULATED demo data</StatusTag>}</span>} />
        <Chart className="xl:col-span-4" title="Origin networks (ASN / org)" kind="hbar" series={charts.asns}
               summary={`Origin networks from stored geolocation: ${data.geo.asns.map((a) => `${a.asn} ${a.count}`).join(', ') || 'none'}.`}
               table={t(['ASN / org', 'Analyses'], charts.asns)} empty="No stored network data."
               note={data.geo.simulated_present ? <StatusTag tone="warn">SIMULATED demo data</StatusTag> : undefined} />

        <Chart className="xl:col-span-8" title="ATT&CK techniques (latest mapping per analysis)" kind="hbar" series={charts.attack}
               summary={`Most frequent ATT&CK techniques: ${data.attack_techniques.map((a) => `${a.technique_id} ${a.count}`).join(', ') || 'none'}.`}
               table={t(['Technique', 'Analyses'], charts.attack)} empty="No ATT&CK mappings stored yet." />
        <Panel title="Threat-intel coverage" className="xl:col-span-4">
          <dl className="space-y-0">
            {([
              ['Analyses considered', intel.analyses_considered],
              ['With consented lookups', `${intel.analyses_with_consented_lookups} (${pct(intel.analyses_with_consented_lookups, intel.analyses_considered)})`],
              ['Lookup runs (incl. declined)', intel.runs_total],
              ['SIMULATED runs', intel.simulated_runs],
            ] as [string, string | number][]).map(([k, v]) => (
              <div key={k} className="grid grid-cols-[1fr_auto] gap-3 border-b border-line py-1.5 last:border-0">
                <dt className="font-mono text-xs uppercase leading-5 tracking-wider text-muted">{k}</dt>
                <dd className="font-mono text-sm text-fg">{v}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-2 text-sm text-muted">External lookups run only with per-analysis consent; results are informational and never change a verdict.</p>
        </Panel>
      </div>
    </div>
  )
}
