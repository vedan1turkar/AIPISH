// Overview (P5u-1): default landing page. Existing endpoints only; every panel holds real data or
// one empty line. Four panels (posture stat row, recent analyses, candidate campaigns, system
// status) plus role-aware quick actions in the page header.
import { useEffect, useState } from 'react'
import {
  getAssessment,
  listAnalyses,
  listCampaigns,
  listInvestigations,
  type AnalysisSummary,
  type CampaignBrief,
  type InvestigationCase,
} from '../../api/client'
import { useAuth } from '../../auth/AuthContext'
import { useSystemStatus } from '../shell/StatusBar'
import { RiskLevelTag } from '../risk/level'
import {
  Button, DataTable, EmptyLine, KV, LED, Panel, SkeletonRows, StatCell, StatusTag, formatDate, verdictTone, type Tone,
} from '../ui'

export const VERDICT_ORDER = ['phishing_fraud_likely', 'suspicious', 'low_risk', 'minimal', 'clean']
export const ML_SAMPLE = 20

export { verdictTone } from '../ui'

export function countBy<T>(items: T[], key: (t: T) => string): [string, number][] {
  const m = new Map<string, number>()
  for (const it of items) m.set(key(it), (m.get(key(it)) ?? 0) + 1)
  return Array.from(m.entries())
}

function BarRows({ rows, total, tone }: { rows: [string, number][]; total: number; tone: (k: string) => Tone }) {
  const fill: Record<Tone, string> = { neutral: 'bg-muted', accent: 'bg-accent', ok: 'bg-ok', warn: 'bg-warn', danger: 'bg-danger' }
  return (
    <ul className="space-y-1.5">
      {rows.map(([k, n]) => (
        <li key={k} className="grid grid-cols-[11rem_1fr_3rem_3rem] items-center gap-3 text-sm" data-testid="bar-row">
          <span className="flex min-w-0 items-center gap-1.5 font-mono text-xs uppercase text-fg">
            <LED tone={tone(k)} /><span className="truncate">{k.replace(/_/g, ' ')}</span>
          </span>
          <span className="h-2 bg-surface-2" aria-hidden>
            <span className={`block h-2 ${fill[tone(k)]}`} style={{ width: `${total ? Math.max(2, (n / total) * 100) : 0}%` }} />
          </span>
          <span className="text-right font-mono">{n}</span>
          <span className="text-right font-mono text-muted">{total ? Math.round((n / total) * 100) : 0}%</span>
        </li>
      ))}
    </ul>
  )
}

type Load<T> = { state: 'loading' } | { state: 'ok'; data: T } | { state: 'error'; message: string }

function useLoad<T>(fn: (signal: AbortSignal) => Promise<T>, enabled = true): Load<T> {
  const [s, setS] = useState<Load<T>>({ state: 'loading' })
  useEffect(() => {
    if (!enabled) return
    const ctl = new AbortController()
    fn(ctl.signal)
      .then((data) => setS({ state: 'ok', data }))
      .catch((e) => {
        if (!ctl.signal.aborted) setS({ state: 'error', message: e instanceof Error ? e.message : 'request failed' })
      })
    return () => ctl.abort()
  }, [fn, enabled])
  return s
}

const loadAnalyses = (s: AbortSignal) => listAnalyses(s)
const loadCampaigns = (s: AbortSignal) => listCampaigns(s).then((r) => r.items)
const loadCases = (s: AbortSignal) => listInvestigations(s)

/** ML class of the latest AI assessment for the most recent analyses (bounded, 4 at a time). */
function useMlClasses(analyses: AnalysisSummary[] | null, enabled: boolean): Load<[string, number][]> {
  const [s, setS] = useState<Load<[string, number][]>>({ state: 'loading' })
  useEffect(() => {
    if (!enabled || !analyses) return
    let alive = true
    const ids = analyses.slice(0, ML_SAMPLE).map((a) => a.id)
    const labels: string[] = []
    const run = async () => {
      for (let i = 0; i < ids.length; i += 4) {
        const batch = await Promise.all(ids.slice(i, i + 4).map((id) =>
          getAssessment(id).then((a) => {
            const ml = a?.ml as { status?: string; label?: string } | undefined
            return ml?.status === 'ok' && ml.label ? ml.label : 'not assessed'
          }).catch(() => 'unavailable')))
        labels.push(...batch)
      }
      if (alive) setS({ state: 'ok', data: countBy(labels, (l) => l).sort((a, b) => b[1] - a[1]) })
    }
    void run().catch((e) => alive && setS({ state: 'error', message: String(e) }))
    return () => {
      alive = false
    }
  }, [analyses, enabled])
  return s
}

export default function OverviewPage({ onOpenAnalysis }: { onOpenAnalysis: (id: string) => void }) {
  const { can } = useAuth()
  const analyses = useLoad(loadAnalyses)
  const campaigns = useLoad(loadCampaigns, can('correlation:read'))
  const cases = useLoad(loadCases, can('case:read'))
  const list = analyses.state === 'ok' ? analyses.data : null
  const ml = useMlClasses(list, can('assessment:read'))
  const { cells } = useSystemStatus()

  const verdicts = list
    ? countBy(list, (a) => a.detection_verdict ?? 'unknown').sort(
        (a, b) => (VERDICT_ORDER.indexOf(a[0]) + 99) % 99 - (VERDICT_ORDER.indexOf(b[0]) + 99) % 99)
    : []
  const n = (v: string) => verdicts.find(([k]) => k === v)?.[1] ?? 0
  const openCases = cases.state === 'ok' ? cases.data.filter((c: InvestigationCase) => c.status === 'open').length : null
  const camps = campaigns.state === 'ok' ? [...campaigns.data].sort((a, b) =>
    b.confidence_score - a.confidence_score || b.member_count - a.member_count) : []

  return (
    <div className="space-y-4" data-testid="overview-page">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold text-fg">Overview</h1>
          <p className="text-sm text-muted">Recent activity from the connected backend · heuristic indicators, not proof of identity</p>
        </div>
        {/* 5 — quick actions (role-aware; the backend enforces the same permissions) */}
        <div className="flex flex-wrap gap-2" role="group" aria-label="Quick actions">
          {can('analysis:create') && (
            <Button variant="primary" onClick={() => { window.location.hash = '#upload' }}>New analysis</Button>
          )}
          <Button onClick={() => { window.location.hash = '#search' }}>Search</Button>
          <Button onClick={() => { window.location.hash = '#history' }}>History</Button>
        </div>
      </div>

      {/* 1 — posture: the focal element */}
      <Panel title="Posture · last 100 analyses" bodyClassName="p-0">
        {analyses.state === 'loading' && <div className="p-3"><SkeletonRows rows={2} /></div>}
        {analyses.state === 'error' && <div className="p-3"><EmptyLine>Analyses could not be loaded: {analyses.message}</EmptyLine></div>}
        {list && (
          <>
            <div className="grid grid-cols-2 divide-x divide-line border-b border-line md:grid-cols-3 xl:grid-cols-6">
              <StatCell label="Analyses" value={list.length} sub={list.length >= 100 ? 'most recent 100' : 'stored'} />
              <StatCell label="Phishing / fraud likely" value={n('phishing_fraud_likely')} tone="danger" />
              <StatCell label="Suspicious" value={n('suspicious')} tone="warn" />
              <StatCell label="Low / minimal" value={n('low_risk') + n('minimal') + n('clean')} tone="neutral" />
              <StatCell label="Open cases" value={openCases ?? '—'} sub={cases.state === 'ok' ? `${cases.data.length} total` : undefined} />
              <StatCell label="Candidate campaigns" value={campaigns.state === 'ok' ? campaigns.data.length : '—'} />
            </div>
            <div className="grid gap-6 p-3 lg:grid-cols-2">
              <div>
                <h3 className="mb-2 font-mono text-xs uppercase tracking-wider text-muted">Rule verdict</h3>
                {list.length ? <BarRows rows={verdicts} total={list.length} tone={verdictTone} /> : <EmptyLine>No analyses stored yet.</EmptyLine>}
              </div>
              <div>
                <h3 className="mb-2 font-mono text-xs uppercase tracking-wider text-muted">
                  ML class · latest AI assessment of the {Math.min(ML_SAMPLE, list.length)} most recent
                </h3>
                {!can('assessment:read') ? <EmptyLine>Your role cannot read AI assessments.</EmptyLine>
                  : ml.state === 'loading' ? <SkeletonRows rows={3} />
                  : ml.state === 'error' ? <EmptyLine>ML classes could not be loaded.</EmptyLine>
                  : ml.data.length ? <BarRows rows={ml.data} total={Math.min(ML_SAMPLE, list.length)}
                                             tone={(k) => (k === 'legitimate' ? 'ok' : k === 'not assessed' || k === 'unavailable' ? 'neutral' : 'danger')} />
                  : <EmptyLine>No analyses to sample.</EmptyLine>}
              </div>
            </div>
          </>
        )}
      </Panel>

      <div className="grid items-start gap-4 xl:grid-cols-12">
        {/* 2 — recent analyses */}
        <Panel title="Recent analyses" className="xl:col-span-8" bodyClassName="p-0"
               status={<a href="#history" className="font-mono text-xs uppercase text-accent hover:underline">view all</a>}>
          {analyses.state === 'loading' ? <div className="p-3"><SkeletonRows rows={6} /></div> : (
            <DataTable<AnalysisSummary>
              label="Recent analyses"
              rows={(list ?? []).slice(0, 10)}
              rowKey={(a) => a.id}
              empty="No analyses yet. Upload an .eml from Analyse to start."
              columns={[
                { key: 'verdict', header: 'Verdict', render: (a) => (
                  <StatusTag tone={verdictTone(a.detection_verdict)}>{(a.detection_verdict ?? 'unknown').replace(/_/g, ' ')}</StatusTag>) },
                { key: 'score', header: 'Score', align: 'right', mono: true, render: (a) => a.detection_score },
                { key: 'combined', header: 'Combined risk', className: 'whitespace-nowrap',
                  render: (a) => <RiskLevelTag level={a.combined_level} score={a.combined_score} /> },
                { key: 'subject', header: 'Subject', className: 'max-w-0 w-full', render: (a) => (
                  <button onClick={() => onOpenAnalysis(a.id)} className="block w-full truncate text-left text-accent hover:underline">
                    {a.subject || '(no subject)'}
                  </button>) },
                { key: 'from', header: 'From domain', hideBelow: '2xl', mono: true, className: 'whitespace-nowrap', render: (a) => a.sender?.domain || '—' },
                { key: 'time', header: 'Received', mono: true, className: 'whitespace-nowrap text-muted', render: (a) => formatDate(a.created_at) },
              ]}
            />
          )}
        </Panel>

        <div className="flex flex-col gap-4 xl:col-span-4">
        {/* 3 — campaigns */}
        <Panel title="Candidate campaigns" bodyClassName="p-0"
               status={<a href="#campaigns" className="font-mono text-xs uppercase text-accent hover:underline">view all</a>}>
          {!can('correlation:read') ? <div className="p-3"><EmptyLine>Your role cannot read campaigns.</EmptyLine></div>
            : campaigns.state === 'loading' ? <div className="p-3"><SkeletonRows rows={4} /></div>
            : campaigns.state === 'error' ? <div className="p-3"><EmptyLine>Campaigns could not be loaded.</EmptyLine></div>
            : (
              <DataTable<CampaignBrief>
                label="Candidate campaigns"
                rows={camps.slice(0, 8)}
                rowKey={(c) => c.id}
                empty="No candidate campaigns: no analyses share enough non-generic infrastructure."
                columns={[
                  { key: 'label', header: 'Campaign', render: (c) => (
                    <a href={`#campaign/${c.id}`} className="text-accent hover:underline">{c.label.replace('Candidate campaign ', '')}</a>) },
                  { key: 'conf', header: 'Confidence', render: (c) => (
                    <StatusTag tone={c.confidence === 'high' ? 'danger' : c.confidence === 'medium' ? 'warn' : 'neutral'}>{c.confidence}</StatusTag>) },
                  { key: 'members', header: 'Members', align: 'right', mono: true, render: (c) => c.member_count },
                ]}
              />
            )}
        </Panel>

        {/* 4 — system status */}
        <Panel title="System status">
          {cells.length === 0 ? <SkeletonRows rows={3} /> : (
            <dl>
              {cells.map((c) => (
                <KV key={c.key} label={c.label}>
                  <span className="inline-flex items-center gap-1.5"><LED tone={c.tone} /><span className="font-mono">{c.value}</span></span>
                </KV>
              ))}
              {!can('config:status') && (
                <KV label="LLM / intel">
                  <span className="text-muted">Configuration status is visible to administrators only.</span>
                </KV>
              )}
            </dl>
          )}
        </Panel>

        </div>
      </div>
    </div>
  )
}
