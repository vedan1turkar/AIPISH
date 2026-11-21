// Risk tab (P5h): the explainable combined risk assessment. An ADDITIONAL, separately labelled index —
// the rule verdict and the ML class stay in their own cells and tabs, unchanged.
import type { ReactNode } from 'react'
import type { RiskAssessment, RiskComponent, RiskHistoryItem } from '../../api/client'
import { Button, EmptyLine, ErrorAlert, KV, LED, Panel, Select, SkeletonRows, StatusTag, formatDate, type Tone } from '../ui'
import { EvidenceChip } from '../assessment/AssessmentPanels'
import { LEVEL_TONE } from './level'

export { LEVEL_TONE, RiskLevelTag } from './level'

const STATUS_TONE: Record<string, Tone> = { available: 'ok', unavailable: 'neutral', not_run: 'neutral', declined: 'neutral', error: 'warn' }
const STATUS_TEXT: Record<string, string> = { available: 'available', unavailable: 'unavailable', not_run: 'not run', declined: 'declined', error: 'error' }
const ROLE_TEXT: Record<string, string> = { primary: 'primary', floor: 'floor', corroboration: 'corroboration', context: 'context only', unavailable: 'unavailable' }
const FLAG_TEXT: Record<string, string> = {
  conflicting_signals: 'conflicting signals', hard_evidence_floor: 'hard-evidence floor', components_missing: 'components missing',
  intel_flagged: 'intel flagged', intel_simulated: 'SIMULATED intel', rules_only: 'rules only', ml_only: 'ML only',
  analyst_review_recommended: 'analyst review recommended',
}
const human = (s: string) => s.replace(/_/g, ' ')
const HARD_SHORT: Record<string, string> = {
  H1_risky_attachment: 'H1 risky attachment',
  H2_verified_auth_fail_identity: 'H2 verified auth failure + identity mismatch',
  H3_payment_or_credential_with_identity: 'H3 payment/credential ask + identity signal',
}

function valueText(c: RiskComponent): ReactNode {
  const v = c.value as Record<string, unknown> | unknown[] | null
  if (v === null || v === undefined) return <span className="text-muted">—</span>
  if (c.name === 'rules' && !Array.isArray(v)) return <span className="font-mono">{String(v.score)}/100 · {human(String(v.verdict))}</span>
  if (c.name === 'ml' && !Array.isArray(v))
    return <span className="font-mono">{Number(v.threat_index).toFixed(4)} · {String(v.label)}</span>
  if (c.name === 'threat_intel' && !Array.isArray(v)) {
    const flagged = (v.flagged_providers as string[]) ?? []
    return <span className="font-mono">run v{String(v.version)} · {flagged.length ? flagged.join(', ') : 'no flags'}{v.simulated ? ' · SIMULATED' : ''}</span>
  }
  if (c.name === 'attack' && !Array.isArray(v)) {
    const t = (v.techniques as string[]) ?? []
    return <span className="font-mono">{t.length ? t.join(', ') : 'no techniques'}</span>
  }
  if (c.name === 'hard_evidence' && Array.isArray(v))
    return v.length ? <span>{v.map((id) => HARD_SHORT[String(id)] ?? String(id)).join('; ')}</span> : <span className="text-muted">none fired</span>
  if (Array.isArray(v)) return v.length ? <span className="font-mono">{v.map(String).join(', ')}</span> : <span className="text-muted">none</span>
  return <span className="text-muted">—</span>
}

function ComponentRow({ c }: { c: RiskComponent }) {
  return (
    <li className="grid gap-x-3 gap-y-1 py-2 first:pt-0 last:pb-0 md:grid-cols-12" data-testid="risk-component" data-name={c.name}>
      <div className="min-w-0 md:col-span-3">
        <div className="text-sm font-medium text-fg">{c.label}</div>
        <div className="mt-1 flex flex-wrap gap-1">
          <StatusTag tone={STATUS_TONE[c.status] ?? 'neutral'}>{STATUS_TEXT[c.status] ?? c.status}</StatusTag>
          <StatusTag tone={c.role === 'primary' ? 'accent' : 'neutral'} led={false}>{ROLE_TEXT[c.role] ?? c.role}</StatusTag>
        </div>
      </div>
      <div className="min-w-0 break-words text-sm md:col-span-3">
        {valueText(c)}
        <div className="text-xs text-muted">effect: <span className="font-mono">{c.effect ?? 'none'}</span></div>
      </div>
      <div className="min-w-0 text-sm text-muted md:col-span-4">{c.reason}</div>
      <div className="flex flex-wrap content-start gap-1 md:col-span-2">
        {c.evidence_ids.length ? c.evidence_ids.map((id) => <EvidenceChip key={id} id={id} title={`Go to evidence ${id}`} />)
          : <span className="text-xs text-muted">no evidence</span>}
      </div>
    </li>
  )
}

export default function RiskPanel({ data, loading, error, history, canRecompute, recomputing, recomputeError, onRecompute, onSelectVersion }: {
  data: RiskAssessment | null
  loading: boolean
  error: string | null
  history: RiskHistoryItem[]
  canRecompute: boolean
  recomputing: boolean
  recomputeError: string | null
  onRecompute: () => void
  onSelectVersion: (version: number) => void
}) {
  if (loading) return <Panel title="Combined risk"><SkeletonRows rows={5} label="Loading combined risk…" /></Panel>
  if (error) return <ErrorAlert message={`Could not load the combined risk assessment: ${error}`} />
  const recompute = canRecompute && (
    <Button size="sm" variant="secondary" onClick={onRecompute} disabled={recomputing} data-testid="risk-recompute">
      {recomputing ? 'Recomputing…' : 'Recompute'}
    </Button>
  )
  if (!data)
    return (
      <Panel title="Combined risk" status={recompute || undefined}>
        <EmptyLine>No combined risk assessment has been computed for this analysis yet. It is computed automatically for new uploads.</EmptyLine>
        {recomputeError && <ErrorAlert message={recomputeError} />}
      </Panel>
    )
  const rules = data.components.find((c) => c.name === 'rules')
  const ml = data.components.find((c) => c.name === 'ml')
  const conflict = data.flags.includes('conflicting_signals')
  const cues = rules?.cues ?? []
  return (
    <div className="space-y-4" data-testid="risk-panel">
      {conflict && (
        <p className="flex items-start gap-2 border border-warn-line bg-warn-weak px-3 py-2 text-sm text-fg" data-testid="risk-conflict">
          <LED tone="warn" />
          <span>
            <strong className="font-semibold">Conflicting signals.</strong>{' '}
            Rule engine: {rules?.value ? valueText(rules) : 'unavailable'} · ML ensemble: {ml?.value ? valueText(ml) : 'unavailable'}.
            The combined level is at least medium; analyst review is recommended before acting.
          </span>
        </p>
      )}
      <div className="grid items-stretch gap-4 xl:grid-cols-12">
        <Panel title="Combined risk · additional result" className="xl:col-span-4"
               status={<span className="font-mono text-xs">v{data.version}</span>}>
          <div className="flex items-center gap-3 border-b border-line pb-3" data-testid="risk-headline">
            <LED tone={LEVEL_TONE[data.level]} />
            <span className="text-xl font-semibold uppercase text-fg">{data.level}</span>
            <span className="font-mono text-xl text-fg">{data.combined_score ?? '—'}</span>
            <span className="font-mono text-sm text-muted">/100</span>
          </div>
          <dl className="mt-2">
            <KV label="Confidence">{data.confidence}</KV>
            <KV label="Agreement">{human(data.agreement)}{data.conflict ? ` (${human(data.conflict)})` : ''}</KV>
            <KV label="Flags">
              {data.flags.length ? (
                <span className="flex flex-wrap gap-1">
                  {data.flags.map((f) => (
                    <StatusTag key={f} tone={f === 'conflicting_signals' || f === 'intel_simulated' ? 'warn' : f === 'hard_evidence_floor' ? 'danger' : 'neutral'}>
                      {FLAG_TEXT[f] ?? human(f)}
                    </StatusTag>))}
                </span>) : <span className="text-muted">none</span>}
            </KV>
            <KV label="Version">
              <span className="flex flex-wrap items-center gap-2">
                {history.length > 1 ? (
                  <Select aria-label="Combined risk version" value={data.version} onChange={(e) => onSelectVersion(Number(e.target.value))} className="h-7 w-auto">
                    {history.map((h) => <option key={h.version} value={h.version}>v{h.version} · {h.source} · {h.level}</option>)}
                  </Select>) : <span className="font-mono">v{data.version} · {data.source}</span>}
                {recompute}
              </span>
            </KV>
            <KV label="Engine" mono>{data.engine_version} · {data.config_version}</KV>
            <KV label="Computed">{formatDate(data.created_at)}</KV>
          </dl>
          {recomputeError && <ErrorAlert message={recomputeError} />}
          {data.new_version === false && <p className="mt-2 text-sm text-muted">Recomputed: no change, so no new version was stored.</p>}
        </Panel>
        <Panel title="Why this level" className="xl:col-span-8" bodyClassName="p-3 flex flex-col">
          <ul className="space-y-1.5 text-sm text-fg" data-testid="risk-explanation">
            {data.explanation.map((line, i) => <li key={i} className="flex gap-2"><span className="font-mono text-xs text-muted" aria-hidden>{String(i + 1).padStart(2, '0')}</span><span>{line}</span></li>)}
          </ul>
          {cues.length > 0 && (
            <div className="mt-3 border-t border-line pt-2">
              <div className="font-mono text-xs uppercase tracking-wider text-muted">Content cues (existing rule lexicons)</div>
              <div className="mt-1 flex flex-wrap gap-1" data-testid="risk-cues">
                {cues.map((c) => <StatusTag key={c.rule_id} tone={c.fired ? 'warn' : 'neutral'}>{human(c.rule_id)}{c.fired ? '' : ': not found'}</StatusTag>)}
              </div>
            </div>
          )}
          <ul className="mt-auto space-y-0.5 border-t border-line pt-2 text-sm text-muted" data-testid="risk-disclaimers">
            {data.disclaimers.map((d) => <li key={d}>{d}</li>)}
          </ul>
        </Panel>
      </div>
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title={`Components (${data.components.length})`} className="xl:col-span-8">
          <ul className="divide-y divide-line">{data.components.map((c) => <ComponentRow key={c.name} c={c} />)}</ul>
        </Panel>
        <Panel title="Evidence" className="xl:col-span-4">
          {data.evidence.length ? (
            <ul className="divide-y divide-line">
              {data.evidence.map((e) => (
                <li key={e.id} id={`evidence-${e.id}`} tabIndex={-1} className="py-1.5 text-sm" data-testid="risk-evidence">
                  <span className="mr-2 font-mono text-xs font-medium text-accent">{e.id}</span>
                  <span className="mr-2 font-mono text-xs uppercase text-muted">{e.source}</span>
                  <span className="text-fg">{e.statement}</span>
                </li>))}
            </ul>) : <EmptyLine>No evidence items: no rule fired, no ML result and no intel or context.</EmptyLine>}
        </Panel>
      </div>
    </div>
  )
}
