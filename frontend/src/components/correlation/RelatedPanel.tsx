// "Related" tab (P5c): analyses sharing non-generic infrastructure with this one.
import { useEffect, useState } from 'react'
import { getCorrelation, type Correlation, type SharedIndicator } from '../../api/client'
import { EmptyState, ErrorAlert, Panel, Spinner, formatDate } from '../ui'
import { CONFIDENCE_STYLE, TIER_STYLE, typeLabel } from './model'

export function TierChip({ tier }: { tier: string }) {
  return (
    <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1 ${TIER_STYLE[tier] ?? TIER_STYLE.weak}`}>
      {tier}
    </span>
  )
}

export function CampaignBadge({ id, label, confidence }: { id: string; label: string; confidence: string }) {
  return (
    <a
      href={`#campaign/${id}`}
      data-testid="campaign-badge"
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ${CONFIDENCE_STYLE[confidence] ?? CONFIDENCE_STYLE.low}`}
    >
      🕸️ {label} · {confidence} confidence
    </a>
  )
}

export function Disclaimer({ text }: { text: string }) {
  return (
    <p className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-[11px] text-slate-600" data-testid="corr-disclaimer">
      {text}
    </p>
  )
}

function IndicatorList({ items }: { items: SharedIndicator[] }) {
  return (
    <ul className="mt-1 space-y-0.5">
      {items.map((i) => (
        <li key={i.entity_id} className="flex flex-wrap items-center gap-1.5 text-xs">
          <TierChip tier={i.tier} />
          <span className="text-gray-500">{typeLabel(i.type)}</span>
          <span className="font-mono text-gray-900 break-all">{i.value}</span>
          {i.damped && <span className="text-[10px] text-amber-700">(damped: common value)</span>}
          <span className="text-[10px] text-gray-400" title={i.evidence.map((e) => `${e.analysis_id?.slice(0, 8) ?? ''} ${e.source_field}`).join('\n')}>
            evidence: {Array.from(new Set(i.evidence.map((e) => e.source_field))).join(', ')}
          </span>
        </li>
      ))}
    </ul>
  )
}

/** "outlook.com (Sender domain, Return-Path domain)" — one entry per value, roles in brackets. */
export function genericSummary(items: { type: string; value: string }[]): string {
  const byValue = new Map<string, string[]>()
  for (const g of items) byValue.set(g.value, [...(byValue.get(g.value) ?? []), typeLabel(g.type)])
  return Array.from(byValue, ([v, types]) => `${v} (${types.join(', ')})`).join('; ')
}

export default function RelatedPanel({ analysisId }: { analysisId: string }) {
  const [data, setData] = useState<Correlation | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const ctl = new AbortController()
    setLoading(true)
    setError(null)
    getCorrelation(analysisId, ctl.signal)
      .then(setData)
      .catch((err) => {
        if (!(err instanceof DOMException && err.name === 'AbortError'))
          setError(err instanceof Error ? err.message : 'Could not load related analyses.')
      })
      .finally(() => setLoading(false))
    return () => ctl.abort()
  }, [analysisId])

  if (loading) return <Spinner label="Loading related analyses…" />
  if (error) return <ErrorAlert message={`Could not load related analyses: ${error}`} />
  if (!data) return null

  const linked = data.related.filter((r) => r.qualifies)
  const weak = data.related.filter((r) => !r.qualifies)
  return (
    <div className="space-y-4" data-testid="related-panel">
      <Disclaimer text={data.disclaimer} />
      {data.status === 'error' && (
        <ErrorAlert message="Correlation could not be computed for this analysis when it was stored. The analysis itself is unaffected; an admin can run a correlation rebuild." />
      )}
      {data.campaigns.length > 0 && (
        <Panel title="Candidate campaign membership">
          <div className="flex flex-wrap gap-2">
            {data.campaigns.map((c) => (
              <CampaignBadge key={c.id} id={c.id} label={c.label} confidence={c.confidence} />
            ))}
          </div>
          <p className="mt-2 text-[11px] text-gray-500">Grouped by shared infrastructure only: not an identification of a sender or person.</p>
        </Panel>
      )}
      <Panel title={`Related analyses (${linked.length} linked)`}>
        {linked.length === 0 ? (
          <EmptyState
            icon="🔗"
            title="No related analyses found"
            hint="No other stored analysis shares enough non-generic infrastructure with this one. This is not a claim that the message is unique."
          />
        ) : (
          <ul className="divide-y divide-gray-100">
            {linked.map((r) => (
              <li key={r.analysis.id} className="py-2" data-testid="related-row">
                <div className="flex flex-wrap items-center gap-2">
                  <a href={`#analysis/${r.analysis.id}`} className="font-medium text-indigo-700 hover:underline">
                    {r.analysis.subject || '(no subject)'}
                  </a>
                  <span className="font-mono text-[11px] text-gray-400">{r.analysis.id.slice(0, 8)}</span>
                  <span className="text-[11px] text-gray-400">{formatDate(r.analysis.created_at)}</span>
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ${CONFIDENCE_STYLE[r.confidence ?? 'low']}`}>
                    link {r.score.toFixed(2)} · {r.confidence}
                  </span>
                </div>
                <p className="mt-0.5 text-[11px] text-gray-500">Why: {r.explanation}.</p>
                <IndicatorList items={r.indicators} />
              </li>
            ))}
          </ul>
        )}
      </Panel>
      {weak.length > 0 && (
        <Panel title={`Shared indicators below the link threshold (${weak.length})`}>
          <p className="text-[11px] text-gray-500">These analyses share something, but not enough to be linked.</p>
          <ul className="divide-y divide-gray-100">
            {weak.map((r) => (
              <li key={r.analysis.id} className="py-2">
                <a href={`#analysis/${r.analysis.id}`} className="text-xs text-indigo-700 hover:underline">
                  {r.analysis.subject || r.analysis.id.slice(0, 8)}
                </a>
                <span className="ml-2 text-[11px] text-gray-500">{r.explanation}</span>
                <IndicatorList items={r.indicators} />
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {data.generic_only_overlaps.count > 0 && (
        <p className="text-xs text-gray-500" data-testid="generic-only">
          {data.generic_only_overlaps.count} other analys{data.generic_only_overlaps.count === 1 ? 'is shares' : 'es share'} only generic
          indicators ({genericSummary(data.generic_only_overlaps.indicators)}): stop-listed or very common values never link analyses.
        </p>
      )}
      <p className="text-[11px] text-gray-400">{data.rule}</p>
    </div>
  )
}
