// Candidate campaigns (P5c): list + detail with an evidence-backed Cytoscape graph.
import { useEffect, useRef, useState } from 'react'
import cytoscape, { type Core } from 'cytoscape'
import { getCampaign, listCampaigns, type CampaignBrief, type CampaignDetail } from '../../api/client'
import { EmptyState, ErrorAlert, Panel, Spinner, formatDate } from '../ui'
import { buildCampaignElements, CONFIDENCE_STYLE, typeLabel } from './model'
import { Disclaimer, TierChip } from './RelatedPanel'

export function CampaignList() {
  const [items, setItems] = useState<CampaignBrief[] | null>(null)
  const [disclaimer, setDisclaimer] = useState('')
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    const ctl = new AbortController()
    listCampaigns(ctl.signal)
      .then((r) => {
        setItems(r.items)
        setDisclaimer(r.disclaimer)
      })
      .catch((err) => {
        if (!(err instanceof DOMException && err.name === 'AbortError'))
          setError(err instanceof Error ? err.message : 'Could not load campaigns.')
      })
    return () => ctl.abort()
  }, [])
  if (error) return <ErrorAlert message={error} />
  if (!items) return <Spinner label="Loading candidate campaigns…" />
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-gray-900">Candidate campaigns</h2>
      <Disclaimer text={disclaimer} />
      {items.length === 0 ? (
        <EmptyState title="No candidate campaigns" hint="No group of analyses shares enough non-generic infrastructure yet." />
      ) : (
        <ul className="divide-y divide-gray-100 border border-gray-200 bg-white">
          {items.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3" data-testid="campaign-row">
              <a href={`#campaign/${c.id}`} className="font-medium text-indigo-700 hover:underline">{c.label}</a>
              <div className="flex gap-2 text-xs">
                <span className={` px-2 py-0.5 font-semibold ring-1 ${CONFIDENCE_STYLE[c.confidence]}`}>
                  {c.confidence} ({c.confidence_score.toFixed(2)})
                </span>
                <span className=" bg-gray-100 px-1.5 py-0.5 text-gray-600">{c.member_count} analyses</span>
                <span className=" bg-gray-100 px-1.5 py-0.5 text-gray-600">v{c.version}</span>
                <span className="text-gray-400">updated {formatDate(c.updated_at)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function CampaignGraph({ detail }: { detail: CampaignDetail }) {
  const ref = useRef<HTMLDivElement>(null)
  const [tip, setTip] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    if (!ref.current) return
    let cy: Core | null = null
    try {
      cy = cytoscape({
        container: ref.current,
        elements: buildCampaignElements(detail),
        layout: { name: 'cose', animate: false, padding: 20 },
        style: [
          { selector: 'node', style: { label: 'data(label)', 'background-color': 'data(color)', shape: 'data(shape)' as never,
                                       color: '#dbe3ea', 'font-size': 9, 'text-wrap': 'ellipsis', 'text-max-width': '110px',
                                       'text-valign': 'bottom', 'text-margin-y': 4, width: 26, height: 26 } },
          { selector: 'node.analysis', style: { width: 34, height: 22 } },
          { selector: 'node.tier-strong', style: { 'border-width': 3, 'border-color': '#e11d48' } },
          { selector: 'node.tier-medium', style: { 'border-width': 3, 'border-color': '#d97706' } },
          { selector: 'edge', style: { label: 'data(label)', 'font-size': 7, color: '#8593a1', width: 1.5,
                                       'line-color': '#3a4757', 'curve-style': 'bezier', 'text-rotation': 'autorotate' } },
        ],
      })
      cy.on('mouseover tap', 'node, edge', (e) => setTip(String(e.target.data('tooltip') ?? '')))
      cy.on('tap', 'node.analysis', (e) => {
        const id = String(e.target.id()).slice(2)
        window.location.hash = `#analysis/${id}`
      })
    } catch {
      setFailed(true)
    }
    return () => cy?.destroy()
  }, [detail])
  return (
    <div>
      {failed ? (
        <p className="text-xs text-gray-500">The graph could not be drawn in this browser; the member and indicator lists below hold the same data.</p>
      ) : (
        <div ref={ref} data-testid="campaign-graph" className="h-96 w-full border border-gray-200 bg-white" />
      )}
      <p className="mt-1 min-h-[1rem] text-xs text-gray-600" data-testid="graph-tip">
        {tip ?? 'Hover or tap a node or edge to see its evidence reference. Tap an analysis to open it.'}
      </p>
    </div>
  )
}

export function CampaignDetailView({ id }: { id: string }) {
  const [d, setD] = useState<CampaignDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    const ctl = new AbortController()
    setD(null)
    setError(null)
    getCampaign(id, ctl.signal)
      .then(setD)
      .catch((err) => {
        if (!(err instanceof DOMException && err.name === 'AbortError'))
          setError(err instanceof Error ? err.message : 'Could not load the campaign.')
      })
    return () => ctl.abort()
  }, [id])
  if (error) return <ErrorAlert message={error} />
  if (!d) return <Spinner label="Loading campaign…" />
  const shared = d.reasons.shared_indicators ?? []
  return (
    <div className="space-y-4" data-testid="campaign-detail">
      <div className="flex flex-wrap items-center gap-2">
        <a href="#campaigns" className="text-xs text-indigo-600 hover:underline">← Candidate campaigns</a>
        <h2 className="text-lg font-semibold text-gray-900">{d.label}</h2>
        <span className={` px-2 py-0.5 text-xs font-semibold ring-1 ${CONFIDENCE_STYLE[d.confidence]}`}>
          {d.confidence} confidence ({d.confidence_score.toFixed(2)})
        </span>
        <span className="text-xs text-gray-400">status {d.status} · version {d.version} · {d.member_count} analyses</span>
      </div>
      <Disclaimer text={d.disclaimer} />
      <Panel title="Shared-infrastructure graph">
        <CampaignGraph detail={d} />
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Why these analyses are grouped">
          <ul className="list-disc space-y-1 pl-4 text-xs text-gray-700">
            {(d.reasons.summary ?? []).map((s, i) => <li key={i}>{s}</li>)}
          </ul>
          <ul className="mt-3 space-y-2">
            {shared.map((i) => (
              <li key={i.entity_id} className="text-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  <TierChip tier={i.tier} />
                  <span className="text-gray-500">{typeLabel(i.type)}</span>
                  <span className="font-mono break-all">{i.value}</span>
                  <span className="text-gray-400">weight {i.weight}</span>
                </div>
                <p className="mt-0.5 text-xs text-gray-500">
                  Evidence: {i.evidence.map((e) => `${e.analysis_id?.slice(0, 8)} ${e.source_field}`).join(' · ')}
                </p>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-gray-400">{d.reasons.rule}</p>
        </Panel>
        <Panel title="Member analyses">
          <ul className="divide-y divide-gray-100">
            {d.members.map((m) => (
              <li key={m.id} className="py-2 text-xs">
                <a href={`#analysis/${m.id}`} className="font-medium text-indigo-700 hover:underline">{m.subject || '(no subject)'}</a>
                <span className="ml-2 font-mono text-gray-400">{m.id.slice(0, 8)}</span>
                <span className="ml-2 text-gray-400">{formatDate(m.created_at)} · score {m.detection_score}</span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  )
}
