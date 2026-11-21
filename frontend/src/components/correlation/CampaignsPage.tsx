// Candidate campaigns (P5c): list + detail with an evidence-backed Cytoscape graph.
import { useEffect, useRef, useState } from 'react'
import cytoscape, { type Core } from 'cytoscape'
import {
  getCampaign, listCampaigns, type AnalysisBrief, type CampaignBrief, type CampaignDetail,
} from '../../api/client'
import { DataTable, ErrorAlert, KV, Mono, Panel, SkeletonRows, Spinner, StatusTag, formatDate, verdictTone } from '../ui'
import { G, GraphControls, ShapeLegend, baseStyle, fitCapped } from '../graph/style'
import { buildCampaignElements, CONFIDENCE_TONE, typeLabel } from './model'
import { Disclaimer, TierChip } from './RelatedPanel'
import GeoPanel from '../geo/GeoPanel'

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
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold text-fg">Candidate campaigns</h1>
        <p className="text-sm text-muted">Groups of analyses that share non-generic infrastructure.</p>
      </div>
      {error ? <ErrorAlert message={error} /> : (
        <>
          {disclaimer && <Disclaimer text={disclaimer} />}
          <Panel title="Campaigns" bodyClassName="p-0"
                 status={items ? <span className="font-mono text-xs">{items.length} total</span> : undefined}>
            {!items ? (
              <div className="p-3"><SkeletonRows rows={4} label="Loading candidate campaigns…" /></div>
            ) : (
              <DataTable<CampaignBrief>
                label="Candidate campaigns"
                rows={items}
                rowKey={(c) => c.id}
                rowTestId={() => 'campaign-row'}
                pageSize={25}
                empty="No candidate campaigns. No group of analyses shares enough non-generic infrastructure yet."
                columns={[
                  { key: 'label', header: 'Campaign', className: 'w-full', sortValue: (c) => c.label, render: (c) => (
                    <a href={`#campaign/${c.id}`} className="font-medium text-accent hover:underline">{c.label}</a>) },
                  { key: 'conf', header: 'Confidence', sortValue: (c) => c.confidence_score, render: (c) => (
                    <StatusTag tone={CONFIDENCE_TONE[c.confidence] ?? 'neutral'}>{c.confidence} ({c.confidence_score.toFixed(2)})</StatusTag>) },
                  { key: 'status', header: 'Status', render: (c) => <span className="text-muted">{c.status}</span> },
                  { key: 'members', header: 'Members', align: 'right', mono: true, sortValue: (c) => c.member_count,
                    render: (c) => `${c.member_count} analyses` },
                  { key: 'ver', header: 'Ver', align: 'right', mono: true, render: (c) => `v${c.version}` },
                  { key: 'upd', header: 'Updated', mono: true, className: 'whitespace-nowrap text-muted',
                    sortValue: (c) => c.updated_at ?? '', render: (c) => formatDate(c.updated_at) },
                ]}
              />
            )}
          </Panel>
        </>
      )}
    </div>
  )
}

const CAMPAIGN_LEGEND = [
  { kind: 'analysis', label: 'analysis' },
  { kind: 'public_ip', label: 'public IP' },
  { kind: 'sender_domain', label: 'domain' },
  { kind: 'url_host', label: 'URL host' },
  { kind: 'attachment_hash', label: 'hash / alias' },
]

function CampaignGraph({ detail }: { detail: CampaignDetail }) {
  const ref = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const [tip, setTip] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    if (!ref.current) return
    let cy: Core | null = null
    try {
      cy = cytoscape({
        container: ref.current,
        elements: buildCampaignElements(detail),
        layout: { name: 'cose', animate: false, padding: 30, idealEdgeLength: 110, nodeRepulsion: 12000, nodeOverlap: 24,
                  componentSpacing: 80, nodeDimensionsIncludeLabels: true } as never,
        style: [
          ...baseStyle(),
          { selector: 'node', style: { shape: 'data(shape)' as never, width: 'data(w)' as never, height: 'data(h)' as never,
                                       'border-style': 'data(borderStyle)' as never } },
          { selector: 'node.analysis', style: { 'background-color': G.nodeFocal, 'border-color': G.fg } },
          { selector: 'node.tier-strong', style: { 'border-width': 2, 'border-color': G.danger } },
          { selector: 'node.tier-medium', style: { 'border-width': 2, 'border-color': G.warn } },
          { selector: ':selected', style: { 'border-color': G.accent, 'border-width': 2, 'line-color': G.accent } },
        ] as never,
      })
      cy.on('mouseover tap', 'node, edge', (e) => setTip(String(e.target.data('tooltip') ?? '')))
      cy.on('tap', 'node.analysis', (e) => {
        const id = String(e.target.id()).slice(2)
        window.location.hash = `#analysis/${id}`
      })
      try { fitCapped(cy as never, 30, 1) } catch { /* a failed fit never hides the graph */ }
      cyRef.current = cy
    } catch {
      setFailed(true)
    }
    const onResize = () => cy?.resize()
    window.addEventListener('resize', onResize)
    return () => { window.removeEventListener('resize', onResize); cy?.destroy(); cyRef.current = null }
  }, [detail])
  const zoomBy = (f: number) => {
    const cy = cyRef.current
    if (cy) cy.zoom(Math.min(cy.maxZoom(), Math.max(cy.minZoom(), cy.zoom() * f)))
  }
  return (
    <div className="flex h-full flex-col">
      {failed ? (
        <p className="p-3 text-sm text-muted">The graph could not be drawn in this browser; the member and indicator lists below hold the same data.</p>
      ) : (
        <div className="relative min-h-[420px] flex-1">
          <div ref={ref} data-testid="campaign-graph" className="absolute inset-0 bg-surface" role="img"
               aria-label="Shared-infrastructure graph" />
          <GraphControls onZoom={zoomBy} onFit={() => cyRef.current && fitCapped(cyRef.current as never, 30, 1)} />
        </div>
      )}
      <div className="space-y-1 border-t border-line px-3 py-2">
        <ShapeLegend items={CAMPAIGN_LEGEND} />
        <p className="text-sm text-muted">
          <span className="mr-3 inline-flex items-center gap-1.5"><span aria-hidden className="inline-block h-2.5 w-2.5 border-2 border-danger" />strong indicator</span>
          <span className="mr-3 inline-flex items-center gap-1.5"><span aria-hidden className="inline-block h-2.5 w-2.5 border-2 border-warn" />medium indicator</span>
        </p>
        <p className="min-h-[1.25rem] font-mono text-xs text-muted" data-testid="graph-tip">
          {tip ?? 'Hover or tap a node or edge to see its evidence reference. Tap an analysis to open it.'}
        </p>
      </div>
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
  if (error) return <div className="space-y-3"><a href="#campaigns" className="text-sm text-accent hover:underline">← Candidate campaigns</a><ErrorAlert message={error} /></div>
  if (!d) return <Spinner label="Loading campaign…" />
  const shared = d.reasons.shared_indicators ?? []
  return (
    <div className="space-y-4" data-testid="campaign-detail">
      <div>
        <a href="#campaigns" className="text-sm text-accent hover:underline">← Candidate campaigns</a>
        <div className="mt-1 flex flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold text-fg">{d.label}</h1>
          <StatusTag tone={CONFIDENCE_TONE[d.confidence] ?? 'neutral'}>
            {d.confidence} confidence ({d.confidence_score.toFixed(2)})
          </StatusTag>
          <span className="font-mono text-xs text-muted">status {d.status} · version {d.version} · {d.member_count} analyses</span>
        </div>
      </div>
      <Disclaimer text={d.disclaimer} />
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Shared-infrastructure graph" className="xl:col-span-8 xl:self-stretch" bodyClassName="p-0 flex-1">
          <CampaignGraph detail={d} />
        </Panel>
        <Panel title="Why these analyses are grouped" className="xl:col-span-4">
          <ul className="list-disc space-y-1 pl-4 text-sm text-fg">
            {(d.reasons.summary ?? []).map((s, i) => <li key={i}>{s}</li>)}
          </ul>
          <ul className="mt-3 divide-y divide-line border-y border-line">
            {shared.map((i) => (
              <li key={i.entity_id} className="py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <TierChip tier={i.tier} />
                  <span className="text-muted">{typeLabel(i.type)}</span>
                  <span className="break-all font-mono text-fg">{i.value}</span>
                  <span className="font-mono text-xs text-muted">weight {i.weight}</span>
                </div>
                <p className="mt-0.5 font-mono text-xs text-muted">
                  Evidence: {i.evidence.map((e) => `${e.analysis_id?.slice(0, 8)} ${e.source_field}`).join(' · ')}
                </p>
              </li>
            ))}
          </ul>
          {d.reasons.rule && <dl className="mt-2"><KV label="Rule">{d.reasons.rule}</KV></dl>}
        </Panel>
      </div>
      <section aria-label="Campaign infrastructure locations" className="space-y-2">
        <h2 className="font-mono text-xs uppercase tracking-wider text-muted">Infrastructure locations (all members)</h2>
        <GeoPanel kind="campaign" id={d.id} />
      </section>
      <Panel title="Member analyses" bodyClassName="p-0" status={<span className="font-mono text-xs">{d.members.length}</span>}>
        <DataTable<AnalysisBrief>
          label="Member analyses"
          rows={d.members}
          rowKey={(m) => m.id}
          initialSort={{ key: 'score', dir: 'desc' }}
          empty="This campaign has no member analyses."
          columns={[
            { key: 'verdict', header: 'Verdict', render: (m) => (
              <StatusTag tone={verdictTone(m.detection_verdict)}>{(m.detection_verdict ?? 'unknown').replace(/_/g, ' ')}</StatusTag>) },
            { key: 'score', header: 'Score', align: 'right', mono: true, sortValue: (m) => m.detection_score, render: (m) => m.detection_score },
            { key: 'subj', header: 'Subject', className: 'max-w-0 w-full', sortValue: (m) => m.subject, render: (m) => (
              <a href={`#analysis/${m.id}`} className="block truncate font-medium text-accent hover:underline">{m.subject || '(no subject)'}</a>) },
            { key: 'dom', header: 'Sender domain', mono: true, className: 'whitespace-nowrap', render: (m) => m.from_domain ?? '—' },
            { key: 'id', header: 'ID', render: (m) => <Mono display={m.id.slice(0, 8)}>{m.id}</Mono> },
            { key: 'sha', header: 'SHA-256', render: (m) => m.sha256 ? <Mono display={`${m.sha256.slice(0, 12)}…`}>{m.sha256}</Mono> : <span className="text-muted">—</span> },
            { key: 'at', header: 'Received', mono: true, className: 'whitespace-nowrap text-muted',
              sortValue: (m) => m.created_at ?? '', render: (m) => formatDate(m.created_at) },
          ]}
        />
      </Panel>
    </div>
  )
}
