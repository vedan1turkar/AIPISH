import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import type { AnalysisDetail } from '../../api/client'
import { buildTraceGraph, type TraceNode, type TraceGraph, type Evidence } from './model'
import { EmptyLine, ErrorAlert, KV, Panel, Spinner, SeverityChip, StatusTag } from '../ui'
import { G, GraphControls, ShapeLegend, baseStyle, fitCapped, shapeFor } from '../graph/style'

// ── styling (shared console graph theme: components/graph/style) ─────────────
const KIND_LABEL: Record<string, string> = {
  message: 'email',
  relay_host: 'mail server',
  ip: 'IP address',
  domain: 'domain',
  url: 'URL',
}

// Provenance → 1px border colour; inferred nodes are also dimmed.
const PROV_STYLE: Record<string, { border: string; opacity: number }> = {
  observed: { border: G.ok, opacity: 1 },
  enriched: { border: G.accent, opacity: 1 },
  inferred: { border: G.muted, opacity: 0.7 },
}

/** Border color by actual finding severity (2px) — no fixture-specific rules. */
const SEV_BORDER: Record<string, string> = {
  low: G.muted,
  medium: G.warn,
  high: G.danger,
  critical: G.danger,
}

const CY_LAYOUT = {
  name: 'breadthfirst',
  directed: true,
  roots: '#message',
  spacingFactor: 1.8,
  padding: 56,
  avoidOverlap: true,
  avoidOverlapPadding: 28,
  nodeDimensionsIncludeLabels: true,
  animate: false,
}

function buildElements(g: TraceGraph): ElementDefinition[] {
  const elems: ElementDefinition[] = []
  for (const n of g.nodes) {
    const base = PROV_STYLE[n.provenance] ?? PROV_STYLE.inferred
    const spec = shapeFor(n.kind)
    // severity-driven highlight only when actual findings reference this entity
    const sev = n.severity
    const seStyle = sev && SEV_BORDER[sev]
      ? { 'border-color': SEV_BORDER[sev], 'border-width': 2 }
      : { 'border-color': base.border, 'border-width': 1 }
    elems.push({
      data: {
        id: n.id,
        label: n.label.length > 34 ? `${n.label.slice(0, 33)}…` : n.label,
        kind: n.kind,
        provenance: n.provenance,
        severity: n.severity ?? null,
        finding_ids: n.finding_ids ?? [],
        enrichment_statuses: n.enrichment_statuses ?? [],
        geo: n.geo ?? null,
        raw: n, // full node payload for the details panel
      },
      style: {
        shape: spec.shape,
        width: spec.width,
        height: spec.height,
        'border-style': spec.borderStyle,
        'background-color': n.kind === 'message' ? G.nodeFocal : G.node,
        opacity: base.opacity,
        ...seStyle,
      },
    } as ElementDefinition)
  }
  for (const e of g.edges) {
    const observed = e.provenance === 'observed'
    elems.push({
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        // Repeating labels on dense URL relationships obscure the evidence.
        // The arrow remains clickable and shows its exact relationship in details.
        label: e.label === 'links to' || e.label === 'hosted on' ? '' : e.label,
        relationship: e.label,
        provenance: e.provenance,
        raw: e,
      },
      style: {
        'line-color': observed ? G.muted : G.line,
        'line-style': observed ? 'solid' : 'dashed',
        'target-arrow-color': observed ? G.muted : G.line,
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.8,
        color: observed ? G.fg : G.muted,
        'text-rotation': 'none',
      },
    } as ElementDefinition)
  }
  return elems
}

// ── Details side panel for a clicked node/edge ──────────────────────────────
interface SelectedItem {
  id: string
  kind?: string
  provenance?: string
  label?: string
  evidence?: Evidence[]
  severity?: string | null
  finding_ids?: string[]
  enrichment_statuses?: { provider: string; status: string; latency_ms: number }[]
  relationship?: string
}

function EvidenceCard({
  item,
  finding_details,
}: {
  item: SelectedItem
  finding_details: AnalysisDetail['detection']['findings']
}) {
  const isEdge = !item.kind
  const title = item.kind
    ? item.kind === 'message'
      ? 'Analyzed message (observed)'
      : `${item.kind.replace('_', ' ')} (${item.provenance})`
    : `Relationship: ${item.provenance ?? 'unknown'}`
  const linked =
    item.finding_ids && item.finding_ids.length > 0
      ? finding_details.filter((f) => item.finding_ids!.includes(f.rule_id))
      : []
  const enr = item.enrichment_statuses ?? []
  const provTone = item.provenance === 'observed' ? 'ok' : item.provenance === 'inferred' ? 'neutral' : 'accent'
  return (
    <Panel title="Selected element" status={
      <StatusTag tone={provTone}>{isEdge ? `${item.provenance ?? '?'} edge` : (item.provenance ?? '?')}</StatusTag>}>
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      {item.label && !isEdge && (
        <p className="mt-0.5 break-all font-mono text-sm text-fg">{item.label}</p>
      )}
      {isEdge && item.relationship && (
        <p className="mt-1 text-sm text-fg">
          Relationship: <span className="font-semibold">{item.relationship}</span>
        </p>
      )}
      <p className="truncate font-mono text-xs text-muted">{item.id}</p>

      {/* severity + associated findings — from actual detection findings */}
      {item.severity && (
        <div className="mt-2 flex items-center gap-2">
          <SeverityChip severity={item.severity} />
          <span className="text-sm text-muted">referenced by detection findings</span>
        </div>
      )}
      {linked.length > 0 && (
        <ul className="mt-2 divide-y divide-line border-y border-line">
          {linked.map((f) => (
            <li key={f.rule_id} className="py-1.5 text-sm">
              <span className="font-medium text-fg">{f.title}</span>
              <span className="ml-1 font-mono text-xs text-muted">(+{f.contribution} pts)</span>
              <p className="mt-0.5 break-all text-muted">{f.evidence}</p>
            </li>
          ))}
        </ul>
      )}

      {/* enrichment statuses — verbatim provider results, or nothing when none */}
      {enr.length > 0 && (
        <div className="mt-2">
          <p className="font-mono text-xs uppercase tracking-wide text-muted">Enrichment</p>
          <ul className="mt-0.5 space-y-0.5 text-sm text-fg">
            {enr.map((s, i) => (
              <li key={i}>
                <span className="font-mono">{s.provider}</span>: {s.status} · {s.latency_ms} ms
              </li>
            ))}
          </ul>
        </div>
      )}

      <dl className="mt-2 border-t border-line pt-1">
        {evidence_list(item.evidence)}
      </dl>
    </Panel>
  )
}

function evidence_list(evidence?: { label: string; value: string }[]) {
  if (!evidence || evidence.length === 0) {
    return <p className="py-1 text-sm text-muted">No evidence recorded for this element.</p>
  }
  return evidence.map((evi, i) => (
    <KV key={i} label={evi.label}><span className="break-all">{evi.value || '—'}</span></KV>
  ))
}

// ── the main trace view ────────────────────────────────────────────────────
export default function TraceView({ analysis }: { analysis: AnalysisDetail }) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const cyRef = useRef<Core | null>(null)
  const [graph, setGraph] = useState<TraceGraph | null>(null)
  const [selected, setSelected] = useState<SelectedItem | null>(null)
  const [renderError, setRenderError] = useState<string | null>(null)

  const hasData = useMemo(() => {
    if (!analysis) return false
    return (
      (analysis.forensics?.relay_chain?.length ?? 0) > 0 ||
      (analysis.forensics?.candidate_ips?.length ?? 0) > 0 ||
      (analysis.urls?.length ?? 0) > 0 ||
      !!analysis.from?.domain
    )
  }, [analysis])

  useEffect(() => {
    if (!analysis) return
    setSelected(null)
    setRenderError(null)
    setGraph(buildTraceGraph(analysis))
  }, [analysis])

  useEffect(() => {
    if (!graph || !containerRef.current) return
    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements: buildElements(graph),
        layout: { ...CY_LAYOUT },
        style: baseStyle(),
        wheelSensitivity: 0.2,
        autoungrabify: true,
      } as never)
      cy.on('tap', 'node, edge', (evt) => {
        const raw = evt.target?.data?.('raw')
        if (raw) {
          setSelected({
            id: raw.id,
            kind: raw.kind,
            provenance: raw.provenance,
            label: raw.label,
            evidence: raw.evidence,
            severity: raw.severity ?? null,
            finding_ids: raw.finding_ids ?? [],
            enrichment_statuses: raw.enrichment_statuses ?? [],
            relationship: raw.label,
          })
        }
      })
      cy.on('tap', (evt) => {
        if (evt.target === cy) setSelected(null)
      })
      cyRef.current = cy
      // Cytoscape may initialise while its tab is acquiring its final size.
      // Run one frame later so a dense graph uses the visible canvas instead
      // of rendering as a tiny cluster in one corner.
      const layoutAndFit = () => {
        cy.resize()
        cy.layout({ ...CY_LAYOUT }).run()
        fitCapped(cy as never, 56)
      }
      const frame = window.requestAnimationFrame(layoutAndFit)
      const onResize = () => cy.resize()
      window.addEventListener('resize', onResize)
      // the canvas stretches with the side column (row height), so follow container size changes too
      const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(onResize) : null
      ro?.observe(containerRef.current)
      return () => {
        window.cancelAnimationFrame(frame)
        window.removeEventListener('resize', onResize)
        ro?.disconnect()
        cy.destroy()
        cyRef.current = null
      }
    } catch (err) {
      setRenderError(err instanceof Error ? err.message : 'Graph failed to render.')
    }
  }, [graph])

  const geoNodes = graph?.nodes.filter((n) => n.geo) ?? []

  const zoomBy = (factor: number) => {
    const cy = cyRef.current
    if (!cy) return
    const z = cy.zoom() * factor
    cy.zoom(Math.min(cy.maxZoom(), Math.max(cy.minZoom(), z)))
  }

  const kindsPresent = Object.keys(KIND_LABEL).filter((k) => graph?.nodes.some((n) => n.kind === k))
  const resetLayout = () => {
    const cy = cyRef.current
    if (!cy) return
    cy.layout({ ...CY_LAYOUT }).run()
    fitCapped(cy as never)
  }

  return (
    <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <Panel title="Relay and infrastructure trace" className="xl:self-stretch" bodyClassName="p-0 flex flex-col"
             status={graph && graph.nodes.length > 1
               ? <span className="font-mono text-xs">{graph.nodes.length} entities · {graph.edges.length} relationships</span>
               : undefined}>
        <div className="relative min-h-[max(420px,min(64vh,600px))] flex-1 overflow-hidden bg-surface">
          {!hasData ? (
            <div className="flex h-full items-center justify-center p-4">
              <EmptyLine>Nothing to trace yet. This message has no relay hops, IPs, sender domain or URLs to visualize.</EmptyLine>
            </div>
          ) : renderError ? (
            <div className="flex h-full items-center justify-center p-4">
              <ErrorAlert message={renderError} />
            </div>
          ) : !graph ? (
            <div className="flex h-full items-center justify-center">
              <Spinner label="Building trace…" />
            </div>
          ) : (
            <>
              <div ref={containerRef} className="absolute inset-0" aria-label="Trace graph" role="img" />
              <GraphControls onZoom={zoomBy} onFit={() => cyRef.current && fitCapped(cyRef.current as never)} onReset={resetLayout} />
              {graph.nodes.length > 1 && (
                <div className="pointer-events-none absolute bottom-2 left-2 border border-line bg-surface px-2 py-1 text-xs text-muted">
                  select an entity or arrow for evidence
                </div>
              )}
              {graph.nodes.length === 1 && graph.nodes[0].kind === 'message' && (
                <div className="pointer-events-none absolute inset-x-0 bottom-3 text-center text-xs text-muted">
                  Only the message node is present — no relay/URL indicators found.
                </div>
              )}
            </>
          )}
        </div>
      </Panel>

      <aside className="space-y-4 xl:sticky xl:top-4">
        {/* details panel */}
        {selected ? (
          <EvidenceCard item={selected} finding_details={analysis.detection?.findings ?? []} />
        ) : (
          <Panel title="Selected element">
            <EmptyLine>Click an entity or arrow to inspect its evidence, source, findings and enrichment status.</EmptyLine>
          </Panel>
        )}
        <Panel title="Legend">
          <div className="space-y-3">
            <ShapeLegend vertical items={(kindsPresent.length ? kindsPresent : Object.keys(KIND_LABEL)).map((k) => ({ kind: k, label: KIND_LABEL[k] }))} />
            <ul className="space-y-1 border-t border-line pt-2 text-sm text-muted" aria-label="Evidence and edges">
              <li className="flex items-center gap-2"><span aria-hidden className="inline-block h-2.5 w-2.5 border border-ok" />Observed (from message bytes)</li>
              <li className="flex items-center gap-2"><span aria-hidden className="inline-block h-2.5 w-2.5 border border-muted opacity-70" />Inferred (heuristic reconstruction)</li>
              <li className="flex items-center gap-2"><span aria-hidden className="inline-block h-0 w-4 border-t border-solid border-muted" />observed edge</li>
              <li className="flex items-center gap-2"><span aria-hidden className="inline-block h-0 w-4 border-t border-dashed border-muted" />inferred edge (heuristic)</li>
            </ul>
            <p className="text-sm text-muted">Border color reflects finding severity; provider results appear in details.</p>
            <p className="border-t border-line pt-2 text-sm text-muted">
              A relay visualization represents the observed or inferred infrastructure path —
              it does <strong className="font-semibold text-fg">not</strong> prove a person&apos;s physical
              travel or identity.
            </p>
          </div>
        </Panel>
        {/* map: only when provider gave coordinates */}
        <MapPanel geoNodes={geoNodes} />
      </aside>
    </div>
  )
}

// ── Map panel with unavailable state ───────────────────────────────────────
function MapPanel({ geoNodes }: { geoNodes: TraceNode[] }) {
  if (geoNodes.length === 0) {
    return (
      <Panel title="Infrastructure location">
        <p className="border border-warn-line bg-warn-weak px-3 py-2 text-sm text-warn">
          Map unavailable — no geolocation provider returned coordinates for the observed
          public IPs. Enable a provider (e.g. <code className="font-mono">ENRICH_ENABLE_IPGEO</code> or a
          MaxMind database key) to see infrastructure locations plotted; nothing is invented
          here in the meantime.
        </p>
      </Panel>
    )
  }
  // Provider-reported coordinates only — plotted on an equirectangular grid.
  return (
    <Panel title="Infrastructure location (provider-reported)">
      <p className="text-sm text-muted">
        Network infrastructure location only — this does not locate or identify a person.
      </p>
      <div className="mt-2 overflow-x-auto">
        <svg viewBox="0 0 360 180" className="h-40 w-full min-w-[320px] border border-line bg-bg" role="img" aria-label="Provider-reported infrastructure locations">
          {[30, 60, 90, 120, 150].map((y) => (
            <line key={y} x1="0" y1={y} x2="360" y2={y} stroke={G.lineWeak} strokeWidth="0.5" />
          ))}
          {[60, 120, 180, 240, 300].map((x) => (
            <line key={x} x1={x} y1="0" x2={x} y2="180" stroke={G.lineWeak} strokeWidth="0.5" />
          ))}
          <line x1="0" y1="90" x2="360" y2="90" stroke={G.line} strokeWidth="1" />
          <line x1="180" y1="0" x2="180" y2="180" stroke={G.line} strokeWidth="1" />
          {geoNodes.map((n) => {
            const x = ((n.geo!.lon + 180) / 360) * 360
            const y = ((90 - n.geo!.lat) / 180) * 180
            return (
              <g key={n.id}>
                <rect x={x - 3} y={y - 3} width="6" height="6" fill={G.accent} stroke={G.canvas} strokeWidth="1" />
                <text x={x + 7} y={y + 3} fontSize="7" fill={G.fg} fontFamily={G.font}>
                  {n.geo!.label || n.label}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
      <ul className="mt-2 space-y-0.5 text-sm text-muted">
        {geoNodes.map((n) => (
          <li key={n.id}>
            <span className="font-mono">{n.label}</span> → {n.geo!.label} ({n.geo!.provider})
          </li>
        ))}
      </ul>
    </Panel>
  )
}
