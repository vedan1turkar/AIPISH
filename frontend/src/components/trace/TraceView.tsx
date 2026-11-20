import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import type { AnalysisDetail } from '../../api/client'
import { buildTraceGraph, type TraceNode, type TraceGraph, type Evidence } from './model'
import { EmptyState, ErrorAlert, Spinner, SeverityChip } from '../ui'

// ── styling ────────────────────────────────────────────────────────────────
const KIND_SHAPE: Record<string, string> = {
  message: 'round-tag',
  relay_host: 'round-rectangle',
  ip: 'ellipse',
  domain: 'diamond',
  url: 'round-tag',
}

// Graph palette = design tokens as hex (Cytoscape cannot read CSS variables). Node kinds are told
// apart by shape and label; only the message node uses the accent.
const KIND_COLOR: Record<string, string> = {
  message: '#4cc9f0',
  relay_host: '#5b6b7c',
  ip: '#8593a1',
  domain: '#6f7f8f',
  url: '#a3b0bc',
}

const KIND_LABEL: Record<string, string> = {
  message: 'email',
  relay_host: 'mail server',
  ip: 'IP address',
  domain: 'domain',
  url: 'URL',
}

const PROV_STYLE: Record<string, { border: string; 'border-width': number; opacity: number }> = {
  observed: { border: '#3fb950', 'border-width': 3, opacity: 1 },
  enriched: { border: '#4cc9f0', 'border-width': 3, opacity: 1 },
  inferred: { border: '#8593a1', 'border-width': 3, opacity: 0.75 },
}

/** Border color by actual finding severity — no fixture-specific rules. */
const SEV_BORDER: Record<string, string> = {
  low: '#8593a1',
  medium: '#e3a008',
  high: '#f0524f',
  critical: '#f0524f',
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
    const base = PROV_STYLE[n.provenance]
    // severity-driven highlight only when actual findings reference this entity
    const sev = n.severity
    const seStyle = sev && SEV_BORDER[sev]
      ? { 'border-color': SEV_BORDER[sev], 'border-width': 5 }
      : { 'border-color': base.border, 'border-width': base['border-width'] }
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
        shape: KIND_SHAPE[n.kind] ?? 'ellipse',
        'background-color': KIND_COLOR[n.kind] ?? '#8593a1',
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
        width: 2,
        'line-color': observed ? '#8593a1' : '#3a4757',
        'line-style': observed ? 'solid' : 'dashed',
        'target-arrow-color': observed ? '#8593a1' : '#3a4757',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        label: e.label,
        'font-size': 9,
        color: observed ? '#dbe3ea' : '#8593a1',
        'font-style': observed ? 'normal' : 'italic',
        'text-background-color': '#10161d',
        'text-background-opacity': 0.85,
        'text-background-padding': 2,
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
  return (
    <div className=" border border-gray-200 bg-white p-4 ">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-gray-900">{title}</h3>
        <span
          className={` px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${
 item.provenance === 'observed'
 ? 'bg-emerald-100 text-emerald-800 ring-emerald-300'
 : item.provenance === 'enriched'
 ? 'bg-blue-100 text-blue-800 ring-blue-300'
 : item.provenance === 'inferred'
 ? 'bg-gray-100 text-gray-600 ring-gray-300'
 : 'bg-indigo-100 text-indigo-700 ring-indigo-200'
 }`}
        >
          {isEdge ? `${item.provenance ?? '?'} edge` : (item.provenance ?? '?')}
        </span>
      </div>
      {item.label && !isEdge && (
        <p className="mt-0.5 break-all font-mono text-xs text-gray-700">{item.label}</p>
      )}
      {isEdge && item.relationship && (
        <p className="mt-1 text-xs text-gray-700">
          Relationship: <span className="font-semibold">{item.relationship}</span>
        </p>
      )}
      <p className="truncate font-mono text-xs text-gray-400">{item.id}</p>

      {/* severity + associated findings — from actual detection findings */}
      {item.severity && (
        <div className="mt-2 flex items-center gap-1.5">
          <SeverityChip severity={item.severity} />
          <span className="text-xs text-gray-500">referenced by detection findings</span>
        </div>
      )}
      {linked.length > 0 && (
        <div className="mt-2 space-y-1">
          {linked.map((f) => (
            <div key={f.rule_id} className=" border border-gray-200 bg-gray-50 px-2 py-1.5 text-xs">
              <span className="font-medium text-gray-800">{f.title}</span>
              <span className="ml-1 text-gray-400">(+{f.contribution} pts)</span>
              <p className="mt-0.5 break-all text-gray-600">{f.evidence}</p>
            </div>
          ))}
        </div>
      )}

      {/* enrichment statuses — verbatim provider results, or nothing when none */}
      {enr.length > 0 && (
        <div className="mt-2 bg-blue-50 px-2 py-1.5">
          <p className="text-xs font-semibold uppercase tracking-wide text-blue-700">Enrichment</p>
          <ul className="mt-0.5 space-y-0.5 text-xs text-blue-900">
            {enr.map((s, i) => (
              <li key={i}>
                <span className="font-mono">{s.provider}</span>: {s.status} · {s.latency_ms} ms
              </li>
            ))}
          </ul>
        </div>
      )}

      <dl className="mt-2 space-y-1.5">
        {evidence_list(item.evidence)}
      </dl>
    </div>
  )
}

function evidence_list(evidence?: { label: string; value: string }[]) {
  if (!evidence || evidence.length === 0) {
    return <p className="text-xs text-gray-400">No evidence recorded for this element.</p>
  }
  return evidence.map((evi, i) => (
    <div key={i} className="text-xs">
      <dt className="font-medium text-gray-500">{evi.label}</dt>
      <dd className="break-all text-gray-800">{evi.value || '—'}</dd>
    </div>
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
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'font-size': 11,
              color: '#dbe3ea',
              'text-valign': 'bottom',
              'text-margin-y': 8,
              'text-wrap': 'wrap',
              'text-max-width': 112,
              'text-outline-color': '#0a0e13',
              'text-outline-width': 2,
              width: 32,
              height: 32,
            },
          },
          {
            selector: 'edge',
            style: {
              label: 'data(label)',
              'curve-style': 'bezier',
            },
          },
          {
            selector: ':selected',
            style: {
              'border-color': '#4f46e5',
              'border-width': 5,
            },
          },
        ],
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
        cy.fit(undefined, 56)
      }
      const frame = window.requestAnimationFrame(layoutAndFit)
      const onResize = () => cy.resize()
      window.addEventListener('resize', onResize)
      return () => {
        window.cancelAnimationFrame(frame)
        window.removeEventListener('resize', onResize)
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

  return (
    <div className="space-y-4">
      {/* legend + disclaimer */}
      <div className=" border border-gray-200 bg-white p-3 ">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-gray-600">
            <span className="font-semibold text-gray-700">Evidence:</span>
            {(['observed', 'inferred'] as const).map((p) => (
              <span key={p} className="flex items-center gap-1.5">
                <span
                  className={`inline-block h-3 w-3 ring-2 ${
 p === 'observed'
 ? 'bg-emerald-600 ring-emerald-300'
 : 'bg-gray-400 opacity-70 ring-gray-200'
 }`}
                />
                {p === 'observed' && 'Observed (from message bytes)'}
                {p === 'inferred' && 'Inferred (heuristic reconstruction)'}
              </span>
            ))}
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs text-gray-500">
            <span className="font-semibold text-gray-700">Node types:</span>
            {Object.entries(KIND_COLOR).map(([kind, color]) => (
              <span key={kind} className="flex items-center gap-1.5">
                <span className="inline-block h-3 w-3 rounded-sm" style={{ backgroundColor: color }} />
                {KIND_LABEL[kind] ?? kind.replace('_', ' ')}
              </span>
            ))}
            <span className="text-gray-400">Border color reflects finding severity; provider results appear in details.</span>
          </div>
          {/* edge-style legend: observed solid / inferred dashed */}
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-gray-500">
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-0 w-8 border-t-2 border-solid border-gray-500" />
              observed edge
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-0 w-8 border-t-2 border-dashed border-gray-300" />
              inferred edge (heuristic)
            </span>
          </div>
          <p className="mt-2 text-xs italic text-gray-400">
            A relay visualization represents the observed or inferred infrastructure path —
            it does <strong className="not-italic">not</strong> prove a person&apos;s physical
            travel or identity.
          </p>
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
        <div className="relative h-[min(68vh,620px)] min-h-[440px] overflow-hidden border border-gray-200 bg-gray-50 ">
          {!hasData ? (
            <div className="flex h-full items-center justify-center p-4">
              <EmptyState
                title="Nothing to trace yet"
                hint="This message has no relay hops, IPs, sender domain or URLs to visualize."
              />
            </div>
          ) : renderError ? (
            <div className="flex h-full items-center justify-center">
              <ErrorAlert message={renderError} />
            </div>
          ) : !graph ? (
            <div className="flex h-full items-center justify-center">
              <Spinner label="Building trace…" />
            </div>
          ) : (
            <>
              <div ref={containerRef} className="h-full w-full" />

              {/* zoom / fit / reset controls */}
              <div className="absolute right-2 top-2 z-10 flex flex-col gap-1">
                <button
                  title="Zoom in"
                  aria-label="Zoom in"
                  onClick={() => zoomBy(1.25)}
                  className="h-7 w-7 border border-gray-300 bg-surface text-sm font-semibold text-gray-600 hover:bg-gray-50 active:bg-gray-100"
                >
                  +
                </button>
                <button
                  title="Zoom out"
                  aria-label="Zoom out"
                  onClick={() => zoomBy(1 / 1.25)}
                  className="h-7 w-7 border border-gray-300 bg-surface text-sm font-semibold text-gray-600 hover:bg-gray-50 active:bg-gray-100"
                >
                  −
                </button>
                <button
                  title="Fit to screen"
                  aria-label="Fit to screen"
                  onClick={() => cyRef.current?.fit(undefined, 30)}
                  className="h-7 w-7 border border-gray-300 bg-surface text-sm font-semibold text-gray-600 hover:bg-gray-50 active:bg-gray-100"
                >
                  ⤢
                </button>
                <button
                  title="Reset layout and fit"
                  aria-label="Reset layout and fit"
                  onClick={() => {
                    const cy = cyRef.current
                    if (!cy) return
                    cy.layout({ ...CY_LAYOUT }).run()
                    cy.fit(undefined, 30)
                  }}
                  className="h-7 w-7 border border-gray-300 bg-surface text-sm font-semibold text-gray-600 hover:bg-gray-50 active:bg-gray-100"
                >
                  ↺
                </button>
              </div>
              {graph.nodes.length > 1 && (
                <div className="pointer-events-none absolute bottom-3 left-3 border border-gray-200 bg-surface px-2 py-1 text-xs text-gray-500 ">
                  {graph.nodes.length} entities · {graph.edges.length} relationships · select an entity or arrow for evidence
                </div>
              )}
              {graph.nodes.length === 1 && graph.nodes[0].kind === 'message' && (
                <div className="pointer-events-none absolute inset-x-0 bottom-3 text-center text-xs text-gray-400">
                  Only the message node is present — no relay/URL indicators found.
                </div>
              )}
            </>
          )}
        </div>

        <aside className="space-y-4 xl:sticky xl:top-4">
          {/* details panel */}
          {selected ? (
            <EvidenceCard item={selected} finding_details={analysis.detection?.findings ?? []} />
          ) : (
            <div className=" border border-dashed border-gray-300 bg-white px-4 py-5 text-center text-xs text-gray-400">
              Click an entity or arrow to inspect its evidence, source, findings and enrichment status.
            </div>
          )}
          {/* map: only when provider gave coordinates */}
          <MapPanel geoNodes={geoNodes} />
        </aside>
      </div>
    </div>
  )
}

// ── Map panel with unavailable state ───────────────────────────────────────
function MapPanel({ geoNodes }: { geoNodes: TraceNode[] }) {
  if (geoNodes.length === 0) {
    return (
      <div className=" border border-gray-200 bg-white p-4 ">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Infrastructure location</h3>
        <p className="mt-2 bg-orange-50 px-3 py-2 text-xs text-orange-700">
          Map unavailable — no geolocation provider returned coordinates for the observed
          public IPs. Enable a provider (e.g. <code>ENRICH_ENABLE_IPGEO</code> or a
          MaxMind database key) to see infrastructure locations plotted; nothing is invented
          here in the meantime.
        </p>
      </div>
    )
  }
  // Provider-reported coordinates only — plotted on an equirectangular grid.
  return (
    <div className=" border border-gray-200 bg-white p-4 ">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">
        Infrastructure location (provider-reported)
      </h3>
      <p className="mt-1 text-xs italic text-gray-400">
        Network infrastructure location only — this does not locate or identify a person.
      </p>
      <div className="mt-2 overflow-x-auto">
        <svg viewBox="0 0 360 180" className="h-40 w-full min-w-[320px] border border-gray-100 bg-sky-50">
          {[30, 60, 90, 120, 150].map((y) => (
            <line key={y} x1="0" y1={y} x2="360" y2={y} stroke="#e0f2fe" strokeWidth="0.5" />
          ))}
          {[60, 120, 180, 240, 300].map((x) => (
            <line key={x} x1={x} y1="0" x2={x} y2="180" stroke="#e0f2fe" strokeWidth="0.5" />
          ))}
          <line x1="0" y1="90" x2="360" y2="90" stroke="#bfdbfe" strokeWidth="1" />
          <line x1="180" y1="0" x2="180" y2="180" stroke="#bfdbfe" strokeWidth="1" />
          {geoNodes.map((n) => {
            const x = ((n.geo!.lon + 180) / 360) * 360
            const y = ((90 - n.geo!.lat) / 180) * 180
            return (
              <g key={n.id}>
                <circle cx={x} cy={y} r="5" fill="#dc2626" fillOpacity="0.85" stroke="#fff" strokeWidth="1.5" />
                <text x={x + 7} y={y + 3} fontSize="7" fill="#334155">
                  {n.geo!.label || n.label}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
      <ul className="mt-2 space-y-0.5 text-xs text-gray-500">
        {geoNodes.map((n) => (
          <li key={n.id}>
            <span className="font-mono">{n.label}</span> → {n.geo!.label} ({n.geo!.provider})
          </li>
        ))}
      </ul>
    </div>
  )
}
