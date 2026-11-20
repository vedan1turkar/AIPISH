// Console-style Cytoscape theme shared by the trace and campaign graphs (P5u-2).
// Cytoscape cannot read CSS variables, so token values are mirrored here as hex.
// Shapes encode the node kind (rectangle = message/analysis, diamond = IP, square = domain/host);
// colour is reserved for status (provenance / severity borders) and the accent selection.
import { Button } from '../ui'

export const G = {
  canvas: '#10161d', node: '#151c25', nodeFocal: '#1b2430', fg: '#dbe3ea', muted: '#8593a1', line: '#3a4757', lineWeak: '#2a3441',
  accent: '#4cc9f0', ok: '#3fb950', warn: '#e3a008', danger: '#f0524f',
  font: '"IBM Plex Mono", ui-monospace, monospace',
}

export type ShapeKind = 'rect' | 'diamond' | 'square' | 'square-dashed' | 'small'

export interface ShapeSpec { shape: string; width: number; height: number; borderStyle: 'solid' | 'dashed'; kind: ShapeKind }

const SPEC: Record<ShapeKind, ShapeSpec> = {
  rect: { shape: 'rectangle', width: 46, height: 24, borderStyle: 'solid', kind: 'rect' },
  diamond: { shape: 'diamond', width: 26, height: 26, borderStyle: 'solid', kind: 'diamond' },
  square: { shape: 'rectangle', width: 18, height: 18, borderStyle: 'solid', kind: 'square' },
  'square-dashed': { shape: 'rectangle', width: 18, height: 18, borderStyle: 'dashed', kind: 'square-dashed' },
  small: { shape: 'rectangle', width: 30, height: 14, borderStyle: 'solid', kind: 'small' },
}

/** Node kind → shape. Unknown kinds fall back to a small square. */
export const KIND_SHAPE: Record<string, ShapeKind> = {
  // trace graph
  message: 'rect', relay_host: 'small', ip: 'diamond', domain: 'square', url: 'square-dashed',
  // campaign graph
  analysis: 'rect', public_ip: 'diamond', sender_domain: 'square', reply_to_domain: 'square',
  return_path_domain: 'square', message_id_domain: 'square', url_host: 'square-dashed',
  attachment_hash: 'small', display_name_alias: 'small',
}

export function shapeFor(kind: string): ShapeSpec {
  return SPEC[KIND_SHAPE[kind] ?? 'square']
}

/** Base stylesheet: dark nodes, 1px borders, mono labels, muted labelled edges, accent selection. */
export function baseStyle(): unknown[] {
  return [
    { selector: 'node', style: {
      label: 'data(label)', 'font-family': G.font, 'font-size': 10, color: G.fg,
      'background-color': G.node, 'border-width': 1, 'border-color': G.muted,
      'text-valign': 'bottom', 'text-margin-y': 6, 'text-wrap': 'ellipsis', 'text-max-width': '120px',
      'text-background-color': G.canvas, 'text-background-opacity': 0.9, 'text-background-padding': '1px',
    } },
    { selector: 'edge', style: {
      label: 'data(label)', 'font-family': G.font, 'font-size': 8, color: G.muted, width: 1,
      'line-color': G.line, 'target-arrow-color': G.line, 'curve-style': 'bezier', 'text-rotation': 'autorotate',
      'text-background-color': G.canvas, 'text-background-opacity': 0.9, 'text-background-padding': '1px',
    } },
    { selector: ':selected', style: { 'border-color': G.accent, 'border-width': 2, 'line-color': G.accent, 'target-arrow-color': G.accent } },
  ]
}

/** Fit the graph, but never blow a tiny graph up past `max` zoom (labels stay at their designed size). */
export function fitCapped(cy: { fit: (e?: undefined, p?: number) => void; zoom: { (): number; (z: number): void }; center: () => void }, padding = 30, max = 1.25) {
  cy.fit(undefined, padding)
  if (cy.zoom() > max) {
    cy.zoom(max)
    cy.center()
  }
}

/** Square zoom / fit controls overlaid top-right on a graph canvas. */
export function GraphControls({ onZoom, onFit, onReset }: { onZoom: (f: number) => void; onFit: () => void; onReset?: () => void }) {
  return (
    <div className="absolute right-2 top-2 z-10 flex flex-col" role="group" aria-label="Graph controls">
      <Button size="sm" className="w-7 px-0" title="Zoom in" aria-label="Zoom in" onClick={() => onZoom(1.25)}>+</Button>
      <Button size="sm" className="-mt-px w-7 px-0" title="Zoom out" aria-label="Zoom out" onClick={() => onZoom(1 / 1.25)}>−</Button>
      <Button size="sm" className="-mt-px w-7 px-0 font-mono text-xs" title="Fit to screen" aria-label="Fit to screen" onClick={onFit}>fit</Button>
      {onReset && (
        <Button size="sm" className="-mt-px w-7 px-0 font-mono text-xs" title="Reset layout and fit" aria-label="Reset layout and fit" onClick={onReset}>rst</Button>
      )}
    </div>
  )
}

/** Tiny inline glyph matching a node shape, for legends. */
export function ShapeGlyph({ kind }: { kind: ShapeKind }) {
  const common = { fill: G.node, stroke: G.muted, strokeWidth: 1 }
  return (
    <svg width="16" height="12" viewBox="0 0 16 12" aria-hidden className="shrink-0">
      {kind === 'rect' && <rect x="0.5" y="2.5" width="15" height="7" {...common} />}
      {kind === 'small' && <rect x="2.5" y="4" width="11" height="4" {...common} />}
      {kind === 'square' && <rect x="3.5" y="1.5" width="9" height="9" {...common} />}
      {kind === 'square-dashed' && <rect x="3.5" y="1.5" width="9" height="9" {...common} strokeDasharray="2 1.5" />}
      {kind === 'diamond' && <polygon points="8,0.5 14,6 8,11.5 2,6" {...common} />}
    </svg>
  )
}

/** Compact legend: one row per node kind present, with its shape glyph and label. */
export function ShapeLegend({ items, vertical = false }: { items: { kind: string; label: string }[]; vertical?: boolean }) {
  return (
    <ul className={vertical ? 'space-y-1 text-sm text-muted' : 'flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted'} aria-label="Node types">
      {items.map((i) => (
        <li key={i.kind} className="flex items-center gap-1.5">
          <ShapeGlyph kind={KIND_SHAPE[i.kind] ?? 'square'} />{i.label}
        </li>
      ))}
    </ul>
  )
}
