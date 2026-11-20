// Correlation display model (P5c). Wording is always "shared infrastructure / candidate campaign",
// never "same attacker" or "same person".
import type { CampaignDetail, GraphNode } from '../../api/client'

export const TYPE_LABEL: Record<string, string> = {
  public_ip: 'Public IP',
  sender_domain: 'Sender domain',
  reply_to_domain: 'Reply-To domain',
  return_path_domain: 'Return-Path domain',
  message_id_domain: 'Message-ID domain',
  url_host: 'URL host',
  attachment_hash: 'Attachment SHA-256',
  display_name_alias: 'Display name',
  analysis: 'Analysis',
}

export const TIER_STYLE: Record<string, string> = {
  strong: 'bg-rose-100 text-rose-800 ring-rose-300',
  medium: 'bg-amber-100 text-amber-800 ring-amber-300',
  weak: 'bg-slate-100 text-slate-700 ring-slate-300',
}

export const CONFIDENCE_STYLE: Record<string, string> = {
  high: 'bg-rose-50 text-rose-800 ring-rose-200',
  medium: 'bg-amber-50 text-amber-800 ring-amber-200',
  low: 'bg-slate-50 text-slate-700 ring-slate-200',
}

export const NODE_COLOR: Record<string, string> = {
  analysis: '#4f46e5',
  public_ip: '#0369a1',
  reply_to_domain: '#7c3aed',
  sender_domain: '#7c3aed',
  return_path_domain: '#7c3aed',
  message_id_domain: '#7c3aed',
  url_host: '#c2410c',
  attachment_hash: '#be123c',
  display_name_alias: '#475569',
}

export const NODE_SHAPE: Record<string, string> = {
  analysis: 'round-rectangle',
  public_ip: 'ellipse',
  attachment_hash: 'hexagon',
  url_host: 'round-tag',
}

export function typeLabel(t: string): string {
  return TYPE_LABEL[t] ?? t.replace(/_/g, ' ')
}

export function nodeTooltip(n: GraphNode, detail: CampaignDetail): string {
  if (n.kind === 'analysis') return `Analysis ${n.analysis_id?.slice(0, 8)} · ${n.subject ?? ''} · score ${n.score ?? '?'} · ${n.verdict ?? ''}`
  const edges = detail.graph.edges.filter((e) => e.target === n.id)
  const refs = edges.map((e) => `${e.source.slice(2, 10)}: ${e.source_field}`).join('; ')
  return `${typeLabel(n.kind)} ${n.label} · ${n.tier} (${n.weight}) · evidence ${refs}`
}

export interface CyElement {
  data: Record<string, string | number | undefined>
  classes?: string
}

/** Cytoscape elements for a campaign: analyses + shared entities, edges labelled by role. */
export function buildCampaignElements(detail: CampaignDetail): CyElement[] {
  const nodes: CyElement[] = detail.graph.nodes.map((n) => ({
    data: {
      id: n.id,
      label: n.kind === 'analysis' ? (n.label || n.analysis_id?.slice(0, 8) || '') : n.label,
      kind: n.kind,
      color: NODE_COLOR[n.kind] ?? '#64748b',
      shape: NODE_SHAPE[n.kind] ?? 'diamond',
      tooltip: nodeTooltip(n, detail),
    },
    classes: n.kind === 'analysis' ? 'analysis' : `entity tier-${n.tier ?? 'weak'}`,
  }))
  const edges: CyElement[] = detail.graph.edges.map((e) => ({
    data: { id: e.id, source: e.source, target: e.target, label: e.role.replace(/_/g, ' '),
            tooltip: `${e.role} · ${e.source_field}`, tier: e.tier },
  }))
  return [...nodes, ...edges]
}
