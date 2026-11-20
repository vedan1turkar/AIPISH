// Correlation display model (P5c). Wording is always "shared infrastructure / candidate campaign",
// never "same attacker" or "same person".
import type { CampaignDetail, GraphNode } from '../../api/client'
import { shapeFor } from '../graph/style'
import type { Tone } from '../ui'

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

/** Indicator tier → status tone (always rendered with its text label). */
export const TIER_TONE: Record<string, Tone> = { strong: 'danger', medium: 'warn', weak: 'neutral' }

/** Campaign / link confidence → status tone (always rendered with its text label). */
export const CONFIDENCE_TONE: Record<string, Tone> = { high: 'danger', medium: 'warn', low: 'neutral' }

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
      shape: shapeFor(n.kind).shape,
      w: shapeFor(n.kind).width,
      h: shapeFor(n.kind).height,
      borderStyle: shapeFor(n.kind).borderStyle,
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
