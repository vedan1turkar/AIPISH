import type { AnalysisDetail, EnrichmentRecord } from '../../api/client'

/**
 * Pure data-shaping layer: turns one AnalysisDetail into the forensic trace
 * graph (nodes + edges + provenance-backed evidence). NO invented data —
 * every node/edge is traceable to a field of the analysis record.
 *
 * Node provenance kinds:
 *  - observed:  proved by the message bytes (headers/body)
 *  - enriched:  added by an external provider lookup (DNS/IP-geo/RDAP)
 *  - inferred:  heuristic reconstruction (candidate relay path)
 */

export type Provenance = 'observed' | 'enriched' | 'inferred'

export type NodeKind =
  | 'message'     // the analyzed email itself (root)
  | 'relay_host'  // a Received-chain hop
  | 'ip'          // candidate public IP
  | 'domain'      // sender / url-host domain
  | 'url'         // URL indicator
  | 'provider'    // external lookup context

export interface Evidence {
  label: string
  value: string
}

export interface TraceNode {
  id: string
  kind: NodeKind
  label: string
  provenance: Provenance
  evidence: Evidence[]
  /** severity from findings that reference this entity (null = not in any finding) */
  severity?: string | null
  /** rule_ids of detection findings that reference this entity */
  finding_ids?: string[]
  /** enrichment status strings for this entity, verbatim from providers */
  enrichment_statuses?: { provider: string; status: string; latency_ms: number }[]
  /** provider-supplied coordinates when an ipgeo result was ok */
  geo?: { lat: number; lon: number; label: string; provider: string }
}

export interface TraceEdge {
  id: string
  source: string
  target: string
  label: string
  provenance: Provenance
  evidence: Evidence[]
}

export interface TraceGraph {
  nodes: TraceNode[]
  edges: TraceEdge[]
  hasGeo: boolean
}

function ev(label: string, value: string | null | undefined): Evidence {
  return { label, value: value ?? '' }
}

function findRecord(
  enrichment: EnrichmentRecord[],
  provider: string,
  kind: string,
  value: string,
): EnrichmentRecord | undefined {
  return enrichment.find(
    (r) => r.provider === provider && r.ioc?.ioc_kind === kind && r.ioc?.ioc_value === value,
  )
}

/** ipgeo evidence nested under evidence['network_location'] with lat/lon? */
function extractCoords(r: EnrichmentRecord | undefined): TraceNode['geo'] | undefined {
  if (!r || r.status !== 'ok') return undefined
  const net = (r.evidence as { network_location?: Record<string, unknown> } | undefined)
    ?.network_location
  if (net && typeof net === 'object') {
    const nl = net as { latitude?: unknown; longitude?: unknown; city?: unknown; region?: unknown; country?: unknown }
    const lat = Number(nl.latitude)
    const lon = Number(nl.longitude)
    if (Number.isFinite(lat) && Number.isFinite(lon)) {
      return {
        lat,
        lon,
        label: [nl.city, nl.region, nl.country].filter(Boolean).map(String).join(', '),
        provider: r.provider,
      }
    }
  }
  return undefined
}

/**
 * Map an entity (domain/IP/host/URL string) to rule_ids whose evidence text
 * mentions it. Pure text-matching against the backend's own finding evidence —
 * no fixture-specific logic, no invented link.
 */
function findingIdsFor(
  values: (string | null | undefined)[],
  findings: { rule_id: string; evidence: string; title: string }[],
): string[] {
  const vals = values.filter((v): v is string => !!v).map((v) => v.toLowerCase())
  if (vals.length === 0) return []
  const hit: string[] = []
  for (const f of findings) {
    const hay = `${f.evidence} ${f.title}`.toLowerCase()
    if (vals.some((v) => hay.includes(v))) hit.push(f.rule_id)
  }
  return hit
}

/** Severity for an entity = highest severity among its referencing findings. */
const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
export function severityFor(
  values: (string | null | undefined)[],
  findings: { rule_id: string; evidence: string; title: string; severity: string }[],
): { severity: string | null; rule_ids: string[] } {
  const ids = findingIdsFor(values, findings)
  if (ids.length === 0) return { severity: null, rule_ids: [] }
  const sev = findings
    .filter((f) => ids.includes(f.rule_id))
    .reduce((max, f) => ((SEV_RANK[f.severity] ?? 0) > (SEV_RANK[max] ?? 0) ? f.severity : max), 'info')
  return { severity: sev, rule_ids: ids }
}

export function buildTraceGraph(a: AnalysisDetail): TraceGraph {
  const nodes: TraceNode[] = []
  const edges: TraceEdge[] = []

  // The API schema supplies these containers, but keep the visualisation safe
  // when an older/partially-written record is returned by the backend.
  const findings = a.detection?.findings ?? []
  const enrichment = a.enrichment?.results ?? []
  const forensics = a.forensics ?? { relay_chain: [], candidate_ips: [] }

  /** attach severity + enrichment info computed from real detection/enrichment data */
  const attach = (
    node: TraceNode,
    matchValues: (string | null | undefined)[],
  ): TraceNode => {
    const { severity, rule_ids } = severityFor(matchValues, findings)
    return {
      ...node,
      severity,
      finding_ids: rule_ids,
      enrichment_statuses: enrForMany(matchValues),
    }
  }
  function enrForMany(matchValues: (string | null | undefined)[]): { provider: string; status: string; latency_ms: number }[] {
    const vals = matchValues.filter((v): v is string => !!v).map((v) => v.toLowerCase())
    if (vals.length === 0) return []
    const seen = new Set<string>()
    const out: { provider: string; status: string; latency_ms: number }[] = []
    for (const r of enrichment) {
      const key = `${r.provider}/${r.ioc?.ioc_kind ?? '?'}/${r.ioc?.ioc_value ?? '?'}`
      const v = String(r.ioc?.ioc_value ?? '').toLowerCase()
      if (vals.some((x) => v === x || v.includes(x)) && !seen.has(key)) {
        seen.add(key)
        out.push({ provider: r.provider, status: r.status, latency_ms: r.latency_ms })
      }
    }
    return out
  }

  // ── root: the message ──────────────────────────────────────────────────
  const senderDomain = a.from?.domain ?? null
  const messageId = a.message_id ?? '(no Message-ID)'
  nodes.push(attach(
    {
      id: 'message',
      kind: 'message',
      label: a.subject || '(no subject)',
      provenance: 'observed',
      evidence: [
        ev('Subject', a.subject),
        ev('From', a.from ? `${a.from.display_name} <${a.from.email}>` : null),
        ev('Message-ID', messageId),
        ev('SHA-256', a.sha256),
      ],
    },
    [senderDomain, a.from?.email],
  ))

  // ── relay chain (observed hops + inferred candidates) ─────────────────
  const chain = Array.isArray(forensics.relay_chain) ? forensics.relay_chain : []
  let prev = 'message'
  chain.forEach((hop, i) => {
    const id = `relay-${hop.index ?? i}`
    const ipCat = hop.from_ip_category ?? ''
    // A Received header is an observed message artifact even when it contains
    // a private/reserved IP. The address may not identify public infrastructure,
    // but it must not be relabelled as a heuristic relationship.
    const prov: Provenance = 'observed'
    nodes.push(attach({
      id,
      kind: 'relay_host',
      label: hop.from_host ?? hop.from_ip ?? `(hop ${hop.index ?? i + 1})`,
      provenance: prov,
      evidence: [
        ev('Hop index', String(hop.index ?? i + 1)),
        ev('from host', hop.from_host),
        ev('from IP', hop.from_ip),
        ev('IP category', ipCat),
        ev('received by', hop.by_host),
        ev('TLS', hop.tls ? 'yes' : 'no'),
        ev('timestamp', hop.timestamp),
        ev('confidence', hop.confidence ? `${hop.confidence}/100` : null),
        ...(Array.isArray(hop.confidence_reasons) && hop.confidence_reasons.length > 0
          ? hop.confidence_reasons.map((r, j) => ev(`confidence reason ${j + 1}`, r))
          : []),
        ...(Array.isArray(hop.notes) && hop.notes.length > 0 ? hop.notes.map((n, j) => ev(`note ${j + 1}`, n)) : []),
      ],
    }, [hop.from_host ?? hop.from_ip]))
    edges.push({
      id: `edge-${prev}-${id}`,
      source: prev,
      target: id,
      label: 'sent via',
      provenance: prov,
      evidence: [
        ev('Source', "Relay chain from the message's Received headers"),
        ev('Trusted hop', hop.trusted ? 'yes' : 'no'),
      ],
    })
    prev = id

    // candidate public IP attached to this relay hop
    if (hop.from_ip && hop.from_ip_category === 'public') {
      const ipId = `ip-${hop.from_ip}`
      if (!nodes.some((n) => n.id === ipId)) {
        nodes.push(attach({
          id: ipId,
          kind: 'ip',
          label: hop.from_ip,
          provenance: 'observed',
          evidence: [
            ev('IP address', hop.from_ip),
            ev('Source', 'Extracted from Received header of the analyzed message'),
          ],
        }, [hop.from_ip])) // a candidate IP is itself a finding match
        edges.push({
          id: `edge-${id}-${ipId}`,
          source: id,
          target: ipId,
          label: 'reported from',
          provenance: 'observed',
          evidence: [ev('Source', 'Received-chain from-address')],
        })
      }

      // enrichment: coordinates + IP intel on this specific observed IP
      const geoRec = findRecord(enrichment, 'ipgeo_http', 'ip', hop.from_ip)
      const coords = extractCoords(geoRec)
      if (coords) {
        const ipNode = nodes.find((n) => n.id === ipId)!
        ipNode.geo = coords
        ipNode.provenance = 'observed'
        ipNode.evidence.push(
          ev('Infrastructure location (provider-claimed)', JSON.stringify(coords.label) + ` via ${coords.provider}`),
        )
      }
      const ipEnr = findRecord(enrichment, 'dns', 'ip', hop.from_ip)
      if (ipEnr) {
        const ipNode = nodes.find((n) => n.id === ipId)!
        ipNode.evidence.push(
          ev(`DNS lookup status (${ipEnr.provider})`, `${ipEnr.status} · ${ipEnr.latency_ms} ms`),
        )
      }
    }
  })

  // candidate_ips from forensics (not necessarily tied to a parsed hop)
  for (const ip of (Array.isArray(forensics.candidate_ips) ? forensics.candidate_ips : [])) {
    const ipId = `ip-${ip}`
    if (nodes.some((n) => n.id === ipId)) continue
    nodes.push(attach({
      id: ipId,
      kind: 'ip',
      label: ip,
      provenance: 'inferred',
      evidence: [
        ev('IP address', ip),
        ev('Source', 'Listed in forensic candidate set (heuristic reconstruction from the Received chain)'),
      ],
    }, [ip]))
    edges.push({
      id: `edge-message-${ipId}-candidate`,
      source: 'message',
      target: ipId,
      label: 'candidate source',
      provenance: 'inferred',
      evidence: [ev('Source', 'Forensic candidate set reconstructed from the Received chain')],
    })
  }

  // verified originating IP (strongest evidence, if present)
  if (forensics.verified_originating_ip) {
    const ipId = `ip-${forensics.verified_originating_ip}`
    if (!nodes.some((n) => n.id === ipId)) {
      nodes.push(attach({
        id: ipId,
        kind: 'ip',
        label: forensics.verified_originating_ip,
        provenance: 'observed',
        evidence: [
          ev('IP address', forensics.verified_originating_ip),
          ev('Source', 'Independently verified (e.g. via SPF correlation)'),
        ],
      }, [forensics.verified_originating_ip]))
    }
    if (!edges.some((edge) => edge.target === ipId && edge.label === 'verified origin')) {
      edges.push({
        id: `edge-message-${ipId}-verified`,
        source: 'message',
        target: ipId,
        label: 'verified origin',
        provenance: 'observed',
        evidence: [ev('Source', 'Verified originating IP in the forensic analysis result')],
      })
    }
    const rec = findRecord(enrichment, 'ipgeo_http', 'ip', forensics.verified_originating_ip)
    const coords = extractCoords(rec)
    if (coords) {
      const ipNode = nodes.find((n) => n.id === ipId)!
      ipNode.geo = coords
      ipNode.evidence.push(
        ev('Infrastructure location (provider-claimed)', `${coords.label} via ${coords.provider}`),
      )
    }
  }

  // ── sender domain ─────────────────────────────────────────────────────
  if (senderDomain) {
    const domId = `domain-${senderDomain}`
    nodes.push(attach({
      id: domId,
      kind: 'domain',
      label: senderDomain,
      provenance: 'observed',
      evidence: [
        ev('Domain', senderDomain),
        ev('Source', 'From the From header of the analyzed message'),
      ],
    }, [senderDomain]))
    edges.push({
      id: `edge-message-${domId}`,
      source: 'message',
      target: domId,
      label: 'sent from',
      provenance: 'observed',
      evidence: [ev('Source', 'From header domain')],
    })

    // sender-domain enrichment
    const dnsRec = findRecord(enrichment, 'dns', 'domain', senderDomain)
    if (dnsRec) {
      const domNode = nodes.find((n) => n.id === domId)!
      domNode.evidence.push(
        ev(`DNS (${dnsRec.provider})`, `${dnsRec.status} · ${dnsRec.latency_ms} ms`),
      )
      const records = (dnsRec.evidence as { records?: Record<string, unknown> } | undefined)?.records
      if (records) {
        for (const [k, v] of Object.entries(records)) {
          domNode.evidence.push(ev(`DNS ${k}`, JSON.stringify(v)))
        }
      }
    }
    const rdapRec = findRecord(enrichment, 'rdap', 'domain', senderDomain)
    if (rdapRec) {
      const domNode = nodes.find((n) => n.id === domId)!
      domNode.evidence.push(
        ev(`RDAP (${rdapRec.provider})`, `${rdapRec.status} · ${rdapRec.latency_ms} ms`),
      )
      const creation = (rdapRec.evidence as { creation_date?: string } | undefined)?.creation_date
      if (creation) domNode.evidence.push(ev('RDAP registered', String(creation)))
      const registrar = (rdapRec.evidence as { registrar_present?: boolean } | undefined)?.registrar_present
      if (registrar != null) domNode.evidence.push(ev('RDAP registrar present', registrar ? 'yes' : 'no'))
    }
  }

  // ── URLs extracted from the body ─────────────────────────────────────
  const urls = Array.isArray(a.urls) ? a.urls : []
  const urlsByHost = new Map<string, typeof urls>()
  for (const u of urls) {
    const host = u.host.replace(/^www\./, '') || 'unknown host'
    const group = urlsByHost.get(host) ?? []
    group.push(u)
    urlsByHost.set(host, group)
  }
  for (const [hostDomain, hostUrls] of urlsByHost) {
    // Group only identical hosts. This keeps a busy HTML message readable
    // without hiding any extracted indicator: every original URL is retained
    // in the node evidence and the edge still represents observed body links.
    const urlId = `url-${encodeURIComponent(hostDomain)}`
    const urlCount = hostUrls.length
    if (nodes.some((n) => n.id === urlId)) continue
    nodes.push(attach({
      id: urlId,
      kind: 'url',
      label: urlCount === 1 ? hostUrls[0].url : `${hostDomain} (${urlCount} links)`,
      provenance: 'observed',
      evidence: [
        ev('Host', hostDomain),
        ev('Extracted URLs', String(urlCount)),
        ...hostUrls.flatMap((u, index) => [
          ev(`URL ${index + 1}`, u.url),
          ev(`URL ${index + 1} appears in`, [u.in_text && 'text part', u.in_html && 'HTML part'].filter(Boolean).join(' + ') || 'unknown'),
        ]),
        ev('Source', 'URL extraction from the message body'),
      ],
    }, hostUrls.flatMap((u) => [u.url, u.host])))
    edges.push({
      id: `edge-message-${urlId}`,
      source: 'message',
      target: urlId,
      label: 'links to',
      provenance: 'observed',
      evidence: [ev('Source', 'URL extraction from the message body')],
    })

    // link URL host to a domain node if one exists (sender domain or url-host domain)
    const domId = `domain-${hostDomain}`
    if (hostDomain && !nodes.some((n) => n.id === domId) && hostDomain === senderDomain) {
      // nothing extra — sender-domain link handled above
    } else if (hostDomain && nodes.some((n) => n.id === domId)) {
      edges.push({
        id: `edge-${urlId}-${domId}`,
        source: urlId,
        target: domId,
        label: 'hosted on',
        provenance: 'observed',
        evidence: [ev('Source', 'URL host is the same as a known domain indicator')],
      })
    } else if (hostDomain) {
      nodes.push(attach({
        id: domId,
        kind: 'domain',
        label: hostDomain,
        provenance: 'observed',
        evidence: [ev('Domain', hostDomain), ev('Source', 'Host part of an extracted URL')],
      }, [hostDomain]))
      edges.push({
        id: `edge-${urlId}-${domId}`,
        source: urlId,
        target: domId,
        label: 'hosted on',
        provenance: 'observed',
        evidence: [ev('Source', 'URL host is a separate domain not in the enrichment set' )],
      })
      const dnsRec = findRecord(enrichment, 'dns', 'domain', hostDomain)
      if (dnsRec) {
        const domNode = nodes.find((n) => n.id === domId)!
        domNode.evidence.push(ev(`DNS (${dnsRec.provider})`, `${dnsRec.status} · ${dnsRec.latency_ms} ms`))
      }
    }
  }

  const hasGeo = nodes.some((n) => n.geo != null)
  return { nodes, edges, hasGeo }
}
