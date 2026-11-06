/**
 * Focused graph-transformation tests for the forensic trace view.
 *
 * Verifies the graph is genuinely data-driven:
 *  - two different API responses produce their own distinct graphs
 *  - switching analyses leaves NO stale nodes or edges
 *  - severity / finding linkage comes from actual detection findings
 *  - private IPs never become "observed" nodes; missing data handled gracefully
 *
 * No synthetic graph data lives here — fixtures mirror the real API schema and
 * carry only plausible values (RFC 5737 / RFC 2606 reserved ranges).
 */
import { describe, it, expect } from 'vitest'
import { buildTraceGraph, severityFor } from './model'
import type { AnalysisDetail } from '../../api/client'

function baseAnalysis(over: Partial<AnalysisDetail> = {}): AnalysisDetail {
  return {
    id: 'aaa',
    created_at: '2026-10-11T00:00:00Z',
    sha256: 'a'.repeat(64),
    size_bytes: 100,
    subject: null,
    from: null,
    to: [],
    cc: [],
    reply_to: [],
    return_path: null,
    date: null,
    message_id: null,
    received_count: 0,
    authentication_results: [],
    dkim_signature_count: 0,
    has_html_body: false,
    body_text: null,
    urls: [],
    attachments: [],
    header_counts: {},
    detection: { score: 0, verdict: '', findings: [], unknowns: [], observed_facts: [] },
    forensics: {
      relay_chain: [],
      trusted_boundary_index: null,
      candidate_ips: [],
      earliest_candidate_ip: null,
      verified_originating_ip: null,
      inconsistencies: [],
      confidence_rules: [],
      forgery_note: '',
      disclaimer: '',
    },
    authentication: {
      spf: { protocol: 'spf', status: 'unknown' },
      dkim: { protocol: 'dkim', status: 'unknown' },
      dmarc: { protocol: 'dmarc', status: 'unknown' },
      alignment: {},
      status_legend: {},
    } as AnalysisDetail['authentication'],
    enrichment: { results: [], degraded: [] },
    parse_defects: [],
    ...over,
  } as AnalysisDetail
}

describe('empty / degraded inputs', () => {
  it('produces a message-only graph with no edges when everything is empty', () => {
    const g = buildTraceGraph(baseAnalysis())
    expect(g.nodes.map((n) => n.id)).toEqual(['message'])
    expect(g.edges).toEqual([])
    expect(g.hasGeo).toBe(false)
  })

  it('falls back to the message node for a partially written analysis record', () => {
    const partial = baseAnalysis({
      urls: null as unknown as AnalysisDetail['urls'],
      forensics: undefined as unknown as AnalysisDetail['forensics'],
      detection: undefined as unknown as AnalysisDetail['detection'],
      enrichment: undefined as unknown as AnalysisDetail['enrichment'],
    })
    expect(() => buildTraceGraph(partial)).not.toThrow()
    expect(buildTraceGraph(partial).nodes.map((node) => node.id)).toEqual(['message'])
  })
})

describe('two different analyses produce their own graphs', () => {
  it('phishing fixture shape: relay + lookalike findings + url node', () => {
    const a = baseAnalysis({
      subject: 'A quick note',
      from: { display_name: 'Someone', email: 'a@corp.example', domain: 'corp.example' },
      urls: [{ url: 'https://example.website/one', host: 'example.website', scheme: 'https', in_html: false, in_text: true }],
    })
    const g = buildTraceGraph(a)
    const ids = g.nodes.map((n) => n.id)
    expect(ids).toContain('message')
    expect(ids).toContain('domain-corp.example')
    // URL host domain is distinct from sender domain → its own domain node
    expect(ids).toContain('url-example.website')
    // edge count > 0 (message → domain, message → url, url → domain)
    expect(g.edges.length).toBeGreaterThanOrEqual(2)
  })

  it('BEC fixture shape: reply-to mismatch reflected only in data, no invented nodes', () => {
    const a = baseAnalysis({
      subject: 'BEC attempt example, one URL',
      from: { display_name: 'PayPal Security Team', email: 'alerts@paypa1-secure.com', domain: 'paypa1-secure.com' },
      urls: [{ url: 'https://paypa1-secure.com/verify', host: 'paypa1-secure.com', scheme: 'https', in_html: true, in_text: false }],
    })
    const g = buildTraceGraph(a)
    const ids = g.nodes.map((n) => n.id)
    expect(ids).toContain('domain-paypa1-secure.com')
    // sender domain and URL host identical → no separate domain node created
    expect(ids.filter((i) => i.startsWith('domain-')).length).toBe(1)
  })

  it('identifies missing relay/private IP: not fabricated as observed', () => {
    const a = baseAnalysis({
      forensics: {
        relay_chain: [
          {
            index: 1,
            from_host: 'internal-relay.corp.local',
            from_ip: '10.0.0.5',
            from_ip_category: 'private',
            by_host: 'mx.corp.example',
            protocol: 'smtp',
            tls: true,
            timestamp: '2026-10-11T00:00:00Z',
            trusted: false,
            confidence: 40,
            confidence_reasons: ['from a private range'],
            notes: ['private relay cannot be observed publicly'],
          },
        ],
        trusted_boundary_index: 1,
        candidate_ips: ['10.0.0.5'],
        earliest_candidate_ip: null,
        verified_originating_ip: null,
        inconsistencies: [],
        confidence_rules: [],
        forgery_note: '',
        disclaimer: 'private IP caveat',
      },
    })
    const g = buildTraceGraph(a)
    const hopNode = g.nodes.find((n) => n.kind === 'relay_host')
    expect(hopNode).toBeDefined()
    expect(hopNode!.provenance).toBe('observed') // the private value was present in a Received header
    // The candidate IP relationship is inferred, but the private header remains visible.
    const ipNodes = g.nodes.filter((n) => n.kind === 'ip')
    expect(ipNodes).toHaveLength(1)
    expect(ipNodes.every((n) => n.provenance === 'inferred')).toBe(true)
    expect(g.edges.some((edge) => edge.label === 'candidate source' && edge.provenance === 'inferred')).toBe(true)
  })

  it('finding severity propagates to nodes referencing it (real evidence), and NOT where unrelated', () => {
    const a = baseAnalysis({
      subject: 'inclusive fixture check',
      from: { display_name: 'PayPal Security Team', email: 'alerts@paypa1-secure.com', domain: 'paypa1-secure.com' },
      urls: [{ url: 'https://paypa1-secure.com/verify', host: 'paypa1-secure.com', scheme: 'https', in_html: false, in_text: true }],
      detection: {
        score: 70,
        verdict: 'phish',
        findings: [
          {
            rule_id: 'lookalike_domain',
            severity: 'high',
            weight: 35,
            contribution: 35,
            knowledge: 'heuristic',
            title: 'Lookalike sender domain',
            evidence: "display name claims brand 'paypal' but mail comes from 'paypa1-secure.com'",
            rationale: 'x',
          },
          {
            rule_id: 'unrelated_rule',
            severity: 'medium',
            weight: 10,
            contribution: 10,
            knowledge: 'heuristic',
            title: 'Unrelated finding',
            evidence: 'something-about-another-thing',
            rationale: 'x',
          },
        ],
        unknowns: [],
        observed_facts: [],
      },
    })
    const g = buildTraceGraph(a)
    const senderNode = g.nodes.find((n) => n.id === 'domain-paypa1-secure.com')!
    expect(senderNode.finding_ids).toContain('lookalike_domain')
    expect(senderNode.finding_ids).not.toContain('unrelated_rule')
    expect(senderNode.severity).toBe('high')

    const messageNode = g.nodes.find((n) => n.id === 'message')!
    // sender-domain finding does mention the sender → attached to message too
    expect(messageNode.finding_ids).toContain('lookalike_domain')
  })
})

describe('relationship evidence', () => {
  it('connects a verified originating IP with the backend-provided relationship', () => {
    const g = buildTraceGraph(baseAnalysis({
      forensics: {
        ...baseAnalysis().forensics,
        verified_originating_ip: '203.0.113.9',
      },
    }))
    expect(g.nodes.map((node) => node.id)).toContain('ip-203.0.113.9')
    expect(g.edges).toContainEqual(expect.objectContaining({
      source: 'message', target: 'ip-203.0.113.9', label: 'verified origin', provenance: 'observed',
    }))
  })

  it('groups same-host URLs while retaining every extracted URL as evidence', () => {
    const g = buildTraceGraph(baseAnalysis({
      urls: [
        { url: 'https://example.test/a', host: 'example.test', scheme: 'https', in_html: false, in_text: true },
        { url: 'https://example.test/b', host: 'example.test', scheme: 'https', in_html: true, in_text: false },
      ],
    }))
    const urlNodes = g.nodes.filter((node) => node.kind === 'url')
    expect(urlNodes).toHaveLength(1)
    expect(urlNodes[0].evidence.map((item) => item.value)).toEqual(expect.arrayContaining([
      'https://example.test/a',
      'https://example.test/b',
    ]))
  })
})

describe('switching investigations: no stale nodes/edges', () => {
  it('rebuilding for a second analysis yields only its own nodes (all-clean state)', () => {
    const a1 = baseAnalysis({
      from: { display_name: 'X', email: 'x@one.example', domain: 'one.example' },
      urls: [{ url: 'https://one.example/link', host: 'one.example', scheme: 'https', in_html: false, in_text: true }],
    })
    const a2 = baseAnalysis({
      from: { display_name: 'Y', email: 'y@two.example', domain: 'two.example' },
      urls: [{ url: 'https://two.example/path', host: 'two.example', scheme: 'https', in_html: false, in_text: true }],
    })
    const g1 = buildTraceGraph(a1)
    const g2 = buildTraceGraph(a2)
    // only the shared root id may repeat; every domain/ip/url node is per-analysis
    const g1_entity_ids = g1.nodes.filter((n) => n.kind !== 'message').map((n) => n.id)
    const g2_ids = g2.nodes.map((n) => n.id)
    for (const id of g1_entity_ids) expect(g2_ids).not.toContain(id)
    // node/edge IDs are rebuild-scoped (no 'one.example' in graph 2)
    expect(g2.nodes.map((n) => n.id).join(',')).not.toContain('one.example')
    expect(g2.edges.map((n) => n.id).join(',')).not.toContain('one.example')
  })
})

describe('severityFor helper', () => {
  const findings = [
    { rule_id: 'r1', severity: 'high', evidence: 'domain bad.example seen', title: 'T' },
    { rule_id: 'r2', severity: 'low', evidence: 'unrelated', title: 'T' },
  ]
  it('returns null for entities with no references', () => {
    expect(severityFor(['nothing.here'], findings).severity).toBeNull()
  })
  it('takes the highest severity among matching findings', () => {
    const r = severityFor(['bad.example'], findings)
    expect(r.severity).toBe('high')
    expect(r.rule_ids).toEqual(['r1'])
  })
})
