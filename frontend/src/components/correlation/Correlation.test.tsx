// @vitest-environment jsdom
// P5c frontend: Related tab, campaign detail + graph model, case add/remove, search, role visibility.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'

vi.mock('cytoscape', () => {
  const fake = vi.fn(() => ({ on: vi.fn(), destroy: vi.fn() }))
  return { default: fake }
})

import cytoscape from 'cytoscape'
import RelatedPanel from './RelatedPanel'
import { CampaignDetailView, CampaignList } from './CampaignsPage'
import { buildCampaignElements } from './model'
import CasePage from '../cases/CasePage'
import SearchPage from '../search/SearchPage'
import App from '../../App'
import { AuthProvider } from '../../auth/AuthContext'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'
import type { CampaignDetail, Correlation } from '../../api/client'

const calls: { url: string; init: RequestInit }[] = []
let routes: [string, string | RegExp, (init: RequestInit) => Response][] = []
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const on = (m: string, p: string | RegExp, f: (init: RequestInit) => Response) => routes.unshift([m, p, f])

beforeEach(() => {
  calls.length = 0
  routes = []
  clearSession()
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    const m = (init.method ?? 'GET').toUpperCase()
    for (const [rm, rp, f] of routes) {
      const hit = typeof rp === 'string' ? url === rp || url.startsWith(`${rp}?`) : rp.test(url)
      if (rm === m && hit) return f(init)
    }
    return json(404, { error: { code: 'NOT_FOUND', message: 'not found' } })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
})

const DISC = 'Shared infrastructure does not identify a human.'
const brief = (id: string, subject = `Subject ${id}`) => ({
  id, created_at: '2026-11-02T08:10:00+00:00', subject, from_domain: 'outlook.com',
  detection_score: 60, detection_verdict: 'suspicious', sha256: 'f'.repeat(64),
})
const camp = { id: 'c1', label: 'Candidate campaign C-0001', status: 'candidate', confidence: 'medium',
  confidence_score: 0.82, member_count: 4, version: 3, merged_into: null, created_at: null, updated_at: null }

function corr(overrides: Partial<Correlation> = {}): Correlation {
  return {
    analysis_id: 'a1', status: 'ok', entities: [], related: [], related_total: 0,
    generic_only_overlaps: { count: 0, indicators: [] }, campaigns: [], rule: 'RULE TEXT', disclaimer: DISC,
    ...overrides,
  }
}

describe('Related tab', () => {
  it('lists linked analyses with shared indicators, link strength, reasons and campaign badge', async () => {
    on('GET', '/api/v1/analyses/a1/correlation', () => json(200, corr({
      campaigns: [camp],
      related: [{
        analysis: brief('a2', 'Updated remittance'), score: 0.82, qualifies: true, confidence: 'medium',
        explanation: 'shares 2 independent indicator types (public_ip, reply_to_domain)',
        independent_types: ['public_ip', 'reply_to_domain'], generic_overlaps: [],
        indicators: [
          { entity_id: 'e1', type: 'public_ip', value: '96.7.128.175', tier: 'medium', weight: 0.6,
            evidence: [{ analysis_id: 'a1', role: 'origin_candidate_ip', source_field: 'forensics.verified_originating_ip' }] },
          { entity_id: 'e2', type: 'reply_to_domain', value: 'vendor-remit-portal.test', tier: 'medium', weight: 0.5,
            evidence: [{ analysis_id: 'a2', role: 'reply_to_domain', source_field: 'reply_to[0]' }] },
        ],
      }],
      generic_only_overlaps: { count: 1, indicators: [{ type: 'sender_domain', value: 'outlook.com', reason: 'stop-listed', analyses: 1 }] },
    })))
    render(<RelatedPanel analysisId="a1" />)
    const row = await screen.findByTestId('related-row')
    expect(within(row).getByText('Updated remittance').getAttribute('href')).toBe('#analysis/a2')
    expect(row.textContent).toContain('96.7.128.175')
    expect(row.textContent).toContain('vendor-remit-portal.test')
    expect(row.textContent).toContain('link 0.82 · medium')
    expect(row.textContent).toContain('forensics.verified_originating_ip')
    expect(screen.getByTestId('campaign-badge').getAttribute('href')).toBe('#campaign/c1')
    expect(screen.getByTestId('corr-disclaimer').textContent).toBe(DISC)
    expect(screen.getByTestId('generic-only').textContent).toContain('outlook.com')
    expect(document.body.textContent).not.toMatch(/same attacker|same person/i)
  })

  it('shows a neutral empty state (not a claim of uniqueness)', async () => {
    on('GET', '/api/v1/analyses/a1/correlation', () => json(200, corr()))
    render(<RelatedPanel analysisId="a1" />)
    await screen.findByText('No related analyses found')
    expect(screen.getByText(/not a claim that the message is unique/)).toBeTruthy()
  })

  it('reports a correlation error without failing', async () => {
    on('GET', '/api/v1/analyses/a1/correlation', () => json(200, corr({ status: 'error' })))
    render(<RelatedPanel analysisId="a1" />)
    await screen.findByText(/analysis itself is unaffected/)
  })
})

const DETAIL: CampaignDetail = {
  ...camp,
  members: [brief('a1'), brief('a2')],
  reasons: {
    summary: ['2 analyses (2 distinct messages) share infrastructure through 1 qualifying link(s).'],
    shared_indicators: [{ entity_id: 'e1', type: 'public_ip', value: '96.7.128.175', tier: 'medium', weight: 0.6,
      analyses: ['a1', 'a2'], evidence: [{ analysis_id: 'a1', role: 'origin_candidate_ip', source_field: 'forensics.candidate_ips[0]' }] }],
    rule: 'RULE TEXT',
  },
  graph: {
    nodes: [{ id: 'a:a1', kind: 'analysis', label: 'S1', analysis_id: 'a1', score: 60, verdict: 'suspicious' },
            { id: 'a:a2', kind: 'analysis', label: 'S2', analysis_id: 'a2', score: 60, verdict: 'suspicious' },
            { id: 'e:e1', kind: 'public_ip', label: '96.7.128.175', tier: 'medium', weight: 0.6 }],
    edges: [{ id: 'x1', source: 'a:a1', target: 'e:e1', role: 'origin_candidate_ip', source_field: 'forensics.candidate_ips[0]', tier: 'medium' },
            { id: 'x2', source: 'a:a2', target: 'e:e1', role: 'origin_candidate_ip', source_field: 'forensics.candidate_ips[0]', tier: 'medium' }],
  },
  disclaimer: DISC,
}

describe('Campaigns', () => {
  it('graph model: typed nodes, role-labelled edges, evidence tooltips', () => {
    const els = buildCampaignElements(DETAIL)
    const ip = els.find((e) => e.data.id === 'e:e1')!
    expect(ip.classes).toContain('tier-medium')
    expect(String(ip.data.tooltip)).toContain('forensics.candidate_ips[0]')
    const edge = els.find((e) => e.data.id === 'x1')!
    expect(edge.data.label).toBe('origin candidate ip')
    expect(els.filter((e) => e.classes === 'analysis')).toHaveLength(2)
  })

  it('detail view renders graph, reasons, members and disclaimer', async () => {
    on('GET', '/api/v1/campaigns/c1', () => json(200, DETAIL))
    render(<CampaignDetailView id="c1" />)
    await screen.findByTestId('campaign-detail')
    expect(screen.getByTestId('campaign-graph')).toBeTruthy()
    expect(vi.mocked(cytoscape)).toHaveBeenCalled()
    expect(screen.getByText(/2 distinct messages/)).toBeTruthy()
    expect(screen.getByText('Subject a1')).toBeTruthy()
    expect(screen.getByTestId('corr-disclaimer').textContent).toBe(DISC)
    expect(document.body.textContent).toContain('forensics.candidate_ips[0]')
  })

  it('list shows confidence and member counts', async () => {
    on('GET', '/api/v1/campaigns', () => json(200, { items: [camp], disclaimer: DISC }))
    render(<CampaignList />)
    const row = await screen.findByTestId('campaign-row')
    expect(row.textContent).toContain('medium (0.82)')
    expect(row.textContent).toContain('4 analyses')
  })
})

function caseRoutes() {
  const state = { members: ['a1'] }
  on('GET', '/api/v1/investigations/k1', () => json(200, { id: 'k1', case_number: 'CASE-2026-0001', title: 'SYNTHETIC DEMO', status: 'open',
    created_at: '2026-11-01T00:00:00Z', evidence_policy: { store_mode: 'hash_only', key_required: false, retention_days: 90, note: '' }, analyses: [] }))
  on('GET', '/api/v1/investigations/k1/analyses', () => json(200, state.members.map((id) => ({ analysis: brief(id), campaigns: id === 'a1' ? [camp] : [] }))))
  on('GET', '/api/v1/investigations/k1/indicators', () => json(200, { case_id: 'k1', disclaimer: DISC, indicators: [
    { entity_id: 'e1', type: 'public_ip', value: '96.7.128.175', case_analyses: state.members, case_count: state.members.length, df: 4, tier: 'medium', weight: 0.6, generic_reason: null },
    { entity_id: 'e2', type: 'sender_domain', value: 'outlook.com', case_analyses: state.members, case_count: 1, df: 5, tier: 'weak', weight: 0, generic_reason: 'stop-listed generic provider/platform domain' }] }))
  on('GET', '/api/v1/analyses', () => json(200, [{ id: 'a1', subject: 'S1' }, { id: 'a2', subject: 'S2' }]))
  on('POST', '/api/v1/investigations/k1/analyses', (init) => {
    state.members.push(JSON.parse(String(init.body)).analysis_id)
    return json(201, {})
  })
  on('DELETE', /\/api\/v1\/investigations\/k1\/analyses\/a1$/, () => {
    state.members = state.members.filter((m) => m !== 'a1')
    return json(200, {})
  })
  return state
}

describe('Case page', () => {
  it('analyst adds and removes analyses; aggregated indicators flag generic values', async () => {
    setSession(sessionFor('analyst'))
    caseRoutes()
    render(withRole(<CasePage id="k1" />, 'analyst'))
    await screen.findByTestId('case-page')
    expect(screen.getAllByTestId('case-member')).toHaveLength(1)
    expect(screen.getAllByTestId('case-indicator')[1].textContent).toContain('generic: stop-listed')
    await waitFor(() => expect(screen.getByRole('option', { name: /a2/ })).toBeTruthy())
    expect(screen.queryByRole('option', { name: /^a1/ })).toBeNull()        // members are not offered again
    fireEvent.change(screen.getByLabelText('Add analysis'), { target: { value: 'a2' } })
    fireEvent.click(screen.getByText('Add to case'))
    await waitFor(() => expect(screen.getAllByTestId('case-member')).toHaveLength(2))
    const post = calls.find((c) => c.init.method === 'POST')!
    expect(JSON.parse(String(post.init.body))).toEqual({ analysis_id: 'a2' })
    expect(new Headers(post.init.headers).get('Authorization')).toBe('Bearer test-token-analyst')
    fireEvent.click(screen.getAllByText('Remove from case')[0])
    await waitFor(() => expect(screen.getAllByTestId('case-member')).toHaveLength(1))
    expect(calls.some((c) => c.init.method === 'DELETE')).toBe(true)
  })

  it('viewer sees the case read-only', async () => {
    setSession(sessionFor('viewer'))
    caseRoutes()
    render(withRole(<CasePage id="k1" />, 'viewer'))
    await screen.findByTestId('case-readonly')
    expect(screen.queryByText('Remove from case')).toBeNull()
    expect(screen.queryByText('Add to case')).toBeNull()
  })
})

describe('Search page', () => {
  it('sends filters, renders results without bodies and paginates', async () => {
    on('GET', /\/api\/v1\/search\?/, (init) => {
      void init
      const offset = Number(new URL(`http://x${calls[calls.length - 1].url}`).searchParams.get('offset') ?? 0)
      return json(200, { query: 'vendor', type: 'all', limit: 20, offset, results: {
        analysis: { total: 25, items: [brief(`a${offset}`, `Hit ${offset}`)] },
        entity: { total: 1, items: [{ id: 'e2', type: 'reply_to_domain', value: 'vendor-remit-portal.test', analyses: 4 }] },
        case: { total: 0, items: [] }, campaign: { total: 0, items: [] } } })
    })
    render(<SearchPage />)
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'vendor' } })
    fireEvent.change(screen.getByDisplayValue('any'), { target: { value: 'suspicious' } })
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await screen.findByText('Hit 0')
    const url = new URL(`http://x${calls[0].url}`)
    expect(url.searchParams.get('q')).toBe('vendor')
    expect(url.searchParams.get('verdict')).toBe('suspicious')
    expect(screen.getByTestId('search-entities').textContent).toContain('seen in 4 analyses')
    expect(screen.getByText('Hit 0').getAttribute('href')).toBe('#analysis/a0')
    fireEvent.click(screen.getByText('Next'))
    await screen.findByText('Hit 20')
  })
})

describe('role-aware navigation (P5c)', () => {
  it('viewer gets Campaigns and Search but not Analyse or Users', async () => {
    setSession(sessionFor('viewer'))
    on('GET', '/api/v1/auth/me', () => json(200, { ...sessionFor('viewer').user }))
    on('GET', '/api/v1/analyses', () => json(200, []))
    render(<AuthProvider><App /></AuthProvider>)
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).getByText('Campaigns')).toBeTruthy()
    expect(within(nav).getByText('Search')).toBeTruthy()
    expect(within(nav).queryByText('Analyse')).toBeNull()
    expect(within(nav).queryByText('Users')).toBeNull()
  })
})
