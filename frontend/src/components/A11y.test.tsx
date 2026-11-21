// @vitest-environment jsdom
// P5u-2: automated accessibility check (axe-core) of the main pages, rendered with realistic data.
// jsdom has no layout engine, so `color-contrast` is checked separately (computed token ratios in
// docs/frontend/design-system.md); every other axe rule runs.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import axe from 'axe-core'

vi.mock('cytoscape', () => ({ default: vi.fn(() => ({ on: vi.fn(), destroy: vi.fn(), zoom: vi.fn(), fit: vi.fn() })) }))

import UploadPage from './UploadPage'
import HistoryPage from './HistoryPage'
import { CampaignDetailView, CampaignList } from './correlation/CampaignsPage'
import SearchPage from './search/SearchPage'
import AdminUsersPage from './admin/AdminUsersPage'
import LoginPage from './auth/LoginPage'
import ChangePasswordPage from './auth/ChangePasswordPage'
import OverviewPage from './overview/OverviewPage'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { clearSession, setSession } from '../auth/session'
import { sessionFor, withRole } from '../test/auth'

let routes: [string | RegExp, () => Response][] = []
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const on = (p: string | RegExp, f: () => Response) => routes.unshift([p, f])

const A = (id: string, score: number, verdict: string) => ({
  id, created_at: '2026-11-20T10:00:00Z', sha256: 'c'.repeat(64), size_bytes: 4096, subject: `Subject ${id}`,
  sender: { display_name: 'X', email: `x@${id}.test`, domain: `${id}.test` }, received_count: 3, url_count: 2,
  attachment_count: 0, detection_score: score, detection_verdict: verdict, has_defects: false,
})
const brief = { id: 'a1', created_at: null, subject: 'Subject a1', from_domain: 'x.test', detection_score: 80,
  detection_verdict: 'suspicious', sha256: 'b'.repeat(64) }
const camp = { id: 'c1', label: 'Candidate campaign C-0001', status: 'candidate', confidence: 'medium',
  confidence_score: 0.82, member_count: 3, version: 1, merged_into: null, created_at: null, updated_at: null }

beforeEach(() => {
  routes = []
  clearSession()
  on('/api/v1/analyses', () => json(200, [A('a1', 95, 'phishing_fraud_likely'), A('a2', 40, 'suspicious')]))
  on('/api/v1/investigations', () => json(200, []))
  on('/api/v1/campaigns', () => json(200, { items: [camp], disclaimer: 'Shared infrastructure does not identify a person.' }))
  on(/\/api\/v1\/campaigns\/c1$/, () => json(200, {
    ...camp, disclaimer: 'D', members: [brief], graph: { nodes: [], edges: [] },
    reasons: { summary: ['3 distinct messages'], rule: 'R', shared_indicators: [{ entity_id: 'e1', type: 'public_ip', value: '203.0.113.7',
      tier: 'strong', weight: 1, damped: false, evidence: [{ analysis_id: 'a1', source_field: 'forensics.candidate_ips[0]' }], analyses: ['a1'] }] },
  }))
  on('/api/v1/admin/users', () => json(200, [
    { id: 'u1', username: 'root', role: 'admin', is_active: true, locked: false, must_change_password: false, last_login_at: null, created_at: null },
    { id: 'u2', username: 'bob', role: 'viewer', is_active: false, locked: false, must_change_password: true, last_login_at: null, created_at: null },
  ]))
  on(/\/api\/v1\/search\?/, () => json(200, { query: 'x', type: 'all', limit: 20, offset: 0, results: {
    analysis: { total: 1, items: [brief] }, entity: { total: 1, items: [{ id: 'e1', type: 'public_ip', value: '203.0.113.7', analyses: 2 }] },
    case: { total: 0, items: [] }, campaign: { total: 1, items: [camp] } } }))
  on('/api/v1/health', () => json(200, { status: 'ok' }))
  on('/api/v1/ml/status', () => json(200, { status: 'ok', model_version: 'm1' }))
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    for (const [p, f] of routes) if (typeof p === 'string' ? url === p || url.startsWith(`${p}?`) : p.test(url)) return f()
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
  window.location.hash = ''
})

async function violations(root: Element, page = false) {
  const res = await axe.run(root, {
    rules: { 'color-contrast': { enabled: false }, region: { enabled: page } },
    resultTypes: ['violations'],
  })
  return res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)
}

describe('axe: main pages have no violations', () => {
  it('login and change password', async () => {
    const { container, unmount } = render(<LoginPage notice="Your session expired. Sign in again." />)
    expect(await violations(container)).toEqual([])
    unmount()
    setSession(sessionFor('analyst'))
    const r = render(withRole(<ChangePasswordPage required={false} />, 'analyst'))
    expect(await violations(r.container)).toEqual([])
  })

  it('overview', async () => {
    setSession(sessionFor('analyst'))
    const { container } = render(withRole(<OverviewPage onOpenAnalysis={() => {}} />, 'analyst'))
    await screen.findByText('Subject a1')
    expect(await violations(container)).toEqual([])
  })

  it('upload with recent analyses', async () => {
    const { container } = render(withRole(<UploadPage onAnalyzed={() => {}} />, 'analyst'))
    await screen.findByRole('table', { name: 'Recent analyses' })
    expect(await violations(container)).toEqual([])
  })

  it('history', async () => {
    const { container } = render(withRole(<HistoryPage onOpenAnalysis={() => {}} />, 'viewer'))
    await screen.findByText('Subject a1')
    expect(await violations(container)).toEqual([])
  })

  it('campaign list and detail', async () => {
    const a = render(withRole(<CampaignList />, 'viewer'))
    await screen.findByTestId('campaign-row')
    expect(await violations(a.container)).toEqual([])
    a.unmount()
    const b = render(withRole(<CampaignDetailView id="c1" />, 'viewer'))
    await screen.findByTestId('campaign-detail')
    expect(await violations(b.container)).toEqual([])
  })

  it('search with results', async () => {
    const { container } = render(withRole(<SearchPage />, 'viewer'))
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await screen.findByText('203.0.113.7')
    expect(await violations(container)).toEqual([])
  })

  it('admin users', async () => {
    const { container } = render(withRole(<AdminUsersPage />, 'admin', { id: 'u1' }))
    await screen.findByTestId('user-row-bob')
    expect(await violations(container)).toEqual([])
  })

  it('full shell (nav, status bar, landmarks) and the 404 notice', async () => {
    setSession(sessionFor('admin'))
    on('/api/v1/auth/me', () => json(200, { ...sessionFor('admin').user }))
    window.location.hash = '#nowhere'
    const { container } = render(<AuthProvider><App /></AuthProvider>)
    await screen.findByRole('region', { name: 'Page not found' })
    expect(await violations(container, true)).toEqual([])
  })
})
