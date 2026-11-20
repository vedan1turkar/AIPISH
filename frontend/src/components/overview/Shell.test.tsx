// @vitest-environment jsdom
// P5u-1: status bar (role-based cells, failure tolerance), Overview page, login layout.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import StatusBar from '../shell/StatusBar'
import OverviewPage, { ML_SAMPLE } from './OverviewPage'
import LoginPage from '../auth/LoginPage'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'

const calls: string[] = []
let routes: Record<string, () => Response> = {}
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  calls.length = 0
  routes = {
    '/api/v1/health': () => json(200, { status: 'ok', version: '0.1.0', env: 'test', db_connected: true }),
    '/api/v1/ml/status': () => json(200, { status: 'ok', model_version: 'm1' }),
    '/api/v1/llm/status': () => json(200, { status: 'ok', model: 'mistral:latest' }),
    '/api/v1/intel/status': () => json(200, { offline: true, simulated: false, providers: {} }),
  }
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    calls.push(url)
    const path = url.split('?')[0]
    if (routes[path]) return routes[path]()
    if (/\/api\/v1\/analyses\/[^/]+\/assessment$/.test(path)) return json(404, { error: { code: 'NOT_FOUND', message: 'none' } })
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
})

describe('status bar', () => {
  it('viewer: API + ML cells only; LLM/intel endpoints are never called', async () => {
    setSession(sessionFor('viewer'))
    render(withRole(<StatusBar />, 'viewer'))
    await screen.findByTestId('status-ml')
    expect(screen.getByTestId('status-api').textContent).toContain('ok')
    expect(screen.queryByTestId('status-llm')).toBeNull()
    expect(screen.queryByTestId('status-intel')).toBeNull()
    expect(calls.some((c) => c.includes('/llm/status') || c.includes('/intel/status'))).toBe(false)
    expect(screen.getByTestId('status-user').textContent).toBe('demo-viewer@viewer')
    expect(screen.getByTestId('status-version').textContent).toContain('api 0.1.0')
    expect(screen.getByTestId('status-time').textContent).toMatch(/\d/)
  })

  it('admin: LLM and intel mode cells', async () => {
    setSession(sessionFor('admin'))
    render(withRole(<StatusBar />, 'admin'))
    expect((await screen.findByTestId('status-llm')).textContent).toContain('mistral:latest')
    expect(screen.getByTestId('status-intel').textContent).toContain('offline')
  })

  it('tolerates failures: unreachable API and failing status endpoints show as text, no crash', async () => {
    setSession(sessionFor('admin'))
    routes['/api/v1/health'] = () => { throw new TypeError('network down') }
    routes['/api/v1/ml/status'] = () => json(500, { error: { code: 'X', message: 'boom' } })
    routes['/api/v1/llm/status'] = () => json(503, { error: { code: 'X', message: 'boom' } })
    render(withRole(<StatusBar />, 'admin'))
    expect((await screen.findByTestId('status-api')).textContent).toContain('unreachable')
    expect(screen.getByTestId('status-ml').textContent).toContain('status unavailable')
    expect(screen.getByTestId('status-llm').textContent).toContain('status unavailable')
  })
})

const A = (id: string, verdict: string, score: number) => ({
  id, created_at: '2026-11-20T10:00:00Z', sha256: 'f'.repeat(64), size_bytes: 1, subject: `Subject ${id}`,
  sender: { display_name: '', email: 'x@d.test', domain: `${id}.test` }, received_count: 1, url_count: 0,
  attachment_count: 0, detection_score: score, detection_verdict: verdict, has_defects: false,
})

describe('overview page', () => {
  it('shows real counts, recent analyses, campaigns and quick actions for analysts', async () => {
    setSession(sessionFor('analyst'))
    const list = [A('a1', 'phishing_fraud_likely', 95), A('a2', 'suspicious', 45), A('a3', 'minimal', 0),
                  ...Array.from({ length: 30 }, (_, i) => A(`b${i}`, 'minimal', 0))]
    routes['/api/v1/analyses'] = () => json(200, list)
    routes['/api/v1/campaigns'] = () => json(200, { items: [{ id: 'c1', label: 'Candidate campaign C-0001', status: 'candidate',
      confidence: 'medium', confidence_score: 0.82, member_count: 4, version: 1, merged_into: null, created_at: null, updated_at: null }], disclaimer: 'd' })
    routes['/api/v1/investigations'] = () => json(200, [{ id: 'k1', status: 'open' }, { id: 'k2', status: 'closed' }])
    render(withRole(<OverviewPage onOpenAnalysis={() => {}} />, 'analyst'))
    await screen.findByText('Subject a1')
    const stats = screen.getAllByTestId('stat-cell').map((c) => c.textContent)
    expect(stats[0]).toContain('33')
    expect(stats.find((t) => t?.startsWith('Phishing'))).toContain('1')
    expect(stats.find((t) => t?.startsWith('Open cases'))).toContain('1')
    expect(stats.find((t) => t?.startsWith('Candidate campaigns'))).toContain('1')
    const recent = screen.getByRole('table', { name: 'Recent analyses' })
    expect(within(recent).getAllByRole('row')).toHaveLength(11)          // header + 10 (limited)
    expect(screen.getByText('C-0001').getAttribute('href')).toBe('#campaign/c1')
    expect(screen.getByRole('group', { name: 'Quick actions' }).textContent).toContain('New analysis')
    await waitFor(() => expect(calls.filter((c) => c.endsWith('/assessment')).length).toBe(ML_SAMPLE))   // bounded
    expect(screen.getAllByTestId('bar-row').length).toBeGreaterThan(2)
  })

  it('empty states are one line each, and viewers get no New analysis', async () => {
    setSession(sessionFor('viewer'))
    routes['/api/v1/analyses'] = () => json(200, [])
    routes['/api/v1/campaigns'] = () => json(200, { items: [], disclaimer: 'd' })
    routes['/api/v1/investigations'] = () => json(200, [])
    render(withRole(<OverviewPage onOpenAnalysis={() => {}} />, 'viewer'))
    await screen.findByText('No analyses yet. Upload an .eml from Analyse to start.')
    expect(screen.getByText(/No candidate campaigns/)).toBeTruthy()
    expect(screen.getByText('No analyses stored yet.')).toBeTruthy()
    for (const e of screen.getAllByTestId('empty-line')) expect(e.tagName).toBe('P')
    expect(screen.getByRole('group', { name: 'Quick actions' }).textContent).not.toContain('New analysis')
    expect(screen.getByText('Configuration status is visible to administrators only.')).toBeTruthy()
  })

  it('failed loads show a one-line reason instead of breaking the page', async () => {
    setSession(sessionFor('analyst'))
    routes['/api/v1/analyses'] = () => json(500, { error: { code: 'X', message: 'db offline' } })
    routes['/api/v1/campaigns'] = () => json(500, { error: { code: 'X', message: 'x' } })
    render(withRole(<OverviewPage onOpenAnalysis={() => {}} />, 'analyst'))
    await screen.findByText(/Analyses could not be loaded: db offline/)
    await screen.findByText('Campaigns could not be loaded.')
  })
})

describe('login layout', () => {
  it('compact panel: product strip, labelled fields, environment footer, notice', () => {
    render(<LoginPage notice="Your session expired. Sign in again." />)
    const form = screen.getByRole('form', { name: 'Sign in' })
    expect(within(form).getByText('AIPISH')).toBeTruthy()
    expect(within(form).getByText('Email threat forensics')).toBeTruthy()
    expect(screen.getByLabelText('Username')).toBeTruthy()
    expect(screen.getByLabelText('Password')).toBeTruthy()
    expect(screen.getByRole('status').textContent).toContain('Your session expired')
    expect(form.textContent).toContain('Local accounts only')
    expect(form.className).toContain('max-w-[400px]')
  })
})
