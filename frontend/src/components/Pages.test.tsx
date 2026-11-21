// @vitest-environment jsdom
// P5u-2: key states of the restyled pages — loading, empty, error and role visibility.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'

vi.mock('cytoscape', () => ({ default: vi.fn(() => ({ on: vi.fn(), destroy: vi.fn(), zoom: vi.fn(), fit: vi.fn() })) }))

import UploadPage from './UploadPage'
import HistoryPage from './HistoryPage'
import CasePage from './cases/CasePage'
import { CampaignDetailView, CampaignList } from './correlation/CampaignsPage'
import SearchPage from './search/SearchPage'
import AdminUsersPage from './admin/AdminUsersPage'
import App from '../App'
import { AuthProvider } from '../auth/AuthContext'
import { clearSession, setSession } from '../auth/session'
import { sessionFor, withRole } from '../test/auth'

type Handler = () => Response | Promise<Response>
let routes: [string, string | RegExp, Handler][] = []
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const on = (m: string, p: string | RegExp, f: Handler) => routes.unshift([m, p, f])
const never = () => new Promise<Response>(() => {})
const fail = (msg = 'db offline') => () => json(500, { error: { code: 'INTERNAL', message: msg } })

beforeEach(() => {
  routes = []
  clearSession()
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    const m = (init.method ?? 'GET').toUpperCase()
    for (const [rm, rp, f] of routes) {
      const hit = typeof rp === 'string' ? url === rp || url.startsWith(`${rp}?`) : rp.test(url)
      if (rm === m && hit) return f()
    }
    return json(404, { error: { code: 'NOT_FOUND', message: 'not found' } })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
  window.location.hash = ''
})

const summary = (id: string, score: number, verdict: string) => ({
  id, created_at: `2026-11-${10 + score % 10}T10:00:00Z`, sha256: 'a'.repeat(64), size_bytes: 2048, subject: `Subject ${id}`,
  sender: { display_name: '', email: `x@${id}.test`, domain: `${id}.test` }, received_count: 2, url_count: 1,
  attachment_count: 0, detection_score: score, detection_verdict: verdict, has_defects: false,
})

describe('Upload page', () => {
  it('square drop zone, verbatim option texts, and recent analyses beside it', async () => {
    on('GET', '/api/v1/analyses', () => json(200, [summary('a1', 95, 'phishing_fraud_likely'), summary('a2', 10, 'minimal')]))
    render(withRole(<UploadPage onAnalyzed={() => {}} />, 'analyst'))
    expect(screen.getByText('Drop an .eml here or click to choose')).toBeTruthy()
    expect(screen.getByText(/I consent to external threat-intel lookups for this analysis/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Analyse email' }) as HTMLButtonElement).disabled).toBe(true)
    const recent = await screen.findByRole('table', { name: 'Recent analyses' })
    expect(within(recent).getAllByRole('row')).toHaveLength(3)
    expect(within(recent).getByText('Subject a1').getAttribute('href')).toBe('#analysis/a1')
  })

  it('rejects a non-.eml file with a one-line reason', () => {
    on('GET', '/api/v1/analyses', never)
    const { container } = render(withRole(<UploadPage onAnalyzed={() => {}} />, 'analyst'))
    const input = container.querySelector('input[type=file]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['x'], 'note.txt', { type: 'text/plain' })] } })
    expect(screen.getByRole('alert').textContent).toContain('Only .eml email files can be analysed')
  })

  it('recent list: loading skeleton, empty line, failure line', async () => {
    on('GET', '/api/v1/analyses', never)
    const { unmount } = render(withRole(<UploadPage onAnalyzed={() => {}} />, 'analyst'))
    expect(within(screen.getByRole('region', { name: 'Recent analyses' })).getByRole('status', { name: 'Loading recent analyses…' })).toBeTruthy()
    unmount()
    on('GET', '/api/v1/analyses', () => json(200, []))
    const r2 = render(withRole(<UploadPage onAnalyzed={() => {}} />, 'analyst'))
    await screen.findByText('No analyses yet — the first upload will appear here.')
    r2.unmount()
    on('GET', '/api/v1/analyses', fail())
    render(withRole(<UploadPage onAnalyzed={() => {}} />, 'analyst'))
    await screen.findByText('Recent analyses could not be loaded.')
  })
})

describe('History page', () => {
  it('analyses table: sortable score header, mono hash, opens an analysis', async () => {
    on('GET', '/api/v1/analyses', () => json(200, [summary('a1', 20, 'minimal'), summary('a2', 90, 'phishing_fraud_likely')]))
    on('GET', /\/api\/v1\/analyses\/a2$/, () => json(200, { id: 'a2' }))
    const onOpen = vi.fn()
    render(withRole(<HistoryPage onOpenAnalysis={onOpen} />, 'viewer'))
    const table = await screen.findByRole('table')
    const score = within(table).getByRole('columnheader', { name: 'Score' })
    fireEvent.click(score.querySelector('button')!)
    fireEvent.click(score.querySelector('button')!)
    expect(score.getAttribute('aria-sort')).toBe('descending')
    expect(within(table).getAllByRole('row')[1].textContent).toContain('Subject a2')
    expect(within(table).getAllByRole('button', { name: /^Copy a{64}$/ })).toHaveLength(2)
    fireEvent.click(within(table).getByText('Subject a2'))
    await waitFor(() => expect(onOpen).toHaveBeenCalledWith('a2'))
  })

  it('empty and error states for both tabs', async () => {
    on('GET', '/api/v1/analyses', () => json(200, []))
    on('GET', '/api/v1/investigations', fail('cases table locked'))
    render(withRole(<HistoryPage onOpenAnalysis={() => {}} />, 'viewer'))
    await screen.findByText(/No analyses yet\. Upload an \.eml file/)
    fireEvent.click(screen.getByRole('tab', { name: 'Investigation cases' }))
    expect((await screen.findByRole('alert')).textContent).toContain('cases table locked')
  })
})

describe('Case page', () => {
  it('loading, then a one-line error when the case cannot be loaded', async () => {
    on('GET', /\/api\/v1\/investigations\/k1/, fail('case store offline'))
    render(withRole(<CasePage id="k1" />, 'analyst'))
    expect(screen.getByText('Loading case…')).toBeTruthy()
    expect((await screen.findByRole('alert')).textContent).toContain('case store offline')
  })
})

const camp = { id: 'c1', label: 'Candidate campaign C-0001', status: 'candidate', confidence: 'high',
  confidence_score: 0.91, member_count: 3, version: 2, merged_into: null, created_at: null, updated_at: '2026-11-19T09:00:00Z' }

describe('Campaigns', () => {
  it('list: loading skeleton, then a sortable table with confidence text', async () => {
    let release!: (r: Response) => void
    on('GET', '/api/v1/campaigns', () => new Promise<Response>((res) => { release = res }))
    render(withRole(<CampaignList />, 'viewer'))
    expect(screen.getByLabelText('Loading candidate campaigns…')).toBeTruthy()
    release(json(200, { items: [camp, { ...camp, id: 'c2', label: 'Candidate campaign C-0002', confidence: 'low', confidence_score: 0.4 }], disclaimer: 'D' }))
    const rows = await screen.findAllByTestId('campaign-row')
    expect(rows).toHaveLength(2)
    expect(rows[0].textContent).toContain('high (0.91)')
    expect(screen.getByRole('columnheader', { name: 'Confidence' }).getAttribute('aria-sort')).toBe('none')
  })

  it('list: empty line and error', async () => {
    on('GET', '/api/v1/campaigns', () => json(200, { items: [], disclaimer: 'D' }))
    const r = render(withRole(<CampaignList />, 'viewer'))
    await screen.findByText(/No candidate campaigns/)
    r.unmount()
    on('GET', '/api/v1/campaigns', fail('correlation offline'))
    render(withRole(<CampaignList />, 'viewer'))
    expect((await screen.findByRole('alert')).textContent).toContain('correlation offline')
  })

  it('detail: graph with square zoom/fit controls, legend, members table; error keeps the back link', async () => {
    on('GET', /\/api\/v1\/campaigns\/c1$/, () => json(200, {
      ...camp, disclaimer: 'D', reasons: { summary: ['3 distinct messages'], shared_indicators: [], rule: 'R' },
      graph: { nodes: [], edges: [] },
      members: [{ id: 'a1', created_at: null, subject: 'Subject a1', from_domain: 'x.test', detection_score: 80, detection_verdict: 'suspicious', sha256: 'b'.repeat(64) }],
    }))
    const r = render(withRole(<CampaignDetailView id="c1" />, 'viewer'))
    await screen.findByTestId('campaign-detail')
    const controls = screen.getByRole('group', { name: 'Graph controls' })
    expect(within(controls).getByRole('button', { name: 'Zoom in' })).toBeTruthy()
    expect(within(controls).getByRole('button', { name: 'Fit to screen' })).toBeTruthy()
    expect(screen.getByRole('list', { name: 'Node types' }).textContent).toContain('public IP')
    expect(within(screen.getByRole('table', { name: 'Member analyses' })).getByText('Subject a1')).toBeTruthy()
    r.unmount()
    on('GET', /\/api\/v1\/campaigns\/c9$/, fail('gone'))
    render(withRole(<CampaignDetailView id="c9" />, 'viewer'))
    await screen.findByRole('alert')
    expect(screen.getByText('← Candidate campaigns').getAttribute('href')).toBe('#campaigns')
  })
})

describe('Search page', () => {
  it('initial hint, empty result line and error', async () => {
    on('GET', /\/api\/v1\/search\?/, () => json(200, { query: 'zz', type: 'all', limit: 20, offset: 0, results: {} }))
    render(withRole(<SearchPage />, 'viewer'))
    expect(screen.getByText(/Enter a value and press Search/)).toBeTruthy()
    expect(screen.getByLabelText('Query')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    await screen.findByText(/No results\./)
    on('GET', /\/api\/v1\/search\?/, fail('index unavailable'))
    fireEvent.click(screen.getByRole('button', { name: 'Search' }))
    expect((await screen.findByRole('alert')).textContent).toContain('index unavailable')
  })
})

const user = (id: string, username: string, extra = {}) => ({
  id, username, role: 'viewer', is_active: true, locked: false, must_change_password: false, last_login_at: null,
  created_at: null, ...extra,
})

describe('Admin users', () => {
  it('loading skeleton, then status tags with text, "(you)" marker and action buttons', async () => {
    let release!: (r: Response) => void
    on('GET', '/api/v1/admin/users', () => new Promise<Response>((res) => { release = res }))
    render(withRole(<AdminUsersPage />, 'admin', { id: 'u1' }))
    expect(screen.getByLabelText('Loading users…')).toBeTruthy()
    release(json(200, [user('u1', 'root', { role: 'admin' }), user('u2', 'bob', { is_active: false }),
                       user('u3', 'cara', { must_change_password: true })]))
    const bob = await screen.findByTestId('user-row-bob')
    expect(bob.textContent).toContain('disabled')
    expect(within(bob).getByText('Enable')).toBeTruthy()
    expect(screen.getByTestId('user-row-cara').querySelector('[data-tone=warn]')?.textContent).toContain('must change password')
    expect(screen.getByTestId('user-row-root').textContent).toContain('(you)')
    expect(screen.getByRole('form', { name: 'Create user' })).toBeTruthy()
  })

  it('a failed load shows the reason', async () => {
    on('GET', '/api/v1/admin/users', fail('users table locked'))
    render(withRole(<AdminUsersPage />, 'admin'))
    expect((await screen.findByRole('alert')).textContent).toContain('users table locked')
  })
})

describe('App routes and role visibility', () => {
  const boot = (role: 'viewer' | 'analyst' | 'admin', hash: string) => {
    setSession(sessionFor(role))
    on('GET', '/api/v1/auth/me', () => json(200, { ...sessionFor(role).user }))
    on('GET', '/api/v1/analyses', () => json(200, []))
    on('GET', '/api/v1/investigations', () => json(200, []))
    on('GET', '/api/v1/campaigns', () => json(200, { items: [], disclaimer: 'D' }))
    window.location.hash = hash
    render(<AuthProvider><App /></AuthProvider>)
  }

  it('unknown route shows a 404 notice with a way back', async () => {
    boot('viewer', '#nowhere')
    const notice = await screen.findByRole('region', { name: 'Page not found' })
    expect(notice.textContent).toContain('404')
    expect(within(notice).getByRole('button', { name: 'Go to overview' })).toBeTruthy()
  })

  it('P5g: every role sees Analytics in the nav and can open #analytics', async () => {
    on('GET', /\/api\/v1\/analytics\/summary/, () => json(200, {
      generated_at: 'x', window: { days: 30, since: 'x', total_analyses: 0, analyses_considered: 0, capped: false, max_window: 2000 },
      verdicts: [], ml_classes: [], per_day: [], score_histogram: [], top_sender_domains: [],
      geo: { coverage: { with_geo: 0, analyses_considered: 0 }, basis: 'x', simulated_present: false, countries: [], asns: [] },
      attack_techniques: [], campaigns: { by_status: {}, candidate_size_distribution: [], candidates: 0 },
      intel_coverage: { analyses_with_consented_lookups: 0, analyses_considered: 0, runs_total: 0, simulated_runs: 0 } }))
    boot('viewer', '#analytics')
    await screen.findByTestId('analytics-page')
    expect(within(screen.getByRole('navigation', { name: 'Main navigation' })).getByText('Analytics')).toBeTruthy()
  })

  it('viewer opening #users or #upload lands on history; admin sees Users', async () => {
    boot('viewer', '#users')
    await screen.findByText('Investigation history')
    expect(screen.queryByText('User management')).toBeNull()
    cleanup()
    on('GET', '/api/v1/admin/users', () => json(200, []))
    boot('admin', '#users')
    await screen.findByText('User management')
    expect(within(screen.getByRole('navigation', { name: 'Main navigation' })).getByText('Users')).toBeTruthy()
  })
})
