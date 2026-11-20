// @vitest-environment jsdom
// P5b frontend auth: login flow, 401 → login, role-aware UI, authenticated PDF download, admin page.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import App from '../App'
import { AuthProvider } from './AuthContext'
import { clearSession, getSession, setSession } from './session'
import { downloadReport, listAnalyses } from '../api/client'
import ResultsDashboard from '../components/ResultsDashboard'
import AdminUsersPage from '../components/admin/AdminUsersPage'
import { PERMS, sessionFor, withRole } from '../test/auth'
import type { AnalysisDetail } from '../api/client'

type Handler = (url: string, init: RequestInit) => Response | undefined
let handlers: Handler[] = []
const calls: { url: string; init: RequestInit }[] = []

const jsonRes = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function on(method: string, path: string | RegExp, res: (init: RequestInit) => Response) {
  handlers.unshift((url, init) => {
    const m = (init.method ?? 'GET').toUpperCase()
    const hit = typeof path === 'string' ? url === path || url.startsWith(`${path}?`) : path.test(url)
    return m === method && hit ? res(init) : undefined
  })
}

function authHeader(init: RequestInit): string | null {
  return new Headers(init.headers).get('Authorization')
}

beforeEach(() => {
  handlers = []
  calls.length = 0
  window.sessionStorage.clear()
  window.localStorage.clear()
  clearSession()
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init })
      for (const h of handlers) {
        const r = h(url, init)
        if (r) return r
      }
      return jsonRes(404, { error: { code: 'NOT_FOUND', message: 'not found' } })
    }),
  )
  on('GET', '/api/v1/health', () => jsonRes(200, { status: 'ok', version: '0.1.0', env: 'test', db_connected: true }))
  on('GET', '/api/v1/analyses', () => jsonRes(200, []))
  on('GET', '/api/v1/investigations', () => jsonRes(200, []))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
})

function meFor(role: 'viewer' | 'analyst' | 'admin', extra = {}) {
  return { ...sessionFor(role).user, is_active: true, ...extra }
}

function signIn(role: 'viewer' | 'analyst' | 'admin') {
  setSession(sessionFor(role))
  on('GET', '/api/v1/auth/me', () => jsonRes(200, meFor(role)))
}

describe('login flow', () => {
  it('shows the login page when signed out and signs in with a bearer token', async () => {
    on('POST', '/api/v1/auth/login', () =>
      jsonRes(200, {
        access_token: 'tok-analyst', token_type: 'bearer',
        expires_at: new Date(Date.now() + 3600_000).toISOString(), user: meFor('analyst'),
      }),
    )
    on('GET', '/api/v1/auth/me', (init) =>
      authHeader(init) === 'Bearer tok-analyst' ? jsonRes(200, meFor('analyst')) : jsonRes(401, { error: { code: 'INVALID_TOKEN', message: 'x' } }),
    )
    render(<AuthProvider><App /></AuthProvider>)
    expect(screen.getByRole('form', { name: 'Sign in' })).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'demo-analyst' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'a-long-password-1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await waitFor(() => expect(screen.getByTestId('current-user').textContent).toContain('demo-analyst'))
    expect(screen.getByTestId('current-user').textContent).toContain('analyst')
    const login = calls.find((c) => c.url === '/api/v1/auth/login')!
    expect(authHeader(login.init)).toBeNull()
    expect(JSON.parse(String(login.init.body))).toEqual({ username: 'demo-analyst', password: 'a-long-password-1' })
    // token persisted per tab in sessionStorage, never localStorage
    expect(window.sessionStorage.getItem('aipish.session')).toContain('tok-analyst')
    expect(window.localStorage.length).toBe(0)
    expect(getSession()?.user.permissions).toEqual(PERMS.analyst)
  })

  it('shows a generic error on invalid credentials', async () => {
    on('POST', '/api/v1/auth/login', () => jsonRes(401, { error: { code: 'INVALID_CREDENTIALS', message: 'invalid credentials' } }))
    render(<AuthProvider><App /></AuthProvider>)
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'x' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'y' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    await screen.findByText('Invalid username or password.')
    expect(getSession()).toBeNull()
  })

  it('forces a password change when the account has a temporary password', async () => {
    setSession({ ...sessionFor('analyst'), user: { ...sessionFor('analyst').user, must_change_password: true } })
    render(<AuthProvider><App /></AuthProvider>)
    expect(screen.getByRole('form', { name: 'Change password' })).toBeTruthy()
    expect(screen.queryByText('Analyse')).toBeNull()
  })
})

describe('401 handling', () => {
  it('attaches the token, and on 401 clears the session and returns to login with a message', async () => {
    signIn('viewer')
    render(<AuthProvider><App /></AuthProvider>)
    await screen.findByTestId('current-user')
    on('GET', '/api/v1/analyses', () => jsonRes(401, { error: { code: 'TOKEN_EXPIRED', message: 'expired' } }))
    await act(async () => {
      await listAnalyses().catch(() => undefined)
    })
    const hits = calls.filter((c) => c.url === '/api/v1/analyses')
    const last = hits[hits.length - 1]
    expect(authHeader(last.init)).toBe('Bearer test-token-viewer')
    await screen.findByText('Your session expired. Sign in again.')
    expect(screen.getByRole('form', { name: 'Sign in' })).toBeTruthy()
    expect(window.sessionStorage.getItem('aipish.session')).toBeNull()
  })

  it('sign out revokes server-side and returns to login', async () => {
    signIn('analyst')
    on('POST', '/api/v1/auth/logout', () => jsonRes(200, { status: 'logged_out' }))
    render(<AuthProvider><App /></AuthProvider>)
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    await screen.findByText('You signed out.')
    expect(calls.some((c) => c.url === '/api/v1/auth/logout' && authHeader(c.init) === 'Bearer test-token-analyst')).toBe(true)
  })
})

describe('token expiry', () => {
  it('signs out locally when the access token expires (no refresh tokens)', async () => {
    signIn('analyst')
    setSession({ ...sessionFor('analyst'), expiresAt: new Date(Date.now() + 300).toISOString() })
    render(<AuthProvider><App /></AuthProvider>)
    await screen.findByTestId('current-user')
    await screen.findByText('Your session expired. Sign in again.', {}, { timeout: 2000 })
    expect(getSession()).toBeNull()
    expect(window.sessionStorage.getItem('aipish.session')).toBeNull()
  })
})

describe('role-aware navigation', () => {
  it('viewer sees no Analyse or Users navigation', async () => {
    signIn('viewer')
    render(<AuthProvider><App /></AuthProvider>)
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).queryByText('Analyse')).toBeNull()
    expect(within(nav).queryByText('Users')).toBeNull()
    expect(within(nav).getByText('History')).toBeTruthy()
  })

  it('analyst sees Analyse but not Users; admin sees Users', async () => {
    signIn('analyst')
    const { unmount } = render(<AuthProvider><App /></AuthProvider>)
    let nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).getByText('Analyse')).toBeTruthy()
    expect(within(nav).queryByText('Users')).toBeNull()
    unmount()
    signIn('admin')
    on('GET', '/api/v1/admin/users', () => jsonRes(200, []))
    render(<AuthProvider><App /></AuthProvider>)
    nav = await screen.findByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).getByText('Users')).toBeTruthy()
  })
})

function analysis(): AnalysisDetail {
  return {
    id: 'a1', created_at: '2026-11-20T09:00:00+00:00', sha256: 'f'.repeat(64), size_bytes: 1, subject: 's',
    from: null, to: [], cc: [], reply_to: [], return_path: null, date: null, message_id: null, received_count: 0,
    authentication_results: [], dkim_signature_count: 0, has_html_body: false, body_text: '', urls: [],
    attachments: [], header_counts: {},
    detection: { score: 100, verdict: 'phishing_fraud_likely', findings: [], unknowns: [] },
    forensics: { relay_chain: [], trusted_boundary_index: null, candidate_ips: [], earliest_candidate_ip: null,
                 verified_originating_ip: null, inconsistencies: [], confidence_rules: [], forgery_note: '',
                 disclaimer: '' },
    authentication: {}, enrichment: { results: [], degraded: [] }, parse_defects: [],
  } as unknown as AnalysisDetail
}

describe('role-aware dashboard', () => {
  it('viewer: read-only (no new analysis, case creation, intel run or generate)', async () => {
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />, 'viewer'))
    expect(screen.queryByText('+ New analysis')).toBeNull()
    expect(screen.queryByText('📁 Create investigation case')).toBeNull()
    expect(screen.getByText('Your role can view cases but not create them.')).toBeTruthy()
    expect(screen.queryByText('Run integrity check')).toBeNull()
    fireEvent.click(screen.getByRole('tab', { name: /Threat intel/ }))
    expect(screen.getByTestId('intel-readonly')).toBeTruthy()
    expect(screen.queryByText('Run threat intel lookup')).toBeNull()
    // config-status endpoints are admin-only and are not even requested for a viewer
    expect(calls.some((c) => c.url.includes('/intel/status') || c.url.includes('/llm/status'))).toBe(false)
  })

  it('analyst: actions available', async () => {
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />, 'analyst'))
    expect(screen.getByText('+ New analysis')).toBeTruthy()
    expect(screen.getByText('📁 Create investigation case')).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', { name: /Threat intel/ }))
    expect(screen.queryByTestId('intel-readonly')).toBeNull()
  })

  it('viewer can download the PDF of an existing case', async () => {
    signIn('viewer')
    on('GET', '/api/v1/investigations', () =>
      jsonRes(200, [{ id: 'c1', case_number: 'CASE-1', status: 'open', analyses: [{ analysis_id: 'a1' }],
        evidence_policy: { store_mode: 'hash_only', retention_days: 30, key_required: false, note: '' } }]),
    )
    on('GET', /\/api\/v1\/investigations\/c1\/report\/a1/, () =>
      new Response(new Blob(['%PDF-1.4']), { status: 200, headers: { 'Content-Type': 'application/pdf' } }),
    )
    const created = vi.fn(() => 'blob:x')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />, 'viewer'))
    await screen.findByText('CASE-1')
    fireEvent.click(screen.getByText('⬇ Download forensic PDF'))
    await waitFor(() => expect(created).toHaveBeenCalled())
    const pdf = calls.find((c) => c.url.includes('/report/a1'))!
    expect(authHeader(pdf.init)).toBe('Bearer test-token-viewer')
    expect(calls.some((c) => c.url.includes('/from-analysis/'))).toBe(false)
  })
})

describe('authenticated PDF download', () => {
  it('fetches with the bearer token and saves a blob (no bare link)', async () => {
    setSession(sessionFor('viewer'))
    on('GET', /\/report\//, () => new Response(new Blob(['%PDF']), { status: 200 }))
    const created = vi.fn(() => 'blob:y')
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: created, revokeObjectURL: vi.fn() }))
    await downloadReport('c9', 'a9', null, 'run1')
    const c = calls[calls.length - 1]
    expect(c.url).toBe('/api/v1/investigations/c9/report/a9?intel_run_id=run1')
    expect(authHeader(c.init)).toBe('Bearer test-token-viewer')
    expect(created).toHaveBeenCalledOnce()
  })

  it('surfaces a 403 as an error', async () => {
    setSession(sessionFor('viewer'))
    on('GET', /\/report\//, () => jsonRes(403, { error: { code: 'FORBIDDEN', message: 'Your role does not allow this action.' } }))
    await expect(downloadReport('c9', 'a9')).rejects.toThrow('Your role does not allow this action.')
    expect(getSession()).not.toBeNull() // 403 is not a sign-out
  })
})

describe('admin user management page', () => {
  const users = [
    { id: 'u1', username: 'demo-admin', role: 'admin', is_active: true, must_change_password: false, created_at: null, last_login_at: null, locked: false },
    { id: 'u2', username: 'bob', role: 'viewer', is_active: true, must_change_password: false, created_at: null, last_login_at: null, locked: false },
  ]

  it('lists, creates (temp password shown once), changes role, disables and resets', async () => {
    setSession(sessionFor('admin', { id: 'u1' }))
    const log = vi.spyOn(console, 'log')
    on('GET', '/api/v1/admin/users', () => jsonRes(200, users))
    on('POST', '/api/v1/admin/users', () =>
      jsonRes(201, { user: { ...users[1], id: 'u3', username: 'carol' }, temporary_password: 'Temp-Once-123abc', note: 'Shown once.' }),
    )
    on('PATCH', /\/api\/v1\/admin\/users\/u2$/, (init) => jsonRes(200, { ...users[1], ...JSON.parse(String(init.body)) }))
    on('POST', /\/api\/v1\/admin\/users\/u2\/reset-password$/, () =>
      jsonRes(200, { user: users[1], temporary_password: 'Reset-Once-456def', note: 'Shown once.' }),
    )
    render(withRole(<AdminUsersPage />, 'admin', { id: 'u1' }))
    await screen.findByTestId('user-row-bob')
    expect(screen.getByText('(you)')).toBeTruthy()

    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'carol' } })
    fireEvent.click(screen.getByText('Create with temporary password'))
    expect((await screen.findByTestId('temp-password')).textContent).toBe('Temp-Once-123abc')
    fireEvent.click(screen.getByText(/hide it/))
    expect(screen.queryByTestId('temp-password')).toBeNull()

    fireEvent.change(screen.getByLabelText('Role for bob'), { target: { value: 'analyst' } })
    await waitFor(() => expect(calls.some((c) => c.init.method === 'PATCH' && String(c.init.body).includes('analyst'))).toBe(true))
    fireEvent.click(within(screen.getByTestId('user-row-bob')).getByText('Disable'))
    await waitFor(() => expect(calls.some((c) => c.init.method === 'PATCH' && String(c.init.body).includes('"is_active":false'))).toBe(true))
    fireEvent.click(within(screen.getByTestId('user-row-bob')).getByText('Reset password'))
    expect((await screen.findByTestId('temp-password')).textContent).toBe('Reset-Once-456def')

    expect(calls.filter((c) => c.url.startsWith('/api/v1/admin')).every((c) => authHeader(c.init) === 'Bearer test-token-admin')).toBe(true)
    expect(JSON.stringify(log.mock.calls)).not.toContain('Temp-Once')
    expect(window.sessionStorage.getItem('aipish.session') ?? '').not.toContain('Temp-Once')
  })

  it('shows the last-admin error from the backend', async () => {
    setSession(sessionFor('admin', { id: 'u1' }))
    on('GET', '/api/v1/admin/users', () => jsonRes(200, users))
    on('PATCH', /\/admin\/users\/u1$/, () => jsonRes(409, { error: { code: 'LAST_ADMIN', message: 'This is the last active admin.' } }))
    render(withRole(<AdminUsersPage />, 'admin', { id: 'u1' }))
    await screen.findByTestId('user-row-demo-admin')
    fireEvent.click(within(screen.getByTestId('user-row-demo-admin')).getByText('Disable'))
    await screen.findByText('This is the last active admin.')
  })
})
