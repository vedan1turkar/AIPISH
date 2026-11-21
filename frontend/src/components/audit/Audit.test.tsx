// @vitest-environment jsdom
// P5e: Audit page, Retention page (confirm flow), Custody tab, masked/redacted states, role visibility, axe.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'
import type { AnalysisDetail } from '../../api/client'
import AuditPage from '../admin/AuditPage'
import RetentionPage from '../admin/RetentionPage'
import CustodyPanel from './CustodyPanel'
import ResultsDashboard from '../ResultsDashboard'
import App from '../../App'
import { AuthProvider } from '../../auth/AuthContext'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'

type Handler = (init: RequestInit, url: string) => Response | Promise<Response>
let routes: [string, RegExp, Handler][] = []
const calls: { method: string; url: string; body?: string }[] = []
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const on = (m: string, p: RegExp, f: Handler) => routes.unshift([m, p, f])

beforeEach(() => {
  routes = []
  calls.length = 0
  clearSession()
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    const method = (init.method ?? 'GET').toUpperCase()
    calls.push({ method, url, body: typeof init.body === 'string' ? init.body : undefined })
    for (const [m, p, f] of routes) if (m === method && p.test(url)) return f(init, url)
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
  window.location.hash = ''
})

const GUARANTEE = 'Tamper-evident (HMAC hash chain), not tamper-proof: an attacker with both database write access and the audit key could forge a chain; external checkpoints reduce that risk.'
const ev = (seq: number, action = 'analysis_viewed', outcome = 'success') => ({
  seq, id: `e${seq}`, at: '2026-11-21T10:00:00+00:00', action, actor_id: 'u1', actor: 'demo-analyst',
  target_type: 'analysis', target_id: 'a1', analysis_id: 'a1', case_id: null, outcome, source_ip: '203.0.113.5',
  detail: { masked: false }, hash_prefix: 'abcdef012345',
})

function auditRoutes(verify: object) {
  on('GET', /\/audit\/verify$/, () => json(200, { checked: 40, last_seq: 40, last_hash: 'f'.repeat(64), guarantee: GUARANTEE, ...verify }))
  on('GET', /\/audit\/checkpoint$/, () => json(200, { latest: null, guarantee: GUARANTEE, advice: 'Record the seq and hash outside this system.' }))
  on('GET', /\/audit\/events/, (_i, url) => {
    const page = Number(new URL(`http://x${url}`).searchParams.get('page') ?? 1)
    return json(200, { items: Array.from({ length: 3 }, (_, i) => ev(60 - (page - 1) * 3 - i)), total: 60, page, page_size: 50,
                       actions: ['analysis_viewed', 'search_performed'], guarantee: GUARANTEE })
  })
}

describe('Audit page', () => {
  it('chain OK badge, honest guarantee, events newest first with seq + hash prefix', async () => {
    auditRoutes({ ok: true, first_broken_seq: null, reason: null })
    render(withRole(<AuditPage />, 'admin'))
    await screen.findByText('chain OK')
    expect(screen.getByText(GUARANTEE)).toBeTruthy()
    const rows = await screen.findAllByTestId('audit-row')
    expect(rows[0].textContent).toContain('60')
    expect(rows[0].textContent).toContain('abcdef012345')
    expect(screen.getByText(/No checkpoint recorded yet/)).toBeTruthy()
    expect(document.body.textContent).not.toMatch(/immutable|WORM|tamper-proof log/i)
  })

  it('BROKEN chain shows the first broken seq; Verify now re-runs; filters are sent; pagination', async () => {
    auditRoutes({ ok: false, first_broken_seq: 17, reason: 'event_hash mismatch: the event content was changed' })
    render(withRole(<AuditPage />, 'admin'))
    await screen.findByText('chain BROKEN')
    expect(screen.getByText('17')).toBeTruthy()
    expect(screen.getByText(/content was changed/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Verify now' }))
    await waitFor(() => expect(calls.filter((c) => c.url.endsWith('/audit/verify')).length).toBe(2))
    await screen.findAllByTestId('audit-row')
    const form = screen.getByRole('form', { name: 'Audit filters' })
    fireEvent.change(within(form).getByPlaceholderText('username'), { target: { value: 'demo-analyst' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Apply filters' }))
    await waitFor(() => expect(calls.some((c) => c.url.includes('actor=demo-analyst'))).toBe(true))
    await screen.findAllByTestId('audit-row')
    fireEvent.click(screen.getByRole('button', { name: 'Older' }))
    await waitFor(() => expect(calls.some((c) => c.url.includes('page=2'))).toBe(true))
  })

  it('Create checkpoint posts and shows the recorded seq', async () => {
    auditRoutes({ ok: true, first_broken_seq: null, reason: null })
    on('POST', /\/audit\/checkpoint$/, () => json(200, {
      checkpoint: { seq: 61, event_hash: 'a'.repeat(64), created_at: '2026-11-21T10:00:00Z', chain_ok: true },
      latest: { seq: 61, event_hash: 'a'.repeat(64), created_at: '2026-11-21T10:00:00Z', by: 'demo-admin' } }))
    render(withRole(<AuditPage />, 'admin'))
    await screen.findByText('chain OK')
    fireEvent.click(screen.getByRole('button', { name: 'Create checkpoint' }))
    await screen.findByText(/Checkpoint recorded at seq 61/)
    expect(screen.getByRole('region', { name: 'External checkpoint' }).textContent).toContain('61')
  })
})

const policy = (enabled: boolean) => ({ analysis_days: enabled ? 30 : 0, evidence_days: 0, mode: 'redact', grace_days: 0,
  enabled, audit_events_purged: false, note: 'x' })
function retentionRoutes(enabled = true) {
  on('GET', /\/admin\/retention\/status$/, () => json(200, {
    policy: policy(enabled), eligible_analyses: 2, eligible_evidence_only: 0, held_skipped: 1, eligible_ids: ['a1', 'a2'],
    holds: [{ id: 'h1', target_type: 'case', target_id: 'c1', reason: 'litigation 42', created_by: 'u', created_at: '2026-11-20T10:00:00Z',
              cleared_at: null, clear_reason: null, active: true }],
    redacted_total: 3, last_run: null, scheduler: 'none built in: run scripts/retention-run.sh from cron' }))
  on('POST', /\/admin\/retention\/run$/, (init) => {
    const dry = JSON.parse(String(init.body)).dry_run
    return json(200, { dry_run: dry, mode: 'redact', policy: policy(enabled), eligible_analyses: ['a1', 'a2'], eligible_evidence_only: [],
                       held_skipped: ['a3'], redacted: dry ? [] : ['a1', 'a2'], deleted: [], evidence_purged: [], errors: [] })
  })
}

describe('Retention page', () => {
  it('dry run previews; apply needs an explicit typed confirmation; holds can be set and cleared', async () => {
    retentionRoutes(true)
    on('POST', /\/admin\/holds$/, () => json(201, {}))
    on('POST', /\/admin\/holds\/h1\/clear$/, () => json(200, {}))
    render(withRole(<RetentionPage />, 'admin'))
    await screen.findByTestId('retention-page')
    const apply = screen.getByRole('button', { name: 'Apply…' }) as HTMLButtonElement
    expect(apply.disabled).toBe(true)                                     // no preview yet
    fireEvent.click(screen.getByRole('button', { name: 'Preview (dry run)' }))
    await screen.findByTestId('retention-preview')
    expect(JSON.parse(calls.find((c) => c.url.endsWith('/retention/run'))!.body!)).toEqual({ dry_run: true })
    fireEvent.click(screen.getByRole('button', { name: 'Apply…' }))
    const dialog = screen.getByRole('dialog', { name: 'Apply retention policy' })
    const confirm = within(dialog).getByRole('button', { name: 'Apply now' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    fireEvent.change(within(dialog).getByLabelText('Confirmation text'), { target: { value: 'apply' } })
    expect(confirm.disabled).toBe(true)                                   // exact text required
    fireEvent.change(within(dialog).getByLabelText('Confirmation text'), { target: { value: 'APPLY' } })
    fireEvent.click(confirm)
    await screen.findByTestId('retention-applied')
    const runs = calls.filter((c) => c.url.endsWith('/retention/run')).map((c) => JSON.parse(c.body!))
    expect(runs).toEqual([{ dry_run: true }, { dry_run: false }])
    const holdForm = screen.getByRole('form', { name: 'Set legal hold' })
    const setBtn = within(holdForm).getByRole('button', { name: 'Set hold' }) as HTMLButtonElement
    expect(setBtn.disabled).toBe(true)
    fireEvent.change(within(holdForm).getAllByRole('textbox')[0], { target: { value: 'a9' } })
    fireEvent.change(within(holdForm).getAllByRole('textbox')[1], { target: { value: 'court order' } })
    fireEvent.click(setBtn)
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/admin/holds'))).toBe(true))
    expect(JSON.parse(calls.find((c) => c.url.endsWith('/admin/holds'))!.body!)).toEqual({ target_type: 'analysis', target_id: 'a9', reason: 'court order' })
    fireEvent.change(screen.getByLabelText('Reason to clear hold on case c1'), { target: { value: 'settled' } })
    fireEvent.click(within(screen.getByRole('table', { name: 'Active legal holds' })).getByRole('button', { name: 'Clear' }))
    await waitFor(() => expect(calls.some((c) => c.url.endsWith('/admin/holds/h1/clear'))).toBe(true))
  })

  it('disabled policy: apply stays disabled and explains how to enable', async () => {
    retentionRoutes(false)
    render(withRole(<RetentionPage />, 'admin'))
    await screen.findByText(/Set RETENTION_ANALYSIS_DAYS/)
    fireEvent.click(screen.getByRole('button', { name: 'Preview (dry run)' }))
    await screen.findByTestId('retention-preview')
    expect((screen.getByRole('button', { name: 'Apply…' }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('axe: retention page', async () => {
    retentionRoutes(true)
    const { container } = render(withRole(<RetentionPage />, 'admin'))
    await screen.findByTestId('retention-page')
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})

describe('Custody tab', () => {
  it('timeline, integrity wording, held/redacted tags; axe clean', async () => {
    on('GET', /\/analyses\/a1\/custody$/, () => json(200, {
      analysis_id: 'a1', sha256: 'b'.repeat(64), size_bytes: 4096, evidence_bytes_stored: false, retention_state: 'redacted',
      redacted_at: '2026-11-21T10:00:00Z', legal_hold: true,
      timeline: [{ at: '2026-11-20T10:00:00Z', action: 'analysis_uploaded', actor: 'demo-analyst', outcome: 'success', case_id: null, detail: {} },
                 { at: '2026-11-20T10:05:00Z', action: 'report_generated', actor: 'demo-viewer', outcome: 'success', case_id: 'c1', detail: { masked: true } }],
      integrity_note: 'SHA-256 detects change to the stored file; it does not make storage tamper-proof.', audit_guarantee: GUARANTEE }))
    const { container } = render(withRole(<CustodyPanel analysisId="a1" />, 'analyst'))
    await screen.findByTestId('custody-panel')
    const rows = within(screen.getByRole('table', { name: 'Custody timeline' })).getAllByRole('row')
    expect(rows[1].textContent).toContain('analysis uploaded')
    expect(rows[2].textContent).toContain('masked: true')
    expect(screen.getByTestId('integrity-note').textContent).toBe('SHA-256 detects change to the stored file; it does not make storage tamper-proof.')
    const tags = screen.getByTestId('retention-tags').textContent
    expect(tags).toContain('redacted')
    expect(tags).toContain('legal hold')
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })

  it('error state', async () => {
    on('GET', /custody$/, () => json(500, { error: { code: 'X', message: 'audit store offline' } }))
    render(withRole(<CustodyPanel analysisId="a1" />, 'analyst'))
    expect((await screen.findByRole('alert')).textContent).toContain('audit store offline')
  })
})

function analysis(o: Partial<AnalysisDetail> = {}): AnalysisDetail {
  return {
    id: 'an1', created_at: '2026-11-20T09:00:00+00:00', sha256: 'f'.repeat(64), size_bytes: 1, subject: 's',
    from: { display_name: 'restricted', email: 'd***@internal-corp.example', domain: 'internal-corp.example' },
    to: [{ display_name: '', email: 'f***@internal-corp.example', domain: '' }], cc: [], reply_to: [], return_path: null, date: null,
    message_id: null, received_count: 0, authentication_results: [], dkim_signature_count: 0, has_html_body: false,
    body_text: null, urls: [], attachments: [], header_counts: {},
    detection: { score: 100, verdict: 'phishing_fraud_likely', findings: [], unknowns: [] },
    forensics: { relay_chain: [], trusted_boundary_index: null, candidate_ips: [], earliest_candidate_ip: null,
                 verified_originating_ip: null, inconsistencies: [], confidence_rules: [], forgery_note: '', disclaimer: '' },
    authentication: {}, enrichment: { results: [], degraded: [] }, parse_defects: [], ...o,
  } as unknown as AnalysisDetail
}

describe('dashboard masked / redacted states and role visibility', () => {
  it('viewer: masked banner, "restricted" display name, no Custody tab', async () => {
    render(withRole(<ResultsDashboard analysis={analysis({ pii_masked: true, body_restricted: true })} onNewAnalysis={() => {}} />, 'viewer'))
    expect((await screen.findByTestId('privacy-banners')).textContent).toContain('restricted for your role')
    expect(screen.getByText('restricted')).toBeTruthy()
    expect(screen.getByText('<d***@internal-corp.example>')).toBeTruthy()
    expect(screen.queryByRole('tab', { name: 'Custody' })).toBeNull()
  })

  it('analyst: redacted analysis shows the retention note and tags, never a blank title; Custody tab present', async () => {
    render(withRole(<ResultsDashboard analysis={analysis({ subject: null, from: null, retention_state: 'redacted', legal_hold: true })} onNewAnalysis={() => {}} />, 'analyst'))
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('content redacted per retention policy')
    expect(screen.getByTestId('privacy-banners').textContent).toContain('Content redacted per retention policy')
    expect(screen.getAllByTestId('retention-tags')[0].textContent).toContain('legal hold')
    expect(screen.getByRole('tab', { name: 'Custody' })).toBeTruthy()
  })

  it('nav: admin sees Audit and Retention; analyst does not; #audit redirects analysts to history', async () => {
    on('GET', /\/api\/v1\/auth\/me$/, () => json(200, { ...sessionFor('analyst').user }))
    on('GET', /\/api\/v1\/analyses$/, () => json(200, []))
    on('GET', /\/api\/v1\/investigations$/, () => json(200, []))
    setSession(sessionFor('analyst'))
    window.location.hash = '#audit'
    render(<AuthProvider><App /></AuthProvider>)
    await screen.findByText('Investigation history')
    const nav = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(within(nav).queryByText('Audit')).toBeNull()
    expect(within(nav).queryByText('Retention')).toBeNull()
    cleanup()
    on('GET', /\/api\/v1\/auth\/me$/, () => json(200, { ...sessionFor('admin').user }))
    auditRoutes({ ok: true, first_broken_seq: null, reason: null })
    setSession(sessionFor('admin'))
    window.location.hash = '#audit'
    render(<AuthProvider><App /></AuthProvider>)
    await screen.findByTestId('audit-page')
    const nav2 = screen.getByRole('navigation', { name: 'Main navigation' })
    expect(within(nav2).getByText('Audit')).toBeTruthy()
    expect(within(nav2).getByText('Retention')).toBeTruthy()
  })

  it('axe: audit page', async () => {
    auditRoutes({ ok: true, first_broken_seq: null, reason: null })
    const { container } = render(withRole(<AuditPage />, 'admin'))
    await screen.findAllByTestId('audit-row')
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([])
  })
})
