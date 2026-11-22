// @vitest-environment jsdom
// P5f frontend: top-bar badge, Alerts page (states, role visibility, acknowledge / resolve with note / reopen,
// 409 handling, admin config), Overview panel, analysis banner, honesty wording, axe.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'
import AlertsPage from './AlertsPage'
import { AlertBadge, AnalysisAlertBanner, OpenAlertsPanelBody, ALERT_HONESTY } from './shared'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'
import type { AlertDetail, AlertItem } from '../../api/client'

function item(over: Partial<AlertItem> = {}): AlertItem {
  return {
    id: 'al1'.padEnd(32, '0'), type: 'high_risk_analysis', type_label: 'High-risk analysis', severity: 'critical', status: 'new',
    title: 'High-risk analysis: combined critical 100/100 (analysis an1)', analysis_id: 'an1', campaign_id: null, risk_id: 'r1',
    summary: { analysis_id: 'an1', combined_level: 'critical', combined_score: 100, rule_verdict: 'phishing_fraud_likely',
               ml_class: 'impersonated', floors: ['H3_payment_or_credential_with_identity'], conflict: null, risk_version: 2 },
    occurrence_count: 2, created_at: '2026-11-22T09:00:00Z', updated_at: '2026-11-22T09:00:00Z', last_seen_at: '2026-11-22T09:05:00Z',
    acknowledged_by: null, acknowledged_at: null, resolved_by: null, resolved_at: null, resolution_note: null,
    delivery: { email: { status: 'disabled' } }, version: 1, analysis_redacted: false, ...over,
  }
}
const campaignItem = item({ id: 'al2'.padEnd(32, '0'), type: 'new_campaign', type_label: 'New candidate campaign', severity: 'medium',
  analysis_id: null, campaign_id: 'c1', risk_id: null, occurrence_count: 1,
  summary: { campaign_id: 'c1', campaign_label: 'Candidate campaign C-0001', campaign_confidence: 'medium', member_count: 4 } })
function detail(over: Partial<AlertDetail> = {}): AlertDetail {
  return { ...item(), history: [{ id: 'h1', action: 'raised', actor: null, note: null, from_state: null, to_state: 'new', detail: {}, at: '2026-11-22T09:00:00Z' },
                                { id: 'h2', action: 'occurrence', actor: null, note: null, from_state: null, to_state: null, detail: {}, at: '2026-11-22T09:05:00Z' }],
           note: ALERT_HONESTY, ...over }
}
const summary = { by_status: { new: 3, acknowledged: 1, resolved: 2 }, open_by_severity: { critical: 1, high: 2, medium: 1, low: 0 },
                  new_by_severity: { critical: 1, high: 1, medium: 1, low: 0 }, new: 3, open: 4, enabled: true, note: ALERT_HONESTY }

const calls: { url: string; init: RequestInit }[] = []
let state: AlertDetail
function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
beforeEach(() => {
  calls.length = 0
  state = detail()
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    const m = (init.method ?? 'GET').toUpperCase()
    if (url === '/api/v1/alerts/summary') return json(200, summary)
    if (url.startsWith('/api/v1/alerts?')) {
      if (url.includes('analysis_id=none')) return json(200, { items: [], total: 0, page: 1, page_size: 5, note: ALERT_HONESTY })
      return json(200, { items: [item(), campaignItem], total: 2, page: 1, page_size: 25, note: ALERT_HONESTY })
    }
    if (url === `/api/v1/alerts/${state.id}` && m === 'GET') return json(200, state)
    if (url === `/api/v1/alerts/${state.id}/acknowledge`) {
      state = { ...state, status: 'acknowledged', acknowledged_by: 'demo-analyst', version: 2 }
      return json(200, state)
    }
    if (url === `/api/v1/alerts/${state.id}/resolve`) {
      const note = JSON.parse(String(init.body)).note
      state = { ...state, status: 'resolved', resolved_by: 'demo-analyst', resolution_note: note, version: state.version + 1 }
      return json(200, state)
    }
    if (url === `/api/v1/alerts/${state.id}/reopen`) return json(409, { error: { code: 'CONFLICT', message: 'The alert was changed by someone else.' } })
    if (url === '/api/v1/admin/alerts/config') return json(200, {
      enabled: true, min_level: 'high', floor_alerts: true, conflict_alerts: true, campaign_min_confidence: 'medium',
      growth_min_new_members: 1, growth_debounce_minutes: 60, trigger_note: ALERT_HONESTY,
      email: { enabled: false, configured: false, min_severity: 'high', smtp_host: null, smtp_port: 587, smtp_security: 'starttls',
               smtp_username_set: false, smtp_password_set: false, from: null, recipients: 0, max_per_minute: 10, timeout_seconds: 10, app_base_url: null } })
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})
afterEach(() => { cleanup(); clearSession(); vi.unstubAllGlobals() })

describe('AlertBadge', () => {
  it('shows the count of NEW alerts and links to the inbox; failure shows a dash', async () => {
    const { unmount } = render(<AlertBadge />)
    await waitFor(() => expect(screen.getByTestId('alert-badge').textContent).toContain('3'))
    expect(screen.getByTestId('alert-badge').getAttribute('href')).toBe('#alerts')
    expect(screen.getByLabelText('3 new alerts')).toBeTruthy()
    unmount()
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline') }))
    render(<AlertBadge />)
    await waitFor(() => expect(screen.getByTestId('alert-badge').textContent).toContain('—'))
  })
})

describe('AlertsPage', () => {
  it('viewer: honesty strip, totals, rows, detail with history, no actions', async () => {
    setSession(sessionFor('viewer'))
    render(withRole(<AlertsPage initialId={state.id} />, 'viewer'))
    expect(screen.getByTestId('alerts-honesty').textContent).toBe(ALERT_HONESTY)
    await waitFor(() => expect(screen.getAllByTestId('alert-row')).toHaveLength(2))
    const det = await screen.findByTestId('alert-detail')
    expect(det.textContent).toContain('critical 100')
    expect(det.textContent).toContain('H3_payment_or_credential_with_identity')
    expect(det.textContent).toContain('pinned risk v2')
    expect(within(screen.getByTestId('alert-history')).getAllByRole('listitem')).toHaveLength(2)
    expect(screen.queryByTestId('alert-actions')).toBeNull()
    expect(screen.queryByTestId('alert-config')).toBeNull()
    expect(screen.getByText('campaign C-0001')).toBeTruthy()
    expect(document.body.textContent?.toLowerCase()).not.toContain('real-time monitoring')
  })

  it('analyst acknowledges, resolves with a required note, and a 409 on reopen is reported', async () => {
    setSession(sessionFor('analyst'))
    render(withRole(<AlertsPage initialId={state.id} />, 'analyst'))
    fireEvent.click(await screen.findByRole('button', { name: 'Acknowledge' }))
    await waitFor(() => expect(screen.getByTestId('alert-detail').textContent).toContain('demo-analyst'))
    const ack = calls.find((c) => c.url.endsWith('/acknowledge'))!
    expect(ack.init.method).toBe('POST')
    expect(JSON.parse(String(ack.init.body))).toEqual({ version: 1 })
    fireEvent.click(screen.getByRole('button', { name: 'Resolve…' }))
    const dialog = screen.getByRole('dialog')
    const confirm = within(dialog).getByRole('button', { name: 'Resolve' }) as HTMLButtonElement
    expect(confirm.disabled).toBe(true)
    fireEvent.change(within(dialog).getByLabelText('Resolution note'), { target: { value: 'Confirmed with the vendor by phone.' } })
    expect(confirm.disabled).toBe(false)
    fireEvent.click(confirm)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(JSON.parse(String(calls.find((c) => c.url.endsWith('/resolve'))!.init.body)).note).toBe('Confirmed with the vendor by phone.')
    fireEvent.click(await screen.findByRole('button', { name: 'Reopen' }))
    await screen.findByText(/changed by someone else\. The alert was reloaded\./)
  })

  it('filters refetch; admin sees read-only configuration', async () => {
    setSession(sessionFor('admin'))
    render(withRole(<AlertsPage />, 'admin'))
    await screen.findByTestId('alert-config')
    expect(screen.getByTestId('alert-config').textContent).toContain('password not set')
    fireEvent.change(screen.getByLabelText('Severity filter'), { target: { value: 'critical' } })
    await waitFor(() => expect(calls.some((c) => c.url.includes('severity=critical') && c.url.includes('status=open'))).toBe(true))
    expect(screen.getByText(/Select an alert/)).toBeTruthy()
  })

  it('error state', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: { code: 'INTERNAL', message: 'boom' } })))
    setSession(sessionFor('viewer'))
    render(withRole(<AlertsPage />, 'viewer'))
    await screen.findByText(/Alerts could not be loaded/)
  })

  it('axe clean', async () => {
    setSession(sessionFor('analyst'))
    const { container } = render(withRole(<AlertsPage initialId={state.id} />, 'analyst'))
    await screen.findByTestId('alert-detail')
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations).toEqual([])
  })
})

describe('Overview panel and analysis banner', () => {
  it('Overview lists open alerts with counts', async () => {
    render(<OpenAlertsPanelBody />)
    const p = await screen.findByTestId('overview-alerts')
    expect(p.textContent).toContain('open 4')
    expect(p.textContent).toContain('critical 1')
    expect(within(p).getByRole('link', { name: 'High-risk analysis' }).getAttribute('href')).toBe(`#alerts/${state.id}`)
  })

  it('analysis banner only when an open alert exists', async () => {
    const { unmount } = render(<AnalysisAlertBanner analysisId="an1" />)
    const b = await screen.findByTestId('analysis-alert-banner')
    expect(b.textContent).toContain('raised when this analysis was processed')
    unmount()
    render(<AnalysisAlertBanner analysisId="none" />)
    await new Promise((r) => setTimeout(r, 20))
    expect(screen.queryByTestId('analysis-alert-banner')).toBeNull()
  })
})
