// @vitest-environment jsdom
// P5h frontend: Risk tab states, verdict-strip cell (separate from rules and ML), version picker, role visibility,
// PDF pin, History / Overview / Search columns, Analytics chart, axe.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'

const plotly = vi.hoisted(() => ({ react: vi.fn(() => Promise.resolve()), purge: vi.fn(), Plots: { resize: vi.fn() } }))
vi.mock('plotly.js-basic-dist-min', () => ({ default: plotly }))

import RiskPanel from './RiskPanel'
import VerdictStrip from '../VerdictStrip'
import ResultsDashboard from '../ResultsDashboard'
import HistoryPage from '../HistoryPage'
import OverviewPage from '../overview/OverviewPage'
import AnalyticsPage from '../analytics/AnalyticsPage'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'
import type { AnalysisDetail, AnalysisSummary, AnalyticsSummary, RiskAssessment, RiskComponent } from '../../api/client'

const DISC = ['Risk index (0-100), not a probability of fraud: it combines existing signals by documented rules.',
  'Absence of threat-intelligence records is not evidence of safety.']

function comps(over: Partial<Record<string, Partial<RiskComponent>>> = {}): RiskComponent[] {
  const base: RiskComponent[] = [
    { name: 'rules', label: '18-rule engine (as displayed)', status: 'available', value: { score: 100, verdict: 'phishing_fraud_likely', fired: ['payment_diversion'] },
      role: 'floor', effect: 'conflict floor (medium)', evidence_ids: ['K1'], reason: 'Rule verdict phishing_fraud_likely (100/100).',
      cues: [{ rule_id: 'urgency_language', fired: true, evidence_id: 'K1' }, { rule_id: 'credential_request', fired: false, evidence_id: null }] },
    { name: 'ml', label: 'ML ensemble (threat index = 1 - P(legitimate))', status: 'available',
      value: { threat_index: 0.03, label: 'legitimate', confidence: 0.97, probabilities: {} }, role: 'primary', effect: 'base 2/100',
      evidence_ids: ['K2'], reason: 'Primary signal.' },
    { name: 'hard_evidence', label: 'Hard-evidence floors', status: 'available', value: ['H3_payment_or_credential_with_identity'],
      role: 'floor', effect: 'floor 60 (high)', evidence_ids: ['K1'], reason: 'BEC pattern.' },
    { name: 'threat_intel', label: 'Threat intelligence (consented runs only)', status: 'not_run', value: null, role: 'unavailable',
      effect: 'none', evidence_ids: [], reason: 'No threat-intel run for this analysis.' },
    { name: 'campaign', label: 'Candidate campaign membership', status: 'available', value: [], role: 'context', effect: 'none',
      evidence_ids: [], reason: 'Not a member of any candidate campaign (context only).' },
    { name: 'attack', label: 'ATT&CK mapping and source-type hypotheses', status: 'available', value: { techniques: ['T1657'], hypotheses: [] },
      role: 'context', effect: 'none', evidence_ids: ['K3'], reason: 'Context only.' },
  ]
  return base.map((c) => ({ ...c, ...(over[c.name] ?? {}) }))
}

function risk(over: Partial<RiskAssessment> = {}): RiskAssessment {
  return {
    risk_id: 'r2', analysis_id: 'an1', version: 2, source: 'recompute', created_at: '2026-11-21T10:00:00Z',
    engine_version: 'risk-engine-1.0', config_version: 'risk-config-1.0', combined_score: 60, level: 'high', confidence: 'low',
    agreement: 'conflict', conflict: 'rules_high_ml_legitimate',
    flags: ['analyst_review_recommended', 'conflicting_signals', 'hard_evidence_floor'],
    components: comps(),
    evidence: [{ id: 'K1', source: 'rule', ref: 'payment_diversion', statement: 'Rule payment_diversion: Payment diversion (+25)' },
               { id: 'K2', source: 'ml', ref: 'm1', statement: 'ML ensemble: class legitimate' },
               { id: 'K3', source: 'attack', ref: 'm/T1657', statement: 'ATT&CK technique T1657 mapped' }],
    explanation: ['Primary signal: ML ensemble threat index 0.03.', 'Conflicting signals: the rule engine says phishing_fraud_likely.'],
    bands: { edges: { low: 10, medium: 25, high: 60, critical: 85 }, ml_thresholds: { t_med: 0.36 } },
    inputs: { detection_score: 100, detection_verdict: 'phishing_fraud_likely',
              ml_source: { kind: 'upload_classification', id: 'm1', model_version: 'aipish-email-v1@x', status: 'available' },
              intel_run_id: null, intel_simulated: false, attack_mapping_id: 'm', campaign_ids: [] },
    disclaimers: DISC,
    ...over,
  }
}

const noop = () => {}
function panel(p: Partial<Parameters<typeof RiskPanel>[0]> = {}) {
  return <RiskPanel data={risk()} loading={false} error={null} history={[]} canRecompute={false} recomputing={false}
                    recomputeError={null} onRecompute={noop} onSelectVersion={noop} {...p} />
}

afterEach(() => { cleanup(); clearSession(); vi.unstubAllGlobals() })

describe('RiskPanel', () => {
  it('shows level, score, confidence, components with status/role/evidence, conflict with both views, disclaimers', () => {
    render(panel())
    const head = screen.getByTestId('risk-headline')
    expect(head.textContent).toContain('high')
    expect(head.textContent).toContain('60')
    expect(screen.getByTestId('risk-conflict').textContent).toMatch(/Rule engine: 100\/100 · phishing fraud likely · ML ensemble: 0\.0300 · legitimate/)
    const rows = screen.getAllByTestId('risk-component')
    expect(rows.map((r) => r.getAttribute('data-name'))).toEqual(['rules', 'ml', 'hard_evidence', 'threat_intel', 'campaign', 'attack'])
    expect(within(rows[3]).getByText('not run')).toBeTruthy()
    expect(within(rows[3]).getAllByText('unavailable').length).toBeGreaterThan(0)
    expect(within(rows[1]).getByText('primary')).toBeTruthy()
    expect(within(rows[4]).getByText('context only')).toBeTruthy()
    expect(within(rows[0]).getByRole('link', { name: 'Go to evidence K1' })).toBeTruthy()
    expect(document.getElementById('evidence-K1')).toBeTruthy()
    for (const d of DISC) expect(screen.getByText(d)).toBeTruthy()
    expect(screen.getByText('conflicting signals')).toBeTruthy()
    expect(within(screen.getByTestId('risk-cues')).getByText('credential request: not found')).toBeTruthy()
  })

  it('ML unavailable and indeterminate states are honest', () => {
    const { rerender } = render(panel({ data: risk({ level: 'low', combined_score: 10, agreement: 'not_applicable', conflict: null,
      flags: ['components_missing', 'rules_only'],
      components: comps({ ml: { status: 'unavailable', value: null, role: 'unavailable', effect: null, evidence_ids: [],
                                reason: 'ML result unavailable: model files missing. Never treated as legitimate; confidence reduced.' } }) }) }))
    expect(screen.queryByTestId('risk-conflict')).toBeNull()
    expect(screen.getByText(/Never treated as legitimate/)).toBeTruthy()
    expect(screen.getByText('components missing')).toBeTruthy()
    rerender(panel({ data: risk({ level: 'indeterminate', combined_score: null, flags: [] }) }))
    expect(screen.getByTestId('risk-headline').textContent).toContain('indeterminate')
    expect(screen.getByTestId('risk-headline').textContent).toContain('—')
  })

  it('loading, error, empty (recompute only when allowed), version picker', () => {
    const onRecompute = vi.fn()
    const onSelectVersion = vi.fn()
    const { rerender } = render(panel({ loading: true }))
    expect(screen.getByLabelText('Loading combined risk…')).toBeTruthy()
    rerender(panel({ error: 'boom' }))
    expect(screen.getByText(/Could not load the combined risk assessment: boom/)).toBeTruthy()
    rerender(panel({ data: null }))
    expect(screen.getByText(/No combined risk assessment has been computed/)).toBeTruthy()
    expect(screen.queryByTestId('risk-recompute')).toBeNull()
    rerender(panel({ data: null, canRecompute: true, onRecompute }))
    fireEvent.click(screen.getByTestId('risk-recompute'))
    expect(onRecompute).toHaveBeenCalled()
    rerender(panel({ onSelectVersion, history: [
      { risk_id: 'r2', version: 2, source: 'recompute', level: 'high', combined_score: 60, confidence: 'low', engine_version: 'e', created_at: null },
      { risk_id: 'r1', version: 1, source: 'upload', level: 'critical', combined_score: 100, confidence: 'low', engine_version: 'e', created_at: null }] }))
    fireEvent.change(screen.getByLabelText('Combined risk version'), { target: { value: '1' } })
    expect(onSelectVersion).toHaveBeenCalledWith(1)
    rerender(panel({ data: { ...risk(), new_version: false } }))
    expect(screen.getByText('Recomputed: no change, so no new version was stored.')).toBeTruthy()
  })

  it('axe clean', async () => {
    const { container } = render(panel({ canRecompute: true }))
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations).toEqual([])
  })
})

function analysis(): AnalysisDetail {
  return {
    id: 'an1', created_at: '2026-11-20T09:00:00+00:00', sha256: 'f'.repeat(64), size_bytes: 1, subject: 's',
    from: null, to: [], cc: [], reply_to: [], return_path: null, date: null, message_id: null, received_count: 0,
    authentication_results: [], dkim_signature_count: 0, has_html_body: false, body_text: '', urls: [],
    attachments: [], header_counts: {},
    detection: { score: 100, verdict: 'phishing_fraud_likely', findings: [], unknowns: [] },
    forensics: { relay_chain: [], trusted_boundary_index: null, candidate_ips: [], earliest_candidate_ip: null,
                 verified_originating_ip: null, inconsistencies: [], confidence_rules: [], forgery_note: '', disclaimer: '' },
    authentication: {}, enrichment: { results: [], degraded: [] }, parse_defects: [],
  } as unknown as AnalysisDetail
}

describe('VerdictStrip combined cell', () => {
  it('is a separate cell; the rule verdict and ML class stay unchanged; upload-time ML is shown as such', () => {
    render(<VerdictStrip analysis={analysis()} assessment={null} attack={null} intelRun={null} caseInfo={null} integrity={null} risk={risk()} />)
    expect(screen.getByTestId('strip-rules').textContent).toContain('100')
    expect(screen.getByTestId('strip-rules').textContent?.toLowerCase()).toContain('phishing fraud likely')
    const ml = screen.getByTestId('strip-ml').textContent ?? ''
    expect(ml.toLowerCase()).toContain('legitimate')
    expect(ml).toContain('upload-time classification')
    const cell = screen.getByTestId('strip-risk').textContent ?? ''
    expect(cell).toContain('Combined risk · index')
    expect(cell).toContain('60')
    expect(cell.toLowerCase()).toContain('high')
    expect(cell).toContain('confidence low · conflicting signals · not a probability')
  })

  it('not computed / loading', () => {
    const { rerender } = render(<VerdictStrip analysis={analysis()} assessment={null} attack={null} intelRun={null} caseInfo={null} integrity={null} />)
    expect(screen.getByTestId('strip-risk').textContent).toContain('not computed')
    expect(screen.getByTestId('strip-ml').textContent).toContain('not assessed')
    rerender(<VerdictStrip analysis={analysis()} assessment={null} attack={null} intelRun={null} caseInfo={null} integrity={null} riskLoading />)
    expect(screen.getByTestId('strip-risk').textContent).toContain('loading…')
  })
})

// ── stubbed backend ───────────────────────────────────────────────────────
const calls: { url: string; init: RequestInit }[] = []
function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
const summaryRow = (over: Partial<AnalysisSummary> = {}): AnalysisSummary => ({
  id: 'an1', created_at: '2026-11-21T09:00:00+00:00', sha256: 'a'.repeat(64), size_bytes: 10, subject: 'Supplier change',
  sender: null, received_count: 1, url_count: 0, attachment_count: 0, detection_score: 100, detection_verdict: 'phishing_fraud_likely',
  has_defects: false, combined_level: 'critical', combined_score: 100, combined_confidence: 'low', ...over,
})
const analytics = (): AnalyticsSummary => ({
  generated_at: '2026-11-21T10:00:00Z',
  window: { days: 30, since: '2026-10-23', total_analyses: 3, analyses_considered: 3, capped: false, max_window: 2000 },
  verdicts: [{ verdict: 'phishing_fraud_likely', count: 2 }, { verdict: 'minimal', count: 1 }],
  ml_classes: [{ label: 'not_assessed', count: 3 }],
  per_day: [{ date: '2026-11-21', count: 3 }],
  score_histogram: [{ bucket: '0-9', count: 1 }], top_sender_domains: [],
  geo: { coverage: { with_geo: 0, analyses_considered: 3 }, basis: 'x', simulated_present: false, countries: [], asns: [] },
  attack_techniques: [],
  combined_levels: [{ level: 'minimal', count: 0 }, { level: 'low', count: 1 }, { level: 'medium', count: 0 }, { level: 'high', count: 0 },
                    { level: 'critical', count: 2 }, { level: 'indeterminate', count: 0 }, { level: 'not_computed', count: 0 }],
  campaigns: { by_status: {}, candidate_size_distribution: [], candidates: 0 },
  intel_coverage: { analyses_with_consented_lookups: 0, analyses_considered: 3, runs_total: 0, simulated_runs: 0 },
})

beforeEach(() => {
  calls.length = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    const m = (init.method ?? 'GET').toUpperCase()
    if (url === '/api/v1/analyses/an1/risk' && m === 'GET') return json(200, risk())
    if (url === '/api/v1/analyses/an1/risk?version=1') return json(200, risk({ risk_id: 'r1', version: 1, source: 'upload', level: 'critical', combined_score: 100 }))
    if (url === '/api/v1/analyses/an1/risk/history') return json(200, [
      { risk_id: 'r2', version: 2, source: 'recompute', level: 'high', combined_score: 60, confidence: 'low', engine_version: 'e', created_at: null },
      { risk_id: 'r1', version: 1, source: 'upload', level: 'critical', combined_score: 100, confidence: 'low', engine_version: 'e', created_at: null }])
    if (url === '/api/v1/analyses/an1/risk/recompute') return json(200, { ...risk(), new_version: false })
    if (url === '/api/v1/analyses') return json(200, [summaryRow(), summaryRow({ id: 'an2', combined_level: null, combined_score: null })])
    if (url.startsWith('/api/v1/analytics/summary')) return json(200, analytics())
    if (url === '/api/v1/investigations') return json(200, [{ id: 'c1', case_number: 'CASE-1', status: 'open', analyses: [{ analysis_id: 'an1' }], evidence_policy: { store_mode: 'hash_only', retention_days: 30, key_required: false, note: '' } }])
    if (url.startsWith('/api/v1/investigations/c1/report/an1')) return new Response(new Blob(['%PDF']), { status: 200 })
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})

describe('dashboard Risk tab', () => {
  it('viewer reads the risk tab without a recompute button', async () => {
    setSession(sessionFor('viewer'))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={noop} />, 'viewer'))
    fireEvent.click(screen.getByRole('tab', { name: 'Risk' }))
    await screen.findByTestId('risk-panel')
    expect(screen.queryByTestId('risk-recompute')).toBeNull()
    await waitFor(() => expect(screen.getByTestId('strip-risk').textContent).toContain('60'))
  })

  it('analyst recomputes, opens an older version, and the PDF pins the shown risk version', async () => {
    setSession(sessionFor('analyst'))
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:z'), revokeObjectURL: vi.fn() }))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={noop} />, 'analyst'))
    fireEvent.click(screen.getByRole('tab', { name: 'Risk' }))
    fireEvent.click(await screen.findByTestId('risk-recompute'))
    await screen.findByText('Recomputed: no change, so no new version was stored.')
    const post = calls.find((c) => c.url.endsWith('/risk/recompute'))!
    expect(post.init.method).toBe('POST')
    fireEvent.change(screen.getByLabelText('Combined risk version'), { target: { value: '1' } })
    await waitFor(() => expect(screen.getByTestId('risk-headline').textContent).toContain('critical'))
    await waitFor(() => expect(calls.some((c) => c.url === '/api/v1/investigations')).toBe(true))
    await new Promise((r) => setTimeout(r, 0))
    fireEvent.click(screen.getByText('Download forensic PDF'))
    await waitFor(() => expect(calls.some((c) => c.url.includes('/report/an1'))).toBe(true))
    expect(calls.find((c) => c.url.includes('/report/an1'))!.url).toContain('risk_id=r1')
  })
})

describe('History, Overview and Analytics', () => {
  it('History shows the combined level next to the unchanged rule verdict', async () => {
    render(withRole(<HistoryPage onOpenAnalysis={noop} />, 'viewer'))
    const table = await screen.findByRole('table', { name: 'Analyses' })
    expect(within(table).getByText('Combined risk')).toBeTruthy()
    expect(within(table).getByText('critical 100')).toBeTruthy()
    expect(within(table).getByText('not computed')).toBeTruthy()
    expect(within(table).getAllByText('phishing fraud likely').length).toBe(2)
  })

  it('Overview recent analyses include the combined level', async () => {
    render(withRole(<OverviewPage onOpenAnalysis={noop} />, 'analyst'))
    const table = await screen.findByRole('table', { name: 'Recent analyses' })
    await waitFor(() => expect(within(table).getByText('critical 100')).toBeTruthy())
  })

  it('Analytics renders the combined-level distribution with a text summary', async () => {
    render(withRole(<AnalyticsPage />, 'viewer'))
    await screen.findByTestId('analytics-page')
    const chart = screen.getAllByTestId('chart').find((c) => (c.getAttribute('aria-label') ?? '').startsWith('Combined risk level per analysis'))
    expect(chart).toBeTruthy()
    expect(chart!.getAttribute('aria-label')).toContain('critical 2')
    expect(screen.getByText('Combined risk levels (index, not a probability)')).toBeTruthy()
  })
})
