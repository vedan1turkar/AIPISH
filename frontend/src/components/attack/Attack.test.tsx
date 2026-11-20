// @vitest-environment jsdom
// P5d frontend: ATT&CK tab rendering, badges, empty state, evidence navigation, source type, roles, PDF pin.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import AttackPanel, { groupByTactic } from './AttackPanel'
import ResultsDashboard from '../ResultsDashboard'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'
import type { AnalysisDetail, AttackMappingResult } from '../../api/client'

const DISC = 'ATT&CK mappings and source-type hypotheses ... never identify a person, group or physical location.'

function result(over: Partial<AttackMappingResult> = {}): AttackMappingResult {
  return {
    mapping_id: 'm1', analysis_id: 'an1', version: 2, source: 'recompute', created_at: '2026-11-20T10:00:00Z',
    engine_version: 'attack-engine-1.0', catalog_version: 'aipish-attack-catalog-1', attack_version: '20.1',
    catalog_verified: true,
    inputs: { intel_run_id: 'run12345abc', intel_run_version: 1, intel_simulated: true, ml_assessment_id: null },
    mappings: [
      { technique_id: 'T1657', name: 'Financial Theft', tactics: ['Impact'], url: 'https://attack.mitre.org/techniques/T1657',
        basis: 'inferred', confidence: 'medium', evidence_ids: ['A1'], supporting_evidence_ids: ['A3'],
        rationale: 'The message asks for a payment.', mapping_rule_id: 'M07_financial_theft', limitations: 'Shows intent only.' },
      { technique_id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactics: ['Initial Access'],
        url: 'https://attack.mitre.org/techniques/T1566/001', basis: 'observed', confidence: 'high', evidence_ids: ['A2'],
        supporting_evidence_ids: [], rationale: 'A risky attachment is present.', mapping_rule_id: 'M01_attachment_delivery', limitations: null },
      { technique_id: 'T1585.002', name: 'Establish Accounts: Email Accounts', tactics: ['Resource Development'],
        url: 'https://attack.mitre.org/techniques/T1585/002', basis: 'inferred', confidence: 'low', evidence_ids: ['A1'],
        supporting_evidence_ids: [], rationale: 'Replies redirected.', mapping_rule_id: 'M11_reply_mailbox', limitations: null },
    ],
    empty_state: null,
    source_type: [
      { hypothesis: 'spoofed_domain', label: 'Possible spoofed sender domain', band: 'possible', evidence_ids: ['A2'],
        rationale: 'One signal.', missing_data: ['Single signal only.'] },
      { hypothesis: 'anonymised_infrastructure', label: 'Anonymised sending infrastructure', band: 'not_assessed',
        evidence_ids: [], rationale: 'Not assessed.', missing_data: ['x'], reason: 'threat-intel lookup was not run for this analysis' },
    ],
    evidence: [
      { id: 'A1', kind: 'rule_finding', category: 'heuristic', source_field: 'detection.findings[1]', statement: 'Rule payment_diversion', tab: 'findings' },
      { id: 'A2', kind: 'attachment', category: 'verified', source_field: 'attachments[0]', statement: 'Attachment inv.docm', tab: 'overview' },
      { id: 'A3', kind: 'ml', category: 'model', source_field: 'assessment[x].ml', statement: 'ML label fraud', tab: 'ai' },
    ],
    disclaimer: DISC, note: 'ATT&CK describes intrusion tradecraft and only approximates business-email-compromise.',
    ...over,
  }
}

const noop = () => {}
const panel = (props: Partial<Parameters<typeof AttackPanel>[0]> = {}) => (
  <AttackPanel data={result()} loading={false} error={null} history={[]} canRecompute={false} recomputing={false}
               recomputeError={null} onRecompute={noop} onSelectVersion={noop} {...props} />
)

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  clearSession()
})

describe('ATT&CK panel', () => {
  it('groups techniques by tactic in ATT&CK order with official links, text badges and confidence', () => {
    render(panel())
    const groups = screen.getAllByTestId('tactic-group').map((g) => g.querySelector('h4')!.textContent)
    expect(groups).toEqual(['Resource Development', 'Initial Access', 'Impact'])
    const link = screen.getByText('T1566.001') as HTMLAnchorElement
    expect(link.href).toBe('https://attack.mitre.org/techniques/T1566/001')
    expect(link.target).toBe('_blank')
    expect(link.rel).toContain('noopener')
    const badges = screen.getAllByTestId('basis-badge').map((b) => b.textContent)
    expect(badges).toEqual(['Inferred', 'Observed', 'Inferred'])     // text, not colour alone
    expect(screen.getByText('Limitation: Shows intent only.')).toBeTruthy()
    expect(screen.getByText(/Supporting \(not basis\)/)).toBeTruthy()
    expect(screen.getByTestId('attack-disclaimer').textContent).toBe(DISC)
    expect(document.body.textContent).toContain('Enterprise 20.1')
    expect(document.body.textContent).toContain('IDs verified against official data')
    expect(document.body.textContent).toContain('SIMULATED provider data')
  })

  it('source type: not-assessed hypotheses show their reason, never "not indicated"', () => {
    render(panel())
    const rows = screen.getAllByTestId('hypothesis')
    const anon = rows.find((r) => r.textContent?.includes('Anonymised'))!
    expect(within(anon).getByTestId('band').textContent).toBe('Not assessed: threat-intel lookup was not run for this analysis')
    expect(anon.textContent).not.toMatch(/not indicated/i)
    expect(within(rows[0]).getByTestId('band').textContent).toBe('Possible')
  })

  it('evidence chips navigate to the cited evidence, and evidence opens its dashboard tab', () => {
    const onNavigate = vi.fn()
    render(panel({ onNavigate }))
    const target = document.getElementById('evidence-A2')!
    const chip = screen.getAllByLabelText('Go to evidence A2')[0]
    expect(chip.getAttribute('href')).toBe('#evidence-A2')
    fireEvent.click(chip)
    expect(target.getAttribute('data-highlighted')).toBe('true')
    fireEvent.click(within(screen.getAllByTestId('attack-evidence')[0]).getByTestId('evidence-open-tab'))
    expect(onNavigate).toHaveBeenCalledWith('findings')
  })

  it('empty state, loading, error and role-aware recompute', () => {
    const { rerender } = render(panel({ data: result({ mappings: [], empty_state: 'No ATT&CK techniques could be mapped from the available evidence.' }) }))
    expect(screen.getByText('No ATT&CK techniques could be mapped from the available evidence.')).toBeTruthy()
    expect(screen.queryByTestId('attack-recompute')).toBeNull()
    const onRecompute = vi.fn()
    rerender(panel({ canRecompute: true, onRecompute }))
    fireEvent.click(screen.getByTestId('attack-recompute'))
    expect(onRecompute).toHaveBeenCalled()
    rerender(panel({ loading: true }))
    expect(screen.getByText('Loading ATT&CK mapping…')).toBeTruthy()
    rerender(panel({ error: 'boom' }))
    expect(screen.getByText(/Could not load the ATT&CK mapping: boom/)).toBeTruthy()
  })

  it('groupByTactic is stable and puts unknown tactics last', () => {
    const g = groupByTactic([{ ...result().mappings[0], tactics: ['Weird'] }, result().mappings[1]])
    expect(g.map(([t]) => t)).toEqual(['Initial Access', 'Weird'])
  })
})

// ── dashboard integration with a stubbed backend ─────────────────────────
const calls: { url: string; init: RequestInit }[] = []
function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
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

beforeEach(() => {
  calls.length = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    const m = (init.method ?? 'GET').toUpperCase()
    if (url === '/api/v1/analyses/an1/attack' && m === 'GET') return json(200, result())
    if (url === '/api/v1/analyses/an1/attack/history') return json(200, [{ mapping_id: 'm1', version: 2, source: 'recompute', created_at: null, technique_count: 3, intel_run_id: null }, { mapping_id: 'm0', version: 1, source: 'auto', created_at: null, technique_count: 1, intel_run_id: null }])
    if (url === '/api/v1/analyses/an1/attack?version=1') return json(200, result({ mapping_id: 'm0', version: 1, mappings: [] , empty_state: 'No ATT&CK techniques could be mapped from the available evidence.'}))
    if (url === '/api/v1/analyses/an1/attack/recompute') return json(200, { ...result(), new_version: false })
    if (url === '/api/v1/investigations') return json(200, [{ id: 'c1', case_number: 'CASE-1', status: 'open', analyses: [{ analysis_id: 'an1' }], evidence_policy: { store_mode: 'hash_only', retention_days: 30, key_required: false, note: '' } }])
    if (url.startsWith('/api/v1/investigations/c1/report/an1')) return new Response(new Blob(['%PDF']), { status: 200 })
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})

function openTab() {
  fireEvent.click(screen.getByRole('tab', { name: /ATT&CK/ }))
}

describe('dashboard ATT&CK tab', () => {
  it('viewer reads the mapping but gets no recompute button', async () => {
    setSession(sessionFor('viewer'))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={noop} />, 'viewer'))
    openTab()
    await screen.findByTestId('attack-panel')
    expect(screen.queryByTestId('attack-recompute')).toBeNull()
    expect(screen.getAllByTestId('attack-technique')).toHaveLength(3)
  })

  it('analyst recomputes, can open an older version, and the PDF pins the shown mapping', async () => {
    setSession(sessionFor('analyst'))
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:z'), revokeObjectURL: vi.fn() }))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={noop} />, 'analyst'))
    openTab()
    fireEvent.click(await screen.findByTestId('attack-recompute'))
    await screen.findByText('Recomputed: no change, so no new version was stored.')
    const post = calls.find((c) => c.url.endsWith('/attack/recompute'))!
    expect(post.init.method).toBe('POST')
    expect(new Headers(post.init.headers).get('Authorization')).toBe('Bearer test-token-analyst')
    fireEvent.change(screen.getByLabelText('ATT&CK mapping version'), { target: { value: '1' } })
    await screen.findByText('No ATT&CK techniques could be mapped from the available evidence.')
    await waitFor(() => expect(calls.some((c) => c.url === '/api/v1/investigations')).toBe(true))
    await new Promise((r) => setTimeout(r, 0))
    fireEvent.click(screen.getByText('⬇ Download forensic PDF'))
    await waitFor(() => expect(calls.some((c) => c.url.includes('/report/an1'))).toBe(true))
    const pdf = calls.find((c) => c.url.includes('/report/an1'))!
    expect(pdf.url).toContain('attack_id=m0')
  })

  it('a 404 "not computed" shows the empty state with recompute for analysts', async () => {
    setSession(sessionFor('analyst'))
    vi.stubGlobal('fetch', vi.fn(async (url: string) =>
      url.endsWith('/attack') ? json(404, { error: { code: 'ATTACK_NOT_COMPUTED', message: 'x' } }) : json(404, { error: { code: 'NOT_FOUND', message: 'x' } })))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={noop} />, 'analyst'))
    openTab()
    await screen.findByText('No ATT&CK mapping has been computed yet')
    expect(screen.getByTestId('attack-recompute')).toBeTruthy()
  })
})
