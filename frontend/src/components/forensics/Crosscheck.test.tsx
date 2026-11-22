// @vitest-environment jsdom
// P5k-lite frontend: parser cross-check panel states, HTML report download (pins, roles, errors), axe.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'
import ParserCrosscheckPanel, { CROSSCHECK_EXPLAINER } from './ParserCrosscheckPanel'
import ResultsDashboard from '../ResultsDashboard'
import { clearSession, setSession } from '../../auth/session'
import { sessionFor, withRole } from '../../test/auth'
import type { AnalysisDetail, ParserCrosscheck } from '../../api/client'

const base: ParserCrosscheck = {
  status: 'agree', primary: 'python email (policy=default)', secondary: 'mail-parser', secondary_version: '4.10.0',
  differences: [], compared: { received_hops: [4, 4], attachments: [1, 1], body_parts: [2, 2] }, note: 'n',
}
function analysis(over: Partial<AnalysisDetail> = {}): AnalysisDetail {
  return {
    id: 'an1', created_at: '2026-11-22T09:00:00+00:00', sha256: 'f'.repeat(64), size_bytes: 1, subject: 's',
    from: null, to: [], cc: [], reply_to: [], return_path: null, date: null, message_id: null, received_count: 0,
    authentication_results: [], dkim_signature_count: 0, has_html_body: false, body_text: '', urls: [],
    attachments: [], header_counts: {},
    detection: { score: 100, verdict: 'phishing_fraud_likely', findings: [], unknowns: [] },
    forensics: { relay_chain: [], trusted_boundary_index: null, candidate_ips: [], earliest_candidate_ip: null,
                 verified_originating_ip: null, inconsistencies: [], confidence_rules: [], forgery_note: '', disclaimer: '' },
    authentication: {}, enrichment: { results: [], degraded: [] }, parse_defects: [], parser_crosscheck: base, ...over,
  } as unknown as AnalysisDetail
}

afterEach(() => { cleanup(); clearSession(); vi.unstubAllGlobals() })

describe('ParserCrosscheckPanel', () => {
  it('agree: status text, compared counts, explainer saying it does not change the score', () => {
    render(<ParserCrosscheckPanel analysis={analysis()} />)
    const p = screen.getByTestId('parser-crosscheck')
    expect(screen.getByText('agree')).toBeTruthy()
    expect(p.textContent).toContain('hops 4 / 4')
    expect(p.textContent).toContain('Both parsers produced the same normalised view')
    expect(p.textContent).toContain(CROSSCHECK_EXPLAINER)
    expect(CROSSCHECK_EXPLAINER).toContain('does not change the score')
  })

  it('security-relevant differences table; unavailable reason; redacted; not recorded', () => {
    const diffs: ParserCrosscheck = { ...base, status: 'security_relevant_differences', differences: [
      { field: 'duplicate_header:from', severity: 'security_relevant', description: "Single-instance header 'from' appears 2 times.", evidence_id: 'P1' },
      { field: 'charsets', severity: 'info', description: 'Declared body charsets differ between parsers.', evidence_id: 'P2' }] }
    const { rerender } = render(<ParserCrosscheckPanel analysis={analysis({ parser_crosscheck: diffs })} />)
    expect(screen.getByText('security-relevant differences')).toBeTruthy()
    const t = screen.getByRole('table', { name: 'Parser differences' })
    expect(within(t).getAllByRole('row')).toHaveLength(3)
    expect(within(t).getByText('security relevant')).toBeTruthy()
    rerender(<ParserCrosscheckPanel analysis={analysis({ parser_crosscheck: { ...base, status: 'unavailable', compared: null,
      reason: 'cross-check unavailable: mail-parser could not be imported (ImportError)' } })} />)
    expect(screen.getByText(/could not be imported/)).toBeTruthy()
    rerender(<ParserCrosscheckPanel analysis={analysis({ retention_state: 'redacted' })} />)
    expect(screen.getByText('Parser cross-check: redacted per retention policy.')).toBeTruthy()
    rerender(<ParserCrosscheckPanel analysis={analysis({ parser_crosscheck: null })} />)
    expect(screen.getByText(/Not recorded for this analysis/)).toBeTruthy()
  })

  it('axe clean', async () => {
    const { container } = render(<ParserCrosscheckPanel analysis={analysis({ parser_crosscheck: { ...base, status: 'minor_differences',
      differences: [{ field: 'duplicate_header:date', severity: 'info', description: 'd', evidence_id: 'P1' }] } })} />)
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations).toEqual([])
  })
})

const calls: { url: string; init: RequestInit }[] = []
function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}
let htmlStatus = 200
beforeEach(() => {
  calls.length = 0
  htmlStatus = 200
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: vi.fn(() => 'blob:h'), revokeObjectURL: vi.fn() }))
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url, init })
    if (url === '/api/v1/analyses/an1/risk') return json(200, { risk_id: 'r7', version: 3, level: 'high', combined_score: 80, confidence: 'medium',
      agreement: 'agree', conflict: null, flags: [], components: [], evidence: [], explanation: [], disclaimers: [],
      inputs: { ml_source: { kind: null, id: null, model_version: null, status: 'not_run' } }, bands: { edges: {}, ml_thresholds: {} } })
    if (url.startsWith('/api/v1/analyses/an1/report.html')) {
      return htmlStatus === 200 ? new Response(new Blob(['<!doctype html>']), { status: 200 })
        : json(htmlStatus, { error: { code: 'EVIDENCE_KEY_REQUIRED', message: 'Configured policy requires a valid X-Evidence-Key header.' } })
    }
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})

describe('HTML report download', () => {
  it('viewer can download; request pins the shown risk version and carries the bearer token', async () => {
    setSession(sessionFor('viewer'))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />, 'viewer'))
    await waitFor(() => expect(screen.getByTestId('strip-risk').textContent).toContain('80'))
    fireEvent.click(screen.getByTestId('download-html'))
    await waitFor(() => expect(calls.some((c) => c.url.includes('/report.html'))).toBe(true))
    const c = calls.find((x) => x.url.includes('/report.html'))!
    expect(c.url).toBe('/api/v1/analyses/an1/report.html?risk_id=r7')
    expect(new Headers(c.init.headers).get('Authorization')).toBe('Bearer test-token-viewer')
  })

  it('errors are shown, the button is re-enabled', async () => {
    htmlStatus = 401
    setSession(sessionFor('analyst'))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />, 'analyst'))
    fireEvent.click(screen.getByTestId('download-html'))
    await screen.findByText(/X-Evidence-Key/)
    expect((screen.getByTestId('download-html') as HTMLButtonElement).disabled).toBe(false)
  })
})
