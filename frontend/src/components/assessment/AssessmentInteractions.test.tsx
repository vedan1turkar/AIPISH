// @vitest-environment jsdom
/**
 * Interaction tests (DOM) for the AI-assessment UI: evidence navigation by
 * mouse and keyboard, duplicate-submit prevention, loading/failure/retry,
 * version history vs latest, PDF version pinning, and no fabricated success.
 * The API client is mocked; fixtures mirror real backend responses.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { AnalysisDetail, Assessment, AssessmentSummary } from '../../api/client'
import real from './__fixtures__/assessment_ok.json'
import { AssessmentView, SummaryPanel, EvidencePanel } from './AssessmentPanels'

vi.mock('../../api/client', async (orig) => {
  const actual = await orig<typeof import('../../api/client')>()
  return {
    ...actual,
    getAssessment: vi.fn(),
    listAssessments: vi.fn(),
    getAssessmentVersion: vi.fn(),
    generateAssessment: vi.fn(),
    getMlStatus: vi.fn(),
    getLlmStatus: vi.fn(),
    createInvestigation: vi.fn(),
    downloadReport: vi.fn(),
    verifyIntegrity: vi.fn(),
    getThreatIntel: vi.fn(),
    getIntelStatus: vi.fn(),
    runThreatIntel: vi.fn(),
  }
})
import * as api from '../../api/client'
import ResultsDashboard from '../ResultsDashboard'
import { withRole } from '../../test/auth'

const OK = real as unknown as Assessment
const v = (n: number, id: string): Assessment => ({ ...JSON.parse(JSON.stringify(OK)), version: n, assessment_id: id })
const summary = (a: Assessment): AssessmentSummary => ({
  assessment_id: a.assessment_id!, version: a.version!, source: 'upload', generated_at: '2026-11-19T18:00:00+00:00',
  ml_status: 'ok', ml_label: 'fraud', summary_status: 'ok',
})
const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>

function analysis(): AnalysisDetail {
  return {
    id: 'an1', created_at: '2026-11-19T18:00:00Z', sha256: 'a'.repeat(64), size_bytes: 10, subject: 'Urgent wire',
    from: null, to: [], cc: [], reply_to: [], return_path: null, date: null, message_id: null, received_count: 0,
    authentication_results: [], dkim_signature_count: 0, has_html_body: false, body_text: null, urls: [],
    attachments: [], header_counts: {},
    detection: { score: 100, verdict: 'phishing_fraud_likely', findings: [], unknowns: [], observed_facts: [] },
    forensics: { relay_chain: [], trusted_boundary_index: null, candidate_ips: [], earliest_candidate_ip: null,
      verified_originating_ip: null, inconsistencies: [], confidence_rules: [], forgery_note: '', disclaimer: '' },
    authentication: {
      spf: { protocol: 'spf', status: 'parsed', claims: [], reason: null, detail: {} },
      dkim: { protocol: 'dkim', status: 'parsed', claims: [], reason: null, detail: {} },
      dmarc: { protocol: 'dmarc', status: 'unknown', claims: [], reason: null, detail: {} },
      alignment: {}, status_legend: {},
    },
    enrichment: { results: [], degraded: [] }, parse_defects: [],
  }
}

beforeEach(() => {
  Element.prototype.scrollIntoView = vi.fn()
  vi.useRealTimers()
  for (const f of Object.values(mocked)) if (typeof f?.mockReset === 'function') f.mockReset()
  mocked.getMlStatus.mockResolvedValue({ status: 'ok', ensemble_weights: { lr: 0, transformer: 0.5, xgb: 0.5 } })
  mocked.getLlmStatus.mockResolvedValue({ status: 'ok', model: 'mistral:latest' })
  mocked.getThreatIntel.mockResolvedValue(null)
  mocked.getIntelStatus.mockRejectedValue(new Error('not needed'))
})
afterEach(() => cleanup())

describe('evidence navigation', () => {
  function renderSummaryAndEvidence() {
    return render(
      <div>
        <SummaryPanel fs={OK.forensic_summary} />
        <EvidencePanel fs={OK.forensic_summary} />
      </div>,
    )
  }

  it('clicking an evidence ID scrolls to, focuses and highlights the right row without changing the URL', () => {
    renderSummaryAndEvidence()
    const before = window.location.href
    const finding = OK.forensic_summary!.findings![0]
    const target = finding.evidence_ids[finding.evidence_ids.length - 1]
    const chip = within(screen.getAllByTestId('summary-finding')[0]).getByRole('link', { name: `Go to evidence ${target}` })
    fireEvent.click(chip)
    const row = document.getElementById(`evidence-${target}`)!
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(1)
    expect((Element.prototype.scrollIntoView as ReturnType<typeof vi.fn>).mock.contexts[0]).toBe(row)
    expect(row.getAttribute('data-highlighted')).toBe('true')
    expect(row.className).toContain('ring-indigo-400')
    expect(document.activeElement).toBe(row)
    expect(window.location.href).toBe(before)
  })

  it('works from the keyboard (Enter and Space)', () => {
    renderSummaryAndEvidence()
    const before = window.location.href
    const chips = screen.getAllByRole('link', { name: /Go to evidence E/ })
    chips[0].focus()
    fireEvent.keyDown(chips[0], { key: 'Enter' })
    fireEvent.keyDown(chips[1], { key: ' ' })
    expect(Element.prototype.scrollIntoView).toHaveBeenCalledTimes(2)
    expect(window.location.href).toBe(before)
  })

  it('the highlight is removed again', () => {
    vi.useFakeTimers()
    renderSummaryAndEvidence()
    const chip = screen.getAllByRole('link', { name: /Go to evidence E/ })[0]
    fireEvent.click(chip)
    const id = chip.textContent!
    expect(document.getElementById(`evidence-${id}`)!.getAttribute('data-highlighted')).toBe('true')
    act(() => vi.advanceTimersByTime(2000))
    expect(document.getElementById(`evidence-${id}`)!.getAttribute('data-highlighted')).toBeNull()
    vi.useRealTimers()
  })
})

describe('generation, history and PDF version through the dashboard', () => {
  async function openAiTab() {
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => undefined} />))
    fireEvent.click(screen.getByRole('tab', { name: /AI assessment/ }))
  }

  it('prevents duplicate submissions while running, then shows the new version', async () => {
    mocked.getAssessment.mockResolvedValue(null)
    mocked.listAssessments.mockResolvedValue([])
    let resolve!: (a: Assessment) => void
    mocked.generateAssessment.mockImplementation(() => new Promise<Assessment>((r) => (resolve = r)))
    await openAiTab()
    const btn = await screen.findByTestId('generate-button')
    fireEvent.click(btn)
    fireEvent.click(btn)
    fireEvent.click(btn)
    expect(mocked.generateAssessment).toHaveBeenCalledTimes(1)
    expect((screen.getByTestId('generate-button') as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByTestId('generating').textContent).toContain('1–2 minutes')
    expect(screen.getByTestId('generating').textContent).not.toMatch(/\d+%/)          // no invented percentage
    const v1 = v(1, 'id-v1')
    mocked.listAssessments.mockResolvedValue([summary(v1)])
    await act(async () => resolve(v1))
    expect((await screen.findByTestId('assessment-version')).textContent).toContain('Version v1')
    expect(screen.queryByTestId('generating')).toBeNull()
  })

  it('clicks fired in the same task (before React re-renders) still send only one request', async () => {
    mocked.getAssessment.mockResolvedValue(null)
    mocked.listAssessments.mockResolvedValue([])
    let resolve!: (a: Assessment) => void
    mocked.generateAssessment.mockImplementation(() => new Promise<Assessment>((r) => (resolve = r)))
    await openAiTab()
    const btn = await screen.findByTestId('generate-button')
    act(() => {
      btn.click()
      btn.click()
      btn.click()
    })
    expect(mocked.generateAssessment).toHaveBeenCalledTimes(1)
    await act(async () => resolve(v(1, 'id-v1')))
    expect(screen.queryByTestId('generate-error')).toBeNull()
    expect((await screen.findByTestId('assessment-version')).textContent).toContain('Version v1')
  })

  it('failure shows an error with retry and keeps the rule-based tabs usable', async () => {
    mocked.getAssessment.mockResolvedValue(null)
    mocked.listAssessments.mockResolvedValue([])
    mocked.generateAssessment.mockRejectedValueOnce(new api.ApiError(0, 'NETWORK_ERROR', 'Cannot reach the analysis backend.'))
    await openAiTab()
    fireEvent.click(await screen.findByTestId('generate-button'))
    expect((await screen.findByTestId('generate-error')).textContent).toContain('rule-based analysis is unaffected')
    expect(screen.queryByText('Version v1')).toBeNull()
    mocked.generateAssessment.mockResolvedValueOnce(v(1, 'id-v1'))
    fireEvent.click(within(screen.getByTestId('generate-error')).getByRole('button', { name: 'Retry' }))
    expect((await screen.findByTestId('assessment-version')).textContent).toContain('Version v1')
    fireEvent.click(screen.getByRole('tab', { name: /Overview/ }))
    expect(screen.getByText('Verdict')).toBeTruthy()
  })

  it('409 in-progress is explained, not treated as success', async () => {
    mocked.getAssessment.mockResolvedValue(null)
    mocked.listAssessments.mockResolvedValue([])
    mocked.generateAssessment.mockRejectedValueOnce(
      new api.ApiError(409, 'ASSESSMENT_IN_PROGRESS', 'already being generated'))
    await openAiTab()
    fireEvent.click(await screen.findByTestId('generate-button'))
    expect((await screen.findByTestId('generate-error')).textContent).toContain('already being generated')
    expect(screen.queryByTestId('assessment-version')).toBeNull()
  })

  it('history: latest is shown by default, an earlier version can be opened and is labelled, and the PDF uses it', async () => {
    const v1 = v(1, 'id-v1')
    const v2 = v(2, 'id-v2')
    v2.forensic_summary!.assessment = 'Second-version assessment text.'
    mocked.getAssessment.mockResolvedValue(v2)
    mocked.listAssessments.mockResolvedValue([summary(v2), summary(v1)])
    mocked.getAssessmentVersion.mockResolvedValue(v1)
    mocked.createInvestigation.mockResolvedValue({ id: 'case1', case_number: 'C-1', status: 'open', analyses: [],
      evidence_policy: { store_mode: 'hash_only', key_required: false, retention_days: 30, note: '' } })
    mocked.downloadReport.mockResolvedValue(undefined)
    await openAiTab()
    expect((await screen.findByTestId('assessment-version')).textContent).toContain('Version v2 (latest)')
    expect(screen.getByText('Second-version assessment text.')).toBeTruthy()
    expect(screen.queryByTestId('old-version-banner')).toBeNull()

    fireEvent.change(screen.getByTestId('version-select'), { target: { value: 'id-v1' } })
    await waitFor(() => expect((screen.getByTestId('assessment-version')).textContent).toContain('Version v1'))
    expect(mocked.getAssessmentVersion).toHaveBeenCalledWith('an1', 'id-v1')
    expect((screen.getByTestId('assessment-version')).textContent).not.toContain('(latest)')
    expect((screen.getByTestId('old-version-banner')).textContent).toContain('The latest is v2')
    expect(screen.queryByText('Second-version assessment text.')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: /Download forensic PDF/ }))
    await waitFor(() => expect(mocked.downloadReport).toHaveBeenCalledWith('case1', 'an1', 'id-v1'))
  })

  it('missing API data never becomes a success state', async () => {
    mocked.getAssessment.mockResolvedValue({ analysis_id: 'an1', assessment_id: 'x', version: 1, ml: null,
      explanation: null, forensic_summary: null })
    mocked.listAssessments.mockResolvedValue([])
    await openAiTab()
    await screen.findByTestId('assessment-version')
    const statuses = screen.getAllByTestId('run-status').map((e) => e.getAttribute('data-status'))
    expect(statuses).toEqual(['missing', 'missing', 'missing'])
    expect(screen.queryByText('Completed')).toBeNull()
    expect(screen.queryByText(/Predicted class/)).toBeNull()
  })

  it('a failed history request does not hide the latest assessment', async () => {
    mocked.getAssessment.mockResolvedValue(v(3, 'id-v3'))
    mocked.listAssessments.mockRejectedValue(new Error('boom'))
    await openAiTab()
    expect((await screen.findByTestId('assessment-version')).textContent).toContain('Version v3')
    expect(screen.queryByTestId('version-select')).toBeNull()
  })
})

describe('AssessmentView generating state (component level)', () => {
  it('shows real elapsed seconds and disables the button', () => {
    render(<AssessmentView assessment={null} loading={false} error={null} generating generateError={null}
      onGenerate={() => undefined} elapsedSeconds={42} />)
    expect((screen.getByTestId('elapsed')).textContent).toContain('42s')
    expect((screen.getByTestId('generate-button') as HTMLButtonElement).disabled).toBe(true)
  })
})
