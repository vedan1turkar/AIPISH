// @vitest-environment jsdom
/**
 * P5a Threat-intel UI: every status renders distinctly (text + icon, not colour
 * alone), "no record" is never worded as clean or safe, stale/fresh cache
 * labels, consent gating, duplicate-click protection, empty/error states,
 * untrusted provider strings rendered as text, and PDF pinning of the run shown.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { AnalysisDetail, IntelResult, IntelServiceStatus, ThreatIntelRun } from '../../api/client'
import ThreatIntelPanel, { INTEL_DISCLAIMER, IntelStatusChip } from './ThreatIntelPanel'
import { INTEL_STATUS_META, factsFor } from './model'

vi.mock('../../api/client', async (orig) => {
  const actual = await orig<typeof import('../../api/client')>()
  return {
    ...actual,
    getAssessment: vi.fn(),
    listAssessments: vi.fn(),
    getMlStatus: vi.fn(),
    getLlmStatus: vi.fn(),
    createInvestigation: vi.fn(),
    downloadReport: vi.fn(),
    getThreatIntel: vi.fn(),
    getIntelStatus: vi.fn(),
    runThreatIntel: vi.fn(),
  }
})
import * as api from '../../api/client'
import ResultsDashboard from '../ResultsDashboard'
import { withRole } from '../../test/auth'

const mocked = api as unknown as Record<string, ReturnType<typeof vi.fn>>

const ALL_STATUSES = [
  'malicious_or_flagged', 'reported_clean_no_flags', 'record_found', 'no_record', 'provider_error', 'rate_limited',
  'auth_failed', 'timeout', 'malformed_response', 'not_permitted', 'not_attempted_consent_disabled',
  'not_attempted_offline', 'not_attempted_cap_reached', 'missing_credentials', 'not_applicable_indicator',
  'quota_exhausted',
]

function result(over: Partial<IntelResult> = {}): IntelResult {
  return {
    provider: 'abuseipdb', provider_label: 'AbuseIPDB', indicator: '8.8.8.8', indicator_type: 'ip',
    status: 'no_record', fetched_at: '2026-11-20T10:00:00+00:00', expires_at: '2026-11-21T10:00:00+00:00',
    cache_state: 'none', source: 'AbuseIPDB API v2 GET /check', data: {}, error_code: null,
    message: 'AbuseIPDB: no reports found in the last 90 days. This is not proof of safety.',
    cache_age_seconds: null, retry_after_seconds: null, ...over,
  }
}

function run(over: Partial<ThreatIntelRun> = {}): ThreatIntelRun {
  return {
    run_id: 'run1', analysis_id: 'an1', version: 2, created_at: '2026-11-20T10:00:00+00:00',
    consent: { granted: true, decided_at: '2026-11-20T10:00:00+00:00', source: 'on_demand', providers: ['abuseipdb'] },
    offline: false, simulated: false, informational_only: true, ioc_cap: 20,
    counts: { total: 3, eligible: 2, looked_up: 1, rejected: 1, cap_skipped: 1 },
    indicators: [
      {
        indicator: '8.8.8.8', indicator_type: 'ip', origins: ['earliest candidate origin IP'], eligible: true,
        state: 'looked_up', rejection_reason: null,
        results: [
          result({ status: 'malicious_or_flagged', cache_state: 'stale', cache_age_seconds: 30 * 3600,
                   message: 'STALE cached result from 30 h ago — live lookup failed (timeout).',
                   data: { abuse_confidence_score: 87, total_reports: 12, isp: '<img src=x onerror=alert(1)>' } }),
          result({ provider: 'tor_exit_list', provider_label: 'Tor exit list', status: 'no_record', cache_state: 'fresh',
                   message: 'Not in the Tor exit list snapshot. This is not proof of safety.',
                   data: { listed: false, list_size: 1200 } }),
        ],
      },
      {
        indicator: '10.0.0.9', indicator_type: 'ip', origins: ['URL host'], eligible: false,
        state: 'not_applicable_indicator', rejection_reason: 'private (RFC 1918 / ULA) address',
        message: 'Not looked up: private (RFC 1918 / ULA) address. Never sent to any provider.', results: [],
      },
      {
        indicator: 'late-domain.net', indicator_type: 'domain', origins: ['Reply-To domain'], eligible: true,
        state: 'not_attempted_cap_reached', rejection_reason: null,
        message: 'Not looked up: per-analysis indicator cap reached. (cap 20)', results: [],
      },
    ],
    provider_summary: { abuseipdb: { malicious_or_flagged: 1 }, tor_exit_list: { no_record: 1 } },
    not_configured: { maxmind_geoip2: 'MaxMind GeoIP2 — not configured', misp: 'MISP — not configured' },
    disclaimer: 'x',
    ...over,
  }
}

const STATUS: IntelServiceStatus = {
  offline: false, simulated: false, consent_required: true, consent_default: false, max_iocs_per_analysis: 20,
  informational_only: true,
  providers: {
    virustotal: { label: 'VirusTotal', configured: true, enabled: true, requires_credentials: true },
    abuseipdb: { label: 'AbuseIPDB', configured: true, enabled: true, requires_credentials: true },
    shodan: { label: 'Shodan', configured: false, enabled: false, requires_credentials: true },
    ipinfo: { label: 'IPinfo', configured: true, enabled: false, requires_credentials: true },
    tor_exit_list: { label: 'Tor exit list', configured: true, enabled: true, requires_credentials: false },
    misp: { label: 'MISP', configured: false, enabled: false, requires_credentials: true, note: 'out of scope' },
  },
}

function panel(props: Partial<Parameters<typeof ThreatIntelPanel>[0]> = {}) {
  const onRun = vi.fn()
  render(
    <ThreatIntelPanel run={null} status={STATUS} loading={false} error={null} running={false} runError={null}
                      onRun={onRun} {...props} />,
  )
  return onRun
}

afterEach(() => cleanup())

describe('status chips', () => {
  it('render every status with its own label and icon, never colour alone', () => {
    const labels = new Set<string>()
    for (const s of ALL_STATUSES) {
      expect(INTEL_STATUS_META[s], s).toBeDefined()
      const { container, unmount } = render(<IntelStatusChip status={s} />)
      const chip = container.querySelector(`[data-status="${s}"]`)!
      expect(chip.textContent).toContain(INTEL_STATUS_META[s].label)
      expect(chip.textContent).toContain(INTEL_STATUS_META[s].icon)
      expect(chip.getAttribute('title')).toBeTruthy()
      labels.add(INTEL_STATUS_META[s].label)
      unmount()
    }
    expect(labels.size).toBe(ALL_STATUSES.length)
  })

  it('never words no-record or no-flags as clean or safe', () => {
    for (const s of ['no_record', 'reported_clean_no_flags', 'record_found', 'not_applicable_indicator']) {
      const m = INTEL_STATUS_META[s]
      const text = `${m.label} ${m.hint}`.toLowerCase().replace('not proof of safety', '')
      expect(text, s).not.toMatch(/\bclean\b|\bsafe\b|\bbenign\b|\btrusted\b/)
    }
    expect(INTEL_STATUS_META.no_record.hint).toContain('not proof of safety')
    expect(INTEL_STATUS_META.reported_clean_no_flags.hint).toContain('not proof of safety')
  })
})

describe('ThreatIntelPanel', () => {
  it('shows the persistent disclaimer, empty state and provider chips when no run exists', () => {
    panel()
    expect(screen.getByRole('note').textContent).toContain(INTEL_DISCLAIMER)
    expect(screen.getByText('No threat-intel lookup has been run')).toBeTruthy()
    const chips = screen.getByRole('list', { name: 'Provider configuration' })
    expect(within(chips).getByText(/Shodan: not configured/)).toBeTruthy()
    expect(within(chips).getByText(/IPinfo: disabled/)).toBeTruthy()
    expect(within(chips).getByText(/VirusTotal: ready/)).toBeTruthy()
  })

  it('requires explicit consent before running; decline records the decision', () => {
    const onRun = panel()
    const runBtn = screen.getByRole('button', { name: 'Run threat intel lookup' }) as HTMLButtonElement
    expect(runBtn.disabled).toBe(true)
    fireEvent.click(screen.getByRole('checkbox'))
    expect(runBtn.disabled).toBe(false)
    fireEvent.click(runBtn)
    expect(onRun).toHaveBeenCalledWith(true)
    fireEvent.click(screen.getByRole('button', { name: /Decline external lookups/ }))
    expect(onRun).toHaveBeenCalledWith(false)
  })

  it('disables both actions while running and shows loading', () => {
    panel({ running: true })
    expect((screen.getByRole('button', { name: 'Running lookups…' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: /Decline/ }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(/Running threat-intel lookups/)).toBeTruthy()
  })

  it('shows load and run errors', () => {
    panel({ error: 'boom', runError: 'provider run failed' })
    expect(screen.getByText(/Could not load threat-intel results: boom/)).toBeTruthy()
    expect(screen.getByText('provider run failed')).toBeTruthy()
  })

  it('renders indicator cards with stale/fresh labels, facts and not-looked-up states', () => {
    const { container } = render(
      <ThreatIntelPanel run={run()} status={STATUS} loading={false} error={null} running={false} runError={null}
                        onRun={vi.fn()} />,
    )
    const card = container.querySelector('[data-indicator="8.8.8.8"]')! as HTMLElement
    const abuse = card.querySelector('[data-provider="abuseipdb"]') as HTMLElement
    expect(within(abuse).getByText(/STALE cache · 30 h old/)).toBeTruthy()
    expect(within(abuse).getByText('87')).toBeTruthy()
    const tor = card.querySelector('[data-provider="tor_exit_list"]') as HTMLElement
    expect(within(tor).getByText('Cached (fresh)')).toBeTruthy()
    expect(within(tor).getByText('No record / no reports')).toBeTruthy()
    expect(tor.textContent!.toLowerCase()).not.toMatch(/\bclean\b|\bsafe\b(?! *\.)/)
    expect(container.querySelector('[data-indicator="10.0.0.9"]')!.textContent).toContain('Never sent to any provider')
    expect(container.querySelector('[data-indicator="late-domain.net"]')!.textContent).toContain('cap reached')
    expect(screen.getByText(/1 over the cap of 20/)).toBeTruthy()
  })

  it('renders provider-supplied strings as inert text', () => {
    const { container } = render(
      <ThreatIntelPanel run={run()} status={STATUS} loading={false} error={null} running={false} runError={null}
                        onRun={vi.fn()} />,
    )
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeTruthy()
  })

  it('labels declined consent and simulated data', () => {
    const declined = run({
      simulated: true,
      consent: { granted: false, decided_at: '2026-11-20T10:00:00+00:00', source: 'on_demand', providers: [] },
    })
    panel({ run: declined })
    expect(screen.getByText(/External lookups were declined for this run/)).toBeTruthy()
    expect(screen.getByText(/SIMULATED providers/)).toBeTruthy()
    expect(screen.getByText('declined')).toBeTruthy()
  })

  it('shows unavailable anonymity fields as unavailable, not "no"', () => {
    const facts = factsFor(result({ provider: 'ipinfo', data: { is_vpn: 'unavailable', is_tor: false, country: 'US' } }))
    expect(facts).toContainEqual(['VPN', 'unavailable'])
    expect(facts).toContainEqual(['Tor', 'no'])
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
                 verified_originating_ip: null, inconsistencies: [], confidence_rules: [], forgery_note: '',
                 disclaimer: '' },
    authentication: {}, enrichment: { results: [], degraded: [] }, parse_defects: [],
  } as unknown as AnalysisDetail
}

describe('dashboard integration', () => {
  beforeEach(() => {
    for (const f of Object.values(mocked)) if (typeof f?.mockReset === 'function') f.mockReset()
    mocked.getAssessment.mockResolvedValue(null)
    mocked.listAssessments.mockResolvedValue([])
    mocked.getMlStatus.mockRejectedValue(new Error('x'))
    mocked.getLlmStatus.mockRejectedValue(new Error('x'))
    mocked.getIntelStatus.mockResolvedValue(STATUS)
  })

  it('blocks duplicate clicks, stores the run and pins it in the PDF', async () => {
    mocked.getThreatIntel.mockResolvedValue(null)
    let resolve!: (r: ThreatIntelRun) => void
    mocked.runThreatIntel.mockReturnValue(new Promise<ThreatIntelRun>((r) => { resolve = r }))
    mocked.createInvestigation.mockResolvedValue({ id: 'case1' })
    mocked.downloadReport.mockResolvedValue(undefined)
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />))
    fireEvent.click(screen.getByRole('tab', { name: /Threat intel/ }))
    await waitFor(() => expect(screen.getByText('No threat-intel lookup has been run')).toBeTruthy())
    fireEvent.click(screen.getByRole('checkbox'))
    const btn = screen.getByRole('button', { name: 'Run threat intel lookup' })
    fireEvent.click(btn)
    fireEvent.click(btn)
    fireEvent.click(btn)
    expect(mocked.runThreatIntel).toHaveBeenCalledTimes(1)
    expect(mocked.runThreatIntel).toHaveBeenCalledWith('an1', { consent: true, source: 'on_demand' })
    resolve(run())
    await waitFor(() => expect(screen.getByText(/Run v2/)).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /Download forensic PDF/ }))
    await waitFor(() => expect(mocked.downloadReport).toHaveBeenCalledWith('case1', 'an1', null, 'run1'))
  })

  it('shows a 409 in-progress message without inventing results', async () => {
    mocked.getThreatIntel.mockResolvedValue(null)
    mocked.runThreatIntel.mockRejectedValue(new api.ApiError(409, 'INTEL_IN_PROGRESS', 'busy'))
    render(withRole(<ResultsDashboard analysis={analysis()} onNewAnalysis={() => {}} />))
    fireEvent.click(screen.getByRole('tab', { name: /Threat intel/ }))
    await waitFor(() => expect(screen.getByText('No threat-intel lookup has been run')).toBeTruthy())
    fireEvent.click(screen.getByRole('button', { name: /Decline external lookups/ }))
    await waitFor(() => expect(screen.getByText(/already running/)).toBeTruthy())
    expect(screen.getByText('No threat-intel lookup has been run')).toBeTruthy()
  })
})
