// @vitest-environment jsdom
// P5g: geo panel (map mocked), GeoMap (Leaflet mocked), analytics page (Plotly mocked), roles, axe.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import axe from 'axe-core'
import type { AnalysisGeo, AnalyticsSummary, GeoPoint } from '../../api/client'

const plotly = vi.hoisted(() => ({ react: vi.fn(() => Promise.resolve()), purge: vi.fn(), Plots: { resize: vi.fn() } }))
vi.mock('plotly.js-basic-dist-min', () => ({ default: plotly }))

const leaflet = vi.hoisted(() => {
  const added: { kind: string; args: unknown[] }[] = []
  const layer = (kind: string, args: unknown[]) => {
    const l = { addTo: vi.fn(() => { added.push({ kind, args }); return l }), remove: vi.fn(), on: vi.fn(), setIcon: vi.fn() }
    return l
  }
  const map = {
    fitWorld: vi.fn(), setView: vi.fn(), fitBounds: vi.fn(), remove: vi.fn(), invalidateSize: vi.fn(),
    getBounds: () => ({ contains: () => true }), panTo: vi.fn(), setZoom: vi.fn(), getZoom: () => 2,
  }
  return {
    added, map,
    mod: {
      map: vi.fn(() => map), svg: vi.fn(), geoJSON: vi.fn((...a: unknown[]) => layer('geojson', a)),
      marker: vi.fn((...a: unknown[]) => layer('marker', a)), polyline: vi.fn((...a: unknown[]) => layer('polyline', a)),
      divIcon: vi.fn((o: unknown) => o), latLngBounds: vi.fn(() => ({ pad: () => ({}) })),
    },
  }
})
vi.mock('leaflet', () => ({ default: leaflet.mod }))
vi.mock('leaflet/dist/leaflet.css', () => ({}))

import GeoPanel from './GeoPanel'
import GeoMap from './GeoMap'
import AnalyticsPage from '../analytics/AnalyticsPage'
import { GEO_DISCLAIMER } from './labels'
import { withRole } from '../../test/auth'

let routes: [RegExp, () => Response][] = []
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
beforeEach(() => {
  routes = []
  leaflet.added.length = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    for (const [p, f] of routes) if (p.test(url)) return f()
    return json(404, { error: { code: 'NOT_FOUND', message: 'nf' } })
  }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

const pt = (ip: string, o: Partial<GeoPoint> = {}): GeoPoint => ({
  ip, role: 'origin_candidate', roles: ['origin_candidate'], hops: [0], hop: 0, via_host: null, lat: 50.1, lon: 8.7,
  country: 'DE', region: 'Hesse', city: 'Frankfurt am Main', asn: 'AS64500', org: 'SIMULATED Hosting', isp: null,
  source: 'SIMULATED demo data (synthetic)', provider: 'simulated-demo', fetched_at: '2026-11-21T10:00:00+00:00',
  stale: false, simulated: true, accuracy_note: 'Approximate: …', ...o,
})
const none = { value: null, source: null }
const geo = (o: Partial<AnalysisGeo> = {}): AnalysisGeo => ({
  analysis_id: 'a1', disclaimer: GEO_DISCLAIMER, accuracy_note: 'x', relay_order_label: 'relay order, not a physical route',
  points: [pt('96.7.128.175'), pt('185.220.101.1', { role: 'trusted_relay', roles: ['trusted_relay'], hop: 3, hops: [3], simulated: false, stale: true, source: 'IPinfo (consented threat-intel run)' })],
  unlocated: [{ ip: '151.101.1.69', role: 'untrusted_relay', roles: ['untrusted_relay'], hops: [2], hop: 2, reason: 'no location data' }],
  anonymity: [
    { ip: '96.7.128.175', role: 'origin_candidate', simulated: false, any_data: false,
      signals: { tor: none, vpn: none, proxy: none, relay: none, hosting: none } },
    { ip: '185.220.101.1', role: 'trusted_relay', simulated: false, any_data: true,
      signals: { tor: { value: true, source: 'Tor bulk exit list' }, vpn: { value: false, source: 'IPinfo privacy flags' }, proxy: none, relay: none, hosting: none } },
  ],
  relay_order: ['96.7.128.175', '185.220.101.1'],
  counts: { ips: 3, located: 2, unlocated: 1 },
  provenance: { lookups_performed: false, intel_run: null, enrichment_geo: false, simulated_present: true, stale_present: true, sources: [] },
  ...o,
})

describe('GeoPanel', () => {
  it('map + synchronized table + selection + flags + anonymity "not available" vs reported', async () => {
    routes.push([/\/analyses\/a1\/geo$/, () => json(200, geo())])
    render(withRole(<GeoPanel kind="analysis" id="a1" />, 'viewer'))
    await screen.findByTestId('geo-panel')
    expect(screen.getByTestId('geo-disclaimer').textContent).toBe(GEO_DISCLAIMER)
    expect(screen.getAllByTestId('geo-row')).toHaveLength(3)
    expect(screen.getByText('no location data')).toBeTruthy()
    expect(screen.getAllByText('SIMULATED demo data').length).toBeGreaterThan(0)
    expect(screen.getAllByText('stale').length).toBeGreaterThan(0)
    await screen.findByTestId('geo-map')                                        // lazy chunk mounted
    fireEvent.click(within(screen.getByRole('table', { name: 'IP addresses' })).getByRole('button', { name: /185\.220\.101\.1/ }))
    const sel = screen.getByRole('region', { name: 'Selected IP' })
    expect(sel.textContent).toContain('IPinfo (consented threat-intel run)')
    expect(sel.textContent).toContain('trusted relay')
    const anon = screen.getByRole('table', { name: 'Anonymity signals' })
    const rows = within(anon).getAllByRole('row')
    expect(rows[1].textContent).toContain('not available')
    expect(rows[1].textContent).not.toContain('not reported')                   // absent data is never "no"
    expect(rows[2].textContent).toContain('reported')
  })

  it('relay order line is off by default and labelled as not a physical route', async () => {
    routes.push([/\/analyses\/a1\/geo$/, () => json(200, geo())])
    render(withRole(<GeoPanel kind="analysis" id="a1" />, 'viewer'))
    const box = await screen.findByRole('checkbox', { name: /Show relay order/ })
    expect((box as HTMLInputElement).checked).toBe(false)
    expect(box.closest('label')?.textContent).toContain('relay order, not a physical route')
  })

  it('no public IPs: one clean line, disclaimer still shown', async () => {
    routes.push([/\/geo$/, () => json(200, geo({ points: [], unlocated: [], anonymity: [], relay_order: [] }))])
    render(withRole(<GeoPanel kind="analysis" id="a1" />, 'viewer'))
    await screen.findByText(/No public IP addresses are recorded for this message/)
    expect(screen.getByTestId('geo-disclaimer')).toBeTruthy()
    expect(screen.queryByTestId('geo-map')).toBeNull()
  })

  it('IPs without stored locations: role-aware hint, no map', async () => {
    const body = geo({ points: [], relay_order: [] })
    routes.push([/\/geo$/, () => json(200, body)])
    const r = render(withRole(<GeoPanel kind="analysis" id="a1" />, 'analyst'))
    await screen.findByText(/Run a threat-intel lookup with consent/)
    expect(screen.queryByTestId('geo-map')).toBeNull()
    r.unmount()
    render(withRole(<GeoPanel kind="analysis" id="a1" />, 'viewer'))
    await screen.findByText(/An analyst can run a consented threat-intel lookup/)
  })

  it('error state keeps the disclaimer', async () => {
    routes.push([/\/geo$/, () => json(500, { error: { code: 'X', message: 'geo store offline' } })])
    render(withRole(<GeoPanel kind="campaign" id="c1" />, 'viewer'))
    expect((await screen.findByRole('alert')).textContent).toContain('geo store offline')
    expect(screen.getByTestId('geo-disclaimer').textContent).toBe(GEO_DISCLAIMER)
  })

  it('campaign view: member counts, no anonymity table, axe clean', async () => {
    routes.push([/\/campaigns\/c1\/geo$/, () => json(200, {
      campaign_id: 'c1', disclaimer: GEO_DISCLAIMER, accuracy_note: 'x',
      points: [{ ...pt('96.7.128.175'), member_count: 4, members: ['a', 'b', 'c', 'd'] }], unlocated: [],
      counts: { members: 4, located: 1, unlocated: 0, truncated: false },
      provenance: { lookups_performed: false, simulated_present: true, stale_present: false, sources: [] },
    })])
    const { container } = render(withRole(<GeoPanel kind="campaign" id="c1" />, 'viewer'))
    await screen.findByTestId('geo-map')
    const table = screen.getByRole('table', { name: 'IP addresses' })
    expect(within(table).getByRole('columnheader', { name: 'Msgs' })).toBeTruthy()
    expect(within(table).getAllByRole('row')[1].textContent).toContain('4')
    expect(screen.queryByRole('table', { name: 'Anonymity signals' })).toBeNull()
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations.map((v) => v.id)).toEqual([])
  })
})

describe('GeoMap (Leaflet mocked)', () => {
  it('vector outline only, one diamond marker per point with hop labels, relay line only when toggled on', () => {
    const points = [pt('96.7.128.175'), pt('185.220.101.1', { hop: 3, role: 'trusted_relay' })]
    const { rerender } = render(<GeoMap points={points} selected={null} onSelect={() => {}} relayOrder={['96.7.128.175', '185.220.101.1']} label="Map" />)
    expect(leaflet.mod.map).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ zoomControl: false, attributionControl: false }))
    expect(leaflet.added.filter((a) => a.kind === 'geojson')).toHaveLength(1)      // no tile layer exists
    expect(leaflet.added.filter((a) => a.kind === 'marker')).toHaveLength(2)
    const html = leaflet.mod.divIcon.mock.calls.map((c) => (c[0] as { html: string }).html).join(' ')
    expect(html).toContain('geo-diamond')
    expect(html).toContain('>3<')
    expect(leaflet.added.some((a) => a.kind === 'polyline')).toBe(false)
    rerender(<GeoMap points={points} selected={null} onSelect={() => {}} relayOrder={['96.7.128.175', '185.220.101.1']} showRelayOrder label="Map" />)
    const line = leaflet.added.find((a) => a.kind === 'polyline')
    expect(line).toBeTruthy()
    expect((line!.args[1] as { dashArray: string }).dashArray).toBe('4 4')
    expect(screen.getByRole('button', { name: 'Fit to screen' })).toBeTruthy()
  })
})

const summary = (o: Partial<AnalyticsSummary> = {}): AnalyticsSummary => ({
  generated_at: '2026-11-21T10:00:00Z',
  window: { days: 30, since: '2026-10-23', total_analyses: 8, analyses_considered: 8, capped: false, max_window: 2000 },
  verdicts: [{ verdict: 'phishing_fraud_likely', count: 5 }, { verdict: 'minimal', count: 3 }],
  ml_classes: [{ label: 'impersonated', count: 1 }, { label: 'not_assessed', count: 7 }],
  per_day: Array.from({ length: 30 }, (_, i) => ({ date: `2026-11-${String(i + 1).padStart(2, '0')}`, count: i === 29 ? 8 : 0 })),
  score_histogram: [{ bucket: '0-9', count: 3 }, { bucket: '90-100', count: 5 }],
  top_sender_domains: [{ domain: 'outlook.com', count: 5, generic: true }, { domain: 'evil.test', count: 1, generic: false }],
  geo: { coverage: { with_geo: 7, analyses_considered: 8 }, basis: 'x', simulated_present: true,
         countries: [{ country: 'DE', count: 4 }], asns: [{ asn: 'AS64500', count: 4 }] },
  attack_techniques: [{ technique_id: 'T1566.001', name: 'Spearphishing Attachment', count: 2 }],
  campaigns: { by_status: { candidate: 1 }, candidate_size_distribution: [{ bucket: '4', count: 1 }], candidates: 1 },
  intel_coverage: { analyses_with_consented_lookups: 0, analyses_considered: 8, runs_total: 0, simulated_runs: 0 },
  ...o,
})

describe('Analytics page (Plotly mocked)', () => {
  it('loading, charts via lazy Plotly, coverage note, SIMULATED tag, generic domain label, table toggle', async () => {
    let release!: (r: Response) => void
    routes.push([/\/analytics\/summary\?days=30$/, () => new Promise<Response>((res) => { release = res }) as unknown as Response])
    render(withRole(<AnalyticsPage />, 'viewer'))
    expect(screen.getAllByLabelText('Loading analytics…').length).toBeGreaterThan(0)
    release(json(200, summary()))
    await screen.findByTestId('analytics-page')
    await waitFor(() => expect(plotly.react).toHaveBeenCalled())
    expect(screen.getByText('7 / 8')).toBeTruthy()
    expect(screen.getAllByText('SIMULATED demo data').length).toBeGreaterThan(0)
    const charts = screen.getAllByTestId('chart')
    expect(charts.every((c) => c.getAttribute('role') === 'img' && (c.getAttribute('aria-label') ?? '').length > 20)).toBe(true)
    const domainsCall = (plotly.react.mock.calls as unknown[][]).find((c) => JSON.stringify(c[1]).includes('outlook.com (generic)'))
    expect(domainsCall).toBeTruthy()
    const layout = (plotly.react.mock.calls[0] as unknown[])[2] as { paper_bgcolor: string }
    expect(layout.paper_bgcolor).toBe('rgba(0,0,0,0)')
    fireEvent.click(screen.getByRole('button', { name: 'Show data table for Top sender domains' }))
    const t = screen.getByRole('table', { name: 'Top sender domains data' })
    expect(t.textContent).toContain('outlook.com (generic)')
  })

  it('empty charts show one line; window selector refetches', async () => {
    routes.push([/days=30$/, () => json(200, summary({ attack_techniques: [], geo: { coverage: { with_geo: 0, analyses_considered: 8 }, basis: 'x', simulated_present: false, countries: [], asns: [] } }))])
    routes.push([/days=7$/, () => json(200, summary({ window: { ...summary().window, days: 7 } }))])
    render(withRole(<AnalyticsPage />, 'viewer'))
    await screen.findByText('No ATT&CK mappings stored yet.')
    expect(screen.getByText(/No stored location data/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Analytics window'), { target: { value: '7' } })
    await screen.findByText('Analyses per day (last 7 days)')
  })

  it('error state and axe', async () => {
    routes.push([/analytics/, () => json(500, { error: { code: 'X', message: 'aggregates offline' } })])
    render(withRole(<AnalyticsPage />, 'viewer'))
    expect((await screen.findByRole('alert')).textContent).toContain('aggregates offline')
  })

  it('axe: analytics page has no violations', async () => {
    routes.push([/analytics/, () => json(200, summary())])
    const { container } = render(withRole(<AnalyticsPage />, 'viewer'))
    await screen.findByTestId('analytics-page')
    const res = await axe.run(container, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`)).toEqual([])
  })
})
