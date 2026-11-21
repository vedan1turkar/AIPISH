// Infrastructure geolocation surface (P5g) for an analysis (Geo tab) or a campaign (aggregated).
// Data comes only from stored results (no lookups). Every state shows the mandatory disclaimer.
import { Suspense, lazy, useEffect, useMemo, useState } from 'react'
import {
  getAnalysisGeo, getCampaignGeo, type AnalysisGeo, type AnonymityRow, type CampaignGeo, type GeoPoint, type GeoUnlocated,
} from '../../api/client'
import { useAuth } from '../../auth/AuthContext'
import { DataTable, EmptyLine, ErrorAlert, KV, LED, Panel, SkeletonRows, StatusTag, formatDate } from '../ui'
import { ROLE_COLOR } from '../graph/style'
import { GEO_DISCLAIMER, MAP_ATTRIBUTION, ROLE_LABEL, ROLES, SIGNALS, SIGNAL_LABEL } from './labels'

const GeoMap = lazy(() => import('./GeoMap'))

type Row = (GeoPoint | GeoUnlocated) & { located: boolean }

export function Disclaimer({ text }: { text?: string }) {
  return (
    <p className="flex items-start gap-2 border-l-2 border-warn-line bg-surface px-3 py-1.5 text-sm text-muted" data-testid="geo-disclaimer">
      <LED tone="warn" className="mt-1.5" />{text || GEO_DISCLAIMER}
    </p>
  )
}

export function Flags({ simulated, stale }: { simulated?: boolean; stale?: boolean }) {
  if (!simulated && !stale) return null
  return (
    <span className="inline-flex gap-1">
      {simulated && <StatusTag tone="warn" title="Synthetic demo data, not a provider result">SIMULATED demo data</StatusTag>}
      {stale && <StatusTag tone="warn" title="Served from an expired provider cache">stale</StatusTag>}
    </span>
  )
}

function RoleSwatch({ role }: { role: string }) {
  return <span aria-hidden className="inline-block h-2.5 w-2.5 shrink-0 rotate-45 border border-bg" style={{ backgroundColor: ROLE_COLOR[role] }} />
}

function where(r: { city?: string | null; region?: string | null; country?: string | null }): string {
  return [r.city, r.region, r.country].filter(Boolean).join(', ')
}

function SelectedIp({ row, isCampaign }: { row: Row | null; isCampaign: boolean }) {
  if (!row) return <EmptyLine>Select an IP on the map or in the table to see its details.</EmptyLine>
  const p = row as GeoPoint
  return (
    <>
    <dl>
      <KV label="IP" mono>{row.ip}</KV>
      <KV label="Role">
        <span className="inline-flex items-center gap-2"><RoleSwatch role={row.role} />
          {row.roles.map((r) => ROLE_LABEL[r]).join(', ')}</span>
      </KV>
      {!isCampaign && row.hop != null && <KV label="Relay hop" mono>{row.hop}</KV>}
      {row.via_host && <KV label="Resolved from" mono>{row.via_host}</KV>}
      {isCampaign && <KV label="Members" mono>{row.member_count ?? 0}</KV>}
      <KV label="Location">{row.located ? (where(p) || 'country unknown') : 'no location data'}</KV>
      {row.located && <KV label="Coordinates" mono>{p.lat.toFixed(2)}, {p.lon.toFixed(2)} (approximate)</KV>}
      <KV label="ASN / org" mono>{[row.asn, row.org].filter(Boolean).join(' · ') || 'not available'}</KV>
      <KV label="Source">{row.source || 'none stored'}</KV>
      {row.located && <KV label="Fetched" mono>{p.fetched_at ? formatDate(p.fetched_at) : 'unknown'}</KV>}
      {row.located && (p.simulated || p.stale) && <KV label="Flags"><Flags simulated={p.simulated} stale={p.stale} /></KV>}
    </dl>
    {row.located && p.accuracy_note && <p className="pt-2 text-sm text-muted">{p.accuracy_note}</p>}
    </>
  )
}

function AnonymityTable({ rows }: { rows: AnonymityRow[] }) {
  return (
    <DataTable<AnonymityRow>
      label="Anonymity signals"
      rows={rows}
      rowKey={(r) => r.ip}
      empty="No public IPs to assess."
      columns={[
        { key: 'ip', header: 'IP', mono: true, className: 'whitespace-nowrap', render: (r) => r.ip },
        { key: 'role', header: 'Role', className: 'whitespace-nowrap text-muted', render: (r) => ROLE_LABEL[r.role] },
        ...SIGNALS.map((s) => ({
          key: s, header: SIGNAL_LABEL[s], className: 'whitespace-nowrap',
          render: (r: AnonymityRow) => {
            const v = r.signals[s]
            if (v.value === null) return <span className="text-muted">not available</span>
            return <StatusTag tone={v.value ? 'warn' : 'neutral'} title={v.source ?? undefined}>{v.value ? 'reported' : 'not reported'}</StatusTag>
          },
        })),
        { key: 'src', header: 'Source', className: 'w-full text-muted', render: (r) => {
          const srcs = Array.from(new Set(Object.values(r.signals).map((x) => x.source).filter(Boolean)))
          return <span className="inline-flex flex-wrap items-center gap-2">{srcs.join(' · ') || 'no stored provider data'}<Flags simulated={r.simulated} /></span>
        } },
      ]}
    />
  )
}

export default function GeoPanel({ kind, id }: { kind: 'analysis' | 'campaign'; id: string }) {
  const { can } = useAuth()
  const [data, setData] = useState<AnalysisGeo | CampaignGeo | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [showOrder, setShowOrder] = useState(false)
  useEffect(() => {
    const ctl = new AbortController()
    setData(null)
    setError(null)
    setSelected(null)
    const load = kind === 'analysis' ? getAnalysisGeo(id, ctl.signal) : getCampaignGeo(id, ctl.signal)
    load.then((g) => {
      setData(g)
      // preselect the first IP (origin candidate first) so its facts are visible without a click
      setSelected(g.points[0]?.ip ?? g.unlocated[0]?.ip ?? null)
    }).catch((err) => {
      if (!(err instanceof DOMException && err.name === 'AbortError'))
        setError(err instanceof Error ? err.message : 'Could not load location data.')
    })
    return () => ctl.abort()
  }, [kind, id])

  const rows: Row[] = useMemo(() => !data ? [] : [
    ...data.points.map((p) => ({ ...p, located: true })),
    ...data.unlocated.map((u) => ({ ...u, located: false })),
  ], [data])
  const isCampaign = kind === 'campaign'
  const sel = rows.find((r) => r.ip === selected) ?? null
  const relayOrder = data && 'relay_order' in data ? data.relay_order : []

  if (error) return <div className="space-y-3"><Disclaimer /><ErrorAlert message={`Location data could not be loaded: ${error}`} /></div>
  if (!data) {
    return (
      <div className="space-y-3"><Disclaimer />
        <Panel title="Infrastructure map"><SkeletonRows rows={6} label="Loading location data…" /></Panel>
      </div>
    )
  }

  const noIps = rows.length === 0
  const noPoints = data.points.length === 0
  const hint = can('intel:run')
    ? 'No stored location data for these IPs. Run a threat-intel lookup with consent (Threat intel tab) to obtain locations.'
    : 'No stored location data for these IPs. An analyst can run a consented threat-intel lookup to obtain locations.'

  return (
    <div className="space-y-4" data-testid="geo-panel">
      <Disclaimer text={data.disclaimer} />
      {noIps ? (
        <Panel title="Infrastructure map">
          <EmptyLine>
            {isCampaign
              ? 'No public IP addresses are recorded for this campaign’s members.'
              : 'No public IP addresses are recorded for this message (no public relay hop, origin candidate or IP URL host), so there is nothing to place on a map.'}
          </EmptyLine>
        </Panel>
      ) : (
        <div className="grid items-start gap-4 xl:grid-cols-12">
          <Panel title="Infrastructure map" className="xl:col-span-8 xl:self-stretch" bodyClassName="p-0 flex flex-col"
                 status={<span className="inline-flex items-center gap-2"><Flags simulated={data.provenance.simulated_present} stale={data.provenance.stale_present} />
                   <span className="font-mono text-xs">{data.points.length} located · {data.unlocated.length} without location</span></span>}>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line px-3 py-1.5 text-sm text-muted">
              <ul className="flex flex-wrap items-center gap-x-4 gap-y-1" aria-label="Marker roles">
                {ROLES.map((r) => <li key={r} className="flex items-center gap-1.5"><RoleSwatch role={r} />{ROLE_LABEL[r]}</li>)}
              </ul>
              {!isCampaign && relayOrder.length > 1 && (
                <label className="ml-auto flex items-center gap-2">
                  <input type="checkbox" className="accent-[var(--accent)]" checked={showOrder} onChange={(e) => setShowOrder(e.target.checked)} />
                  Show relay order <span className="text-xs">(relay order, not a physical route)</span>
                </label>
              )}
            </div>
            <div className="relative min-h-[380px] flex-1 bg-bg">
              {noPoints ? (
                <div className="flex h-full min-h-[380px] items-center justify-center p-4"><EmptyLine>{hint}</EmptyLine></div>
              ) : (
                <Suspense fallback={<div className="p-3"><SkeletonRows rows={6} label="Loading map…" /></div>}>
                  <GeoMap points={data.points} selected={selected} onSelect={setSelected} relayOrder={relayOrder}
                          showRelayOrder={showOrder} label={isCampaign ? 'Campaign infrastructure map' : 'Infrastructure map'} />
                </Suspense>
              )}
            </div>
            <p className="border-t border-line px-3 py-1 font-mono text-xs text-muted">{MAP_ATTRIBUTION}</p>
          </Panel>
          <div className="space-y-4 xl:col-span-4">
            <Panel title={`IP addresses (${rows.length})`} bodyClassName="p-0">
              <DataTable<Row>
                label="IP addresses"
                rows={rows}
                rowKey={(r) => r.ip}
                maxHeight="16rem"
                rowTestId={() => 'geo-row'}
                columns={[
                  { key: 'ip', header: 'IP', render: (r) => (
                    <button type="button" onClick={() => setSelected(r.ip)} aria-pressed={r.ip === selected}
                            className={`inline-flex items-center gap-2 font-mono text-sm hover:text-accent ${r.ip === selected ? 'text-accent' : 'text-fg'}`}>
                      <RoleSwatch role={r.role} />{r.ip}
                    </button>) },
                  { key: 'where', header: 'Location', className: 'max-w-0 w-full', render: (r) => (
                    <span className={`block truncate ${r.located ? '' : 'text-muted'}`}>
                      {r.located ? (where(r as GeoPoint) || 'country unknown') : 'no location data'}
                    </span>) },
                  ...(isCampaign ? [{ key: 'n', header: 'Msgs', align: 'right' as const, mono: true, render: (r: Row) => r.member_count ?? 0 }]
                    : [{ key: 'hop', header: 'Hop', align: 'right' as const, mono: true, render: (r: Row) => r.hop ?? '—' }]),
                ]}
              />
            </Panel>
            <Panel title="Selected IP"><SelectedIp row={sel} isCampaign={isCampaign} /></Panel>
          </div>
        </div>
      )}
      {!isCampaign && 'anonymity' in data && data.anonymity.length > 0 && (
        <Panel title="Anonymity signals (Tor / VPN / proxy / relay / hosting)" bodyClassName="p-0"
               status={<span className="text-xs">shown only when a stored provider result backs them</span>}>
          <AnonymityTable rows={data.anonymity} />
        </Panel>
      )}
    </div>
  )
}
