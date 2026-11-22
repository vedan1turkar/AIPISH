// Alerts page (P5f): inbox of risk-based alerts with filters, server pagination, detail, history and
// acknowledge / resolve (note required) / reopen for analysts. Admins also see the effective configuration.
import { useCallback, useEffect, useState } from 'react'
import {
  ApiError, alertAction, getAlert, getAlertConfig, getAlertsSummary, getCampaign, listAlerts,
  type AlertConfigView, type AlertDetail, type AlertFilters, type AlertItem, type AlertList, type AlertsSummary,
} from '../../api/client'
import { useAuth } from '../../auth/AuthContext'
import {
  Button, DataTable, EmptyLine, ErrorAlert, Field, KV, LED, Panel, Select, SkeletonRows, StatCell, StatusTag, formatDate,
} from '../ui'
import { RiskLevelTag } from '../risk/level'
import { ALERT_HONESTY, AlertStatusTag, SeverityTag, subjectHref, subjectText } from './shared'

const PAGE_SIZE = 25
const TYPES: [string, string][] = [
  ['high_risk_analysis', 'High-risk analysis'], ['hard_evidence_floor', 'Hard-evidence floor'],
  ['review_conflict', 'Rules/ML conflict'], ['new_campaign', 'New campaign'], ['campaign_growth', 'Campaign growth'],
]
const human = (s: string) => s.replace(/_/g, ' ')

function ResolveDialog({ onCancel, onConfirm, busy }: { onCancel: () => void; onConfirm: (note: string) => void; busy: boolean }) {
  const [note, setNote] = useState('')
  const ok = note.trim().length > 0 && note.length <= 1000
  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-[rgba(10,14,19,0.85)] p-4"
         onKeyDown={(e) => { if (e.key === 'Escape') onCancel() }}>
      <div role="dialog" aria-modal="true" aria-labelledby="resolve-title" className="w-full max-w-[520px] border border-line-strong bg-surface">
        <div className="flex h-8 items-center border-b border-line px-3">
          <h2 id="resolve-title" className="font-mono text-xs uppercase tracking-wider text-muted">Resolve alert</h2>
        </div>
        <div className="space-y-3 p-4 text-sm text-fg">
          <p>Resolving closes the alert. A later recompute at the same level will not reopen it; a higher level opens a new alert.</p>
          <Field label="Resolution note (required, max 1000)">
            <textarea autoFocus value={note} onChange={(e) => setNote(e.target.value)} rows={4} maxLength={1000}
                      aria-label="Resolution note"
                      className="w-full border border-line-strong bg-bg px-2 py-1.5 text-sm text-fg focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent" />
          </Field>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={onCancel}>Cancel</Button>
            <Button variant="primary" disabled={!ok || busy} onClick={() => onConfirm(note.trim())}>{busy ? 'Resolving…' : 'Resolve'}</Button>
          </div>
        </div>
      </div>
    </div>
  )
}

function Detail({ id, canManage, onChanged }: { id: string; canManage: boolean; onChanged: () => void }) {
  const [a, setA] = useState<AlertDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [resolving, setResolving] = useState(false)
  const load = useCallback((signal?: AbortSignal) => getAlert(id, signal).then((d) => { setA(d); setError(null) }).catch((err) => {
    if (!(err instanceof DOMException && err.name === 'AbortError')) setError(err instanceof Error ? err.message : 'Alert could not be loaded.')
  }), [id])
  useEffect(() => { const ctl = new AbortController(); setA(null); void load(ctl.signal); return () => ctl.abort() }, [load])
  // P5z.1: the alert stores the campaign size when it was raised (the growth baseline); show today's size too.
  const campaignId = a?.summary.campaign_id
  const [membersNow, setMembersNow] = useState<number | null>(null)
  useEffect(() => {
    setMembersNow(null)
    if (!campaignId) return
    const ctl = new AbortController()
    getCampaign(campaignId, ctl.signal).then((c) => setMembersNow(c.member_count)).catch(() => undefined)
    return () => ctl.abort()
  }, [campaignId])
  async function act(action: 'acknowledge' | 'resolve' | 'reopen', note?: string) {
    if (!a) return
    setBusy(true)
    try {
      setA(await alertAction(a.id, action, { note, version: a.version }))
      setError(null)
      setResolving(false)
      onChanged()
    } catch (err) {
      setError(err instanceof ApiError && err.status === 409 ? `${err.message} The alert was reloaded.` : err instanceof Error ? err.message : 'Action failed.')
      void load()
    } finally {
      setBusy(false)
    }
  }
  if (error && !a) return <Panel title="Alert"><ErrorAlert message={error} /></Panel>
  if (!a) return <Panel title="Alert"><SkeletonRows rows={6} label="Loading alert…" /></Panel>
  const s = a.summary
  return (
    <Panel title={`Alert ${a.id.slice(0, 8)}`} status={<SeverityTag severity={a.severity} />}>
      <div data-testid="alert-detail">
        <p className="mb-2 text-sm font-medium text-fg">{a.title}</p>
        <dl>
          <KV label="Status"><AlertStatusTag status={a.status} /></KV>
          <KV label="Type">{a.type_label}</KV>
          <KV label="Subject">
            <a href={subjectHref(a)} className="text-accent hover:underline">{subjectText(a)}</a>
            {a.analysis_redacted && <span className="ml-2"><StatusTag tone="warn">redacted</StatusTag></span>}
          </KV>
          {s.combined_level && (
            <KV label="Combined risk">
              <span className="flex flex-wrap items-center gap-2">
                <RiskLevelTag level={s.combined_level} score={s.combined_score} />
                {a.risk_id && a.analysis_id && <span className="font-mono text-xs text-muted">pinned risk v{s.risk_version}</span>}
              </span>
            </KV>)}
          {s.rule_verdict !== undefined && <KV label="Rule verdict">{human(s.rule_verdict ?? 'n/a')}</KV>}
          {s.combined_level && <KV label="ML class">{s.ml_class ?? 'not available'}</KV>}
          {s.floors && <KV label="Floors" mono>{s.floors.length ? s.floors.join(', ') : 'none'}</KV>}
          {s.conflict && <KV label="Conflict">{human(s.conflict)}</KV>}
          {s.campaign_label && (
            <KV label="Campaign">
              {s.campaign_label} · {s.campaign_confidence} · {s.member_count} members when raised
              {membersNow !== null && membersNow !== s.member_count && ` · ${membersNow} now`}
            </KV>)}
          <KV label="Occurrences" mono>{a.occurrence_count}</KV>
          <KV label="First / last seen">{formatDate(a.created_at)} · {formatDate(a.last_seen_at)}</KV>
          {a.acknowledged_by && <KV label="Acknowledged">{a.acknowledged_by} · {formatDate(a.acknowledged_at)}</KV>}
          {a.resolved_by && <KV label="Resolved">{a.resolved_by} · {formatDate(a.resolved_at)}</KV>}
          {a.resolution_note && <KV label="Resolution note">{a.resolution_note}</KV>}
          <KV label="E-mail" mono>{human(a.delivery.email?.status ?? 'n/a')}{a.delivery.email?.reason ? ` · ${a.delivery.email.reason}` : ''}</KV>
        </dl>
        {error && <div className="mt-2"><ErrorAlert message={error} onDismiss={() => setError(null)} /></div>}
        {canManage && (
          <div className="mt-3 flex flex-wrap gap-2" data-testid="alert-actions">
            {a.status === 'new' && <Button size="sm" disabled={busy} onClick={() => void act('acknowledge')}>Acknowledge</Button>}
            {a.status !== 'resolved' && <Button size="sm" variant="primary" disabled={busy} onClick={() => setResolving(true)}>Resolve…</Button>}
            {a.status !== 'new' && <Button size="sm" variant="ghost" disabled={busy} onClick={() => void act('reopen')}>Reopen</Button>}
          </div>
        )}
        <h3 className="mb-1 mt-4 border-b border-line pb-1 font-mono text-xs uppercase tracking-wider text-muted">History</h3>
        <ol className="space-y-1" data-testid="alert-history">
          {a.history.map((h) => (
            <li key={h.id} className="grid grid-cols-[auto_1fr] gap-x-3 text-sm">
              <span className="font-mono text-xs text-muted">{formatDate(h.at)}</span>
              <span>
                <span className="font-medium text-fg">{human(h.action)}</span>
                {h.from_state && h.to_state && <span className="text-muted"> · {h.from_state} → {h.to_state}</span>}
                <span className="text-muted"> · {h.actor ?? 'system'}</span>
                {h.note && <span className="block text-muted">{h.note}</span>}
              </span>
            </li>))}
        </ol>
      </div>
      {resolving && <ResolveDialog busy={busy} onCancel={() => setResolving(false)} onConfirm={(n) => void act('resolve', n)} />}
    </Panel>
  )
}

function ConfigPanel() {
  const [cfg, setCfg] = useState<AlertConfigView | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    const ctl = new AbortController()
    getAlertConfig(ctl.signal).then(setCfg).catch((err) => {
      if (!(err instanceof DOMException && err.name === 'AbortError')) setError(err instanceof Error ? err.message : 'failed')
    })
    return () => ctl.abort()
  }, [])
  return (
    <Panel title="Alert configuration · admin, read-only" status={cfg ? <StatusTag tone={cfg.enabled ? 'ok' : 'neutral'}>{cfg.enabled ? 'enabled' : 'disabled'}</StatusTag> : undefined}>
      {error ? <EmptyLine>Configuration could not be loaded: {error}</EmptyLine> : !cfg ? <SkeletonRows rows={4} label="Loading configuration…" /> : (
        <dl data-testid="alert-config">
          <KV label="Minimum level">{cfg.min_level}</KV>
          <KV label="Floor / conflict">{cfg.floor_alerts ? 'floor on' : 'floor off'} · {cfg.conflict_alerts ? 'conflict on' : 'conflict off'}</KV>
          <KV label="Campaigns">confidence ≥ {cfg.campaign_min_confidence} · growth +{cfg.growth_min_new_members}, debounce {cfg.growth_debounce_minutes} min</KV>
          <KV label="E-mail">{cfg.email.enabled ? (cfg.email.configured ? `on · ≥ ${cfg.email.min_severity} · ${cfg.email.recipients} recipient(s) · ${cfg.email.smtp_security}` : 'on but not configured') : 'off'}</KV>
          <KV label="SMTP" mono>{cfg.email.smtp_host ? `${cfg.email.smtp_host}:${cfg.email.smtp_port}` : 'not set'} · password {cfg.email.smtp_password_set ? 'set' : 'not set'}</KV>
        </dl>)}
    </Panel>
  )
}

export default function AlertsPage({ initialId = null }: { initialId?: string | null }) {
  const { can } = useAuth()
  const canManage = can('alert:manage')
  const [filters, setFilters] = useState<AlertFilters>({ status: 'open' })
  const [page, setPage] = useState(1)
  const [data, setData] = useState<AlertList | null>(null)
  const [summary, setSummary] = useState<AlertsSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(initialId)
  const [tick, setTick] = useState(0)
  useEffect(() => { setSelected(initialId) }, [initialId])
  useEffect(() => {
    const ctl = new AbortController()
    setError(null)
    listAlerts({ ...filters, page, page_size: PAGE_SIZE }, ctl.signal).then(setData).catch((err) => {
      if (!(err instanceof DOMException && err.name === 'AbortError')) setError(err instanceof Error ? err.message : 'Alerts could not be loaded.')
    })
    getAlertsSummary(ctl.signal).then(setSummary).catch(() => undefined)
    return () => ctl.abort()
  }, [filters, page, tick])
  const pick = (id: string) => { setSelected(id); window.history.replaceState(null, '', `#alerts/${id}`) }
  const set = (k: keyof AlertFilters, v: string) => { setPage(1); setFilters((f) => ({ ...f, [k]: v })) }
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1
  return (
    <div className="space-y-4" data-testid="alerts-page">
      <div>
        <h1 className="text-xl font-semibold text-fg">Alerts</h1>
        <p className="flex items-center gap-2 text-sm text-muted" data-testid="alerts-honesty"><LED tone="neutral" />{ALERT_HONESTY}</p>
      </div>
      <section aria-label="Alert totals" className="grid grid-cols-2 divide-x divide-y divide-line border border-line bg-surface md:grid-cols-4 md:divide-y-0">
        <StatCell label="New" value={summary?.by_status.new ?? '…'} tone={summary?.new ? 'danger' : 'ok'} sub="not yet acknowledged" />
        <StatCell label="Acknowledged" value={summary?.by_status.acknowledged ?? '…'} sub="open, being reviewed" />
        <StatCell label="Open critical / high" value={summary ? `${summary.open_by_severity.critical} / ${summary.open_by_severity.high}` : '…'} sub="new + acknowledged" />
        <StatCell label="Resolved" value={summary?.by_status.resolved ?? '…'} sub="closed with a note" />
      </section>
      <div className="grid items-start gap-4 xl:grid-cols-12">
        <Panel title="Alert inbox" className="xl:col-span-8" bodyClassName="p-0"
               status={data ? <span className="font-mono text-xs">{data.total} matching</span> : undefined}>
          <form className="grid gap-3 border-b border-line p-3 md:grid-cols-3" aria-label="Alert filters" onSubmit={(e) => e.preventDefault()}>
            <Field label="Status">
              <Select value={filters.status ?? ''} onChange={(e) => set('status', e.target.value)} aria-label="Status filter">
                <option value="open">open (new + acknowledged)</option><option value="new">new</option>
                <option value="acknowledged">acknowledged</option><option value="resolved">resolved</option><option value="">any</option>
              </Select>
            </Field>
            <Field label="Severity">
              <Select value={filters.severity ?? ''} onChange={(e) => set('severity', e.target.value)} aria-label="Severity filter">
                <option value="">any</option>{['critical', 'high', 'medium', 'low'].map((v) => <option key={v} value={v}>{v}</option>)}
              </Select>
            </Field>
            <Field label="Type">
              <Select value={filters.type ?? ''} onChange={(e) => set('type', e.target.value)} aria-label="Type filter">
                <option value="">any</option>{TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </Select>
            </Field>
          </form>
          {error ? <div className="p-3"><ErrorAlert message={`Alerts could not be loaded: ${error}`} /></div>
            : !data ? <div className="p-3"><SkeletonRows rows={6} label="Loading alerts…" /></div> : (
            <>
              <DataTable<AlertItem>
                label="Alerts"
                rows={data.items}
                rowKey={(a) => a.id}
                rowTestId={() => 'alert-row'}
                empty="No alerts match these filters. Alerts are raised when an analysis is processed."
                columns={[
                  { key: 'sev', header: 'Severity', render: (a) => <SeverityTag severity={a.severity} /> },
                  { key: 'type', header: 'Type', className: 'whitespace-nowrap', render: (a) => (
                    <button onClick={() => pick(a.id)} aria-pressed={selected === a.id}
                            className={`text-left hover:underline ${selected === a.id ? 'font-semibold text-fg' : 'text-accent'}`}>{a.type_label}</button>) },
                  { key: 'status', header: 'Status', render: (a) => <AlertStatusTag status={a.status} /> },
                  { key: 'subject', header: 'Subject', className: 'max-w-0 w-full', render: (a) => (
                    <a href={subjectHref(a)} title={a.summary.campaign_label ?? a.analysis_id ?? undefined} className="block truncate text-accent hover:underline">{subjectText(a)}</a>) },
                  { key: 'level', header: 'Combined', className: 'whitespace-nowrap', render: (a) => a.summary.combined_level
                    ? <RiskLevelTag level={a.summary.combined_level} score={a.summary.combined_score} />
                    : <span className="text-muted">{a.summary.campaign_confidence ? `${a.summary.campaign_confidence} conf.` : '—'}</span> },
                  { key: 'occ', header: 'Occ.', align: 'right', mono: true, render: (a) => a.occurrence_count },
                  { key: 'first', header: 'First seen', hideBelow: '2xl', mono: true, className: 'whitespace-nowrap text-muted', render: (a) => formatDate(a.created_at) },
                  { key: 'last', header: 'Last seen', hideBelow: '2xl', mono: true, className: 'whitespace-nowrap text-muted', render: (a) => formatDate(a.last_seen_at) },
                  { key: 'actor', header: 'Actor', hideBelow: '2xl', mono: true, className: 'whitespace-nowrap', render: (a) => a.resolved_by ?? a.acknowledged_by ?? <span className="text-muted">—</span> },
                ]}
              />
              <div className="flex items-center justify-between border-t border-line px-3 py-2 text-sm text-muted">
                <span className="font-mono text-xs">page {page} / {pages}</span>
                <span className="flex gap-2">
                  <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Newer</Button>
                  <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Older</Button>
                </span>
              </div>
            </>)}
        </Panel>
        <div className="flex flex-col gap-4 xl:col-span-4">
          {selected ? <Detail id={selected} canManage={canManage} onChanged={() => setTick((t) => t + 1)} />
            : <Panel title="Alert"><EmptyLine>Select an alert to see its details, pinned risk version and history.</EmptyLine></Panel>}
          {can('config:status') && <ConfigPanel />}
        </div>
      </div>
    </div>
  )
}
