// Shared alert presentation (P5f): severity/status tags, honesty text, top-bar badge, analysis banner.
import { useEffect, useState } from 'react'
import { getAlertsSummary, listAlerts, type AlertItem, type AlertSeverity, type AlertStatus } from '../../api/client'
import { LED, StatusTag, type Tone } from '../ui'

export const ALERT_HONESTY = 'Alerts are raised when an analysis is processed; this system does not monitor mailboxes in real time.'
export const SEVERITY_TONE: Record<AlertSeverity, Tone> = { low: 'neutral', medium: 'warn', high: 'danger', critical: 'danger' }
export const STATUS_TONE: Record<AlertStatus, Tone> = { new: 'accent', acknowledged: 'warn', resolved: 'ok' }
export const POLL_MS = 45_000

export function SeverityTag({ severity }: { severity: AlertSeverity }) {
  return <StatusTag tone={SEVERITY_TONE[severity]}>{severity}</StatusTag>
}

export function AlertStatusTag({ status }: { status: AlertStatus }) {
  return <StatusTag tone={STATUS_TONE[status]} led={false}>{status}</StatusTag>
}

/** Where an alert points: the analysis (with pinned risk version) or the campaign. */
export function subjectHref(a: AlertItem): string {
  if (a.analysis_id) return `#analysis/${a.analysis_id}`
  if (a.campaign_id) return `#campaign/${a.campaign_id}`
  return '#alerts'
}

export function subjectText(a: AlertItem): string {
  if (a.summary.campaign_label) return a.summary.campaign_label.replace(/^Candidate campaign /, 'campaign ')
  if (a.analysis_id) return `an ${a.analysis_id.slice(0, 8)}`
  return '—'
}

/** Top-bar indicator: count of NEW alerts; polls lightly and only while the tab is visible. */
export function AlertBadge() {
  const [count, setCount] = useState<number | null>(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let ctl = new AbortController()
    const load = () => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return
      ctl.abort()
      ctl = new AbortController()
      getAlertsSummary(ctl.signal)
        .then((s) => { setCount(s.new); setFailed(false) })
        .catch((err) => { if (!(err instanceof DOMException && err.name === 'AbortError')) setFailed(true) })
    }
    load()
    const timer = window.setInterval(load, POLL_MS)
    const onVis = () => { if (document.visibilityState === 'visible') load() }
    document.addEventListener('visibilitychange', onVis)
    return () => { ctl.abort(); window.clearInterval(timer); document.removeEventListener('visibilitychange', onVis) }
  }, [])
  const label = failed ? 'Alerts: count unavailable' : count === null ? 'Alerts' : `${count} new alert${count === 1 ? '' : 's'}`
  return (
    <a href="#alerts" data-testid="alert-badge" aria-label={label} title={label}
       className="flex h-7 items-center gap-1.5 border border-line-strong bg-surface-2 px-2 font-mono text-xs uppercase tracking-wider text-fg hover:bg-surface-3">
      <LED tone={failed ? 'neutral' : count ? 'danger' : 'ok'} />
      <span className="hidden xl:inline">Alerts</span>
      <span className="font-semibold">{failed ? '—' : count ?? '…'}</span>
    </a>
  )
}

/** Analysis page: compact strip when the analysis has an open alert. */
export function AnalysisAlertBanner({ analysisId }: { analysisId: string }) {
  const [items, setItems] = useState<AlertItem[]>([])
  useEffect(() => {
    const ctl = new AbortController()
    setItems([])
    listAlerts({ analysis_id: analysisId, status: 'open', page_size: 5 }, ctl.signal)
      .then((r) => setItems(r.items)).catch(() => setItems([]))
    return () => ctl.abort()
  }, [analysisId])
  if (!items.length) return null
  const top = items[0]
  return (
    <p className="flex flex-wrap items-center gap-2 border border-line bg-surface px-3 py-1.5 text-sm text-fg" data-testid="analysis-alert-banner">
      <LED tone={SEVERITY_TONE[top.severity]} />
      <span>{items.length === 1 ? 'Open alert' : `${items.length} open alerts`}:</span>
      <a href={`#alerts/${top.id}`} className="text-accent hover:underline">{top.type_label}</a>
      <SeverityTag severity={top.severity} />
      <AlertStatusTag status={top.status} />
      <span className="text-muted">raised when this analysis was processed</span>
    </p>
  )
}

/** Overview panel: open-alert counts and the most recent open alerts. */
export function OpenAlertsPanelBody() {
  const [state, setState] = useState<{ items: AlertItem[]; open: number; crit: number; high: number } | 'loading' | 'error'>('loading')
  useEffect(() => {
    const ctl = new AbortController()
    Promise.all([listAlerts({ status: 'open', page_size: 3 }, ctl.signal), getAlertsSummary(ctl.signal)])
      .then(([l, s]) => setState({ items: l.items, open: s.open, crit: s.open_by_severity.critical, high: s.open_by_severity.high }))
      .catch((err) => { if (!(err instanceof DOMException && err.name === 'AbortError')) setState('error') })
    return () => ctl.abort()
  }, [])
  if (state === 'loading') return <div className="p-3" role="status" aria-label="Loading alerts…"><span className="text-sm text-muted">Loading alerts…</span></div>
  if (state === 'error') return <p className="p-3 text-sm text-muted">Alerts could not be loaded.</p>
  return (
    <div data-testid="overview-alerts">
      <p className="flex flex-wrap gap-x-4 border-b border-line px-3 py-2 font-mono text-xs uppercase tracking-wider text-muted">
        <span>open <span className="text-fg">{state.open}</span></span>
        <span>critical <span className="text-fg">{state.crit}</span></span>
        <span>high <span className="text-fg">{state.high}</span></span>
      </p>
      {state.items.length === 0 ? (
        <p className="px-3 py-2 text-sm text-muted">No open alerts. Alerts are raised when an analysis is processed.</p>
      ) : (
        <ul className="divide-y divide-line">
          {state.items.map((a) => (
            <li key={a.id} className="flex items-center gap-2 px-3 py-1.5 text-sm">
              <SeverityTag severity={a.severity} />
              <a href={`#alerts/${a.id}`} className="min-w-0 flex-1 truncate text-accent hover:underline" title={a.title}>{a.type_label}</a>
              <span className="whitespace-nowrap font-mono text-xs text-muted">{subjectText(a)}</span>
            </li>))}
        </ul>)}
    </div>
  )
}
