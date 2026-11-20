// Threat Intelligence tab (P5a): consent control, provider status, per-indicator results.
// Results are informational only and never change the score or verdict.
import { useState } from 'react'
import type { IntelIndicator, IntelResult, IntelServiceStatus, ThreatIntelRun } from '../../api/client'
import { Button, EmptyState, ErrorAlert, Panel, Spinner, formatDate } from '../ui'
import { ORDER_PROVIDERS, ageText, cacheLabel, factsFor, statusMeta } from './model'

export const INTEL_DISCLAIMER =
  'Threat-intelligence results are third-party, point-in-time data and are informational only. They do not change the rule score, ML classification or verdict. ' +
  'If a provider has no reports or flags, that is not proof of safety. An IP address or its geolocation identifies network infrastructure, never a person.'

export function IntelStatusChip({ status }: { status: string }) {
  const m = statusMeta(status)
  return (
    <span
      title={m.hint}
      data-status={status}
      className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium border whitespace-nowrap ${m.className}`}
    >
      <span aria-hidden>{m.icon}</span>
      {m.label}
    </span>
  )
}

function Disclaimer() {
  return (
    <div role="note" className=" border border-warn-line bg-warn-weak px-3 py-2 text-xs text-warn">
      <strong>Read with care:</strong> {INTEL_DISCLAIMER}
    </div>
  )
}

function ConsentCard({
  status,
  running,
  hasRun,
  onRun,
}: {
  status: IntelServiceStatus | null
  running: boolean
  hasRun: boolean
  onRun: (consent: boolean) => void
}) {
  const [agreed, setAgreed] = useState(false)
  const configured = status
    ? ORDER_PROVIDERS.filter((p) => status.providers[p]?.enabled).map((p) => status.providers[p].label)
    : []
  return (
    <Panel title="External lookup consent" status={<span className="text-xs text-muted">External lookups are off unless you opt in for this analysis</span>}>
      <div className="space-y-2 text-sm text-fg">
        <p>
          <strong>What is sent:</strong> only the bare indicator: a public IP address, a domain name, or an attachment
          SHA-256 hash. Each goes only to the providers that handle that type
          {configured.length ? ` (${configured.join(', ')})` : ''}. The Tor exit list is downloaded and checked on this
          server, so no indicator is sent for that check.
        </p>
        <p>
          <strong>Never sent:</strong> the subject, the body, sender or recipient addresses, headers, URL paths or query
          strings, attachments, case IDs, or private and internal addresses.
        </p>
        {status?.offline && (
          <p className=" bg-surface-2 px-2 py-1 text-xs text-fg">
            Offline mode is on, so no external calls are made. Only cached results are shown, and they are labelled stale
            if expired.
          </p>
        )}
        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={agreed}
            disabled={running}
            onChange={(e) => setAgreed(e.target.checked)}
          />
          <span>I consent to sending these bare indicators to the external providers listed for this analysis.</span>
        </label>
        <div className="flex flex-wrap gap-2 pt-1">
          <Button type="button" variant="primary" onClick={() => onRun(true)} disabled={!agreed || running}>
            {running ? 'Running lookups…' : hasRun ? 'Run threat intel lookup again' : 'Run threat intel lookup'}
          </Button>
          <Button type="button" onClick={() => onRun(false)} disabled={running}>
            Decline external lookups (record decision)
          </Button>
        </div>
      </div>
    </Panel>
  )
}

export function ProviderStatusChips({ status }: { status: IntelServiceStatus | null }) {
  if (!status) return null
  const entries = Object.entries(status.providers)
  return (
    <ul className="flex flex-wrap gap-2" aria-label="Provider configuration">
      {entries.map(([key, p]) => {
        const state = p.enabled ? 'ready' : p.configured ? 'disabled' : 'not configured'
        const cls = p.enabled
          ? 'bg-ok-weak text-ok border-ok-line'
          : p.configured
            ? 'bg-warn-weak text-warn border-warn-line'
            : 'bg-surface-2 text-muted border-line'
        return (
          <li key={key} title={p.note ?? ''} className={` px-2 py-0.5 text-xs border ${cls}`}>
            <span aria-hidden>{p.enabled ? '● ' : '○ '}</span>
            {p.label}: {state}
          </li>
        )
      })}
    </ul>
  )
}

function ResultRow({ r }: { r: IntelResult }) {
  const facts = factsFor(r)
  const cache = cacheLabel(r)
  return (
    <li className=" border border-line p-3" data-provider={r.provider}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-fg">{r.provider_label}</span>
        <IntelStatusChip status={r.status} />
        {cache && (
          <span
            className={` px-1.5 py-0.5 text-xs font-semibold ${
 r.cache_state === 'stale' ? 'bg-warn-line text-warn' : 'bg-surface-2 text-muted'
 }`}
          >
            {cache}
            {r.cache_state === 'stale' ? ` · ${ageText(r.cache_age_seconds)}` : ''}
          </span>
        )}
        <span className="text-xs text-muted">
          {r.fetched_at ? `fetched ${formatDate(r.fetched_at)}` : 'no data fetched'}
        </span>
      </div>
      <p className="mt-1 text-xs text-muted break-words">{r.message}</p>
      {r.retry_after_seconds ? (
        <p className="mt-0.5 text-xs text-warn">Retry after about {r.retry_after_seconds}s.</p>
      ) : null}
      {facts.length > 0 && (
        <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-0.5 text-xs sm:grid-cols-2">
          {facts.map(([k, v]) => (
            <div key={k} className="flex min-w-0 gap-1">
              <dt className="shrink-0 text-muted">{k}:</dt>
              <dd className="min-w-0 break-words text-fg">{v}</dd>
            </div>
          ))}
        </dl>
      )}
      <p className="mt-1 text-xs text-muted">Source: {r.source}</p>
    </li>
  )
}

function IndicatorCard({ ind }: { ind: IntelIndicator }) {
  const notLooked = ind.state !== 'looked_up'
  return (
    <div className=" border border-line bg-surface p-3 " data-indicator={ind.indicator}>
      <div className="flex flex-wrap items-center gap-2">
        <code className="break-all text-sm font-semibold text-fg">{ind.indicator}</code>
        <span className=" bg-surface-2 px-1.5 py-0.5 text-xs uppercase text-muted">{ind.indicator_type}</span>
        {notLooked && <IntelStatusChip status={ind.state} />}
      </div>
      <p className="mt-0.5 text-xs text-muted">From: {ind.origins.join(', ')}</p>
      {notLooked ? (
        <p className="mt-1 text-xs text-muted">{ind.message ?? ind.rejection_reason}</p>
      ) : (
        <ul className="mt-2 space-y-2">
          {ind.results.map((r) => (
            <ResultRow key={r.provider} r={r} />
          ))}
        </ul>
      )}
    </div>
  )
}

export function RunSummary({ run }: { run: ThreatIntelRun }) {
  const providers = ORDER_PROVIDERS.filter((p) => Object.keys(run.provider_summary[p] ?? {}).length > 0)
  const idle = ORDER_PROVIDERS.filter((p) => run.provider_summary[p] && !providers.includes(p))
  return (
    <div className="space-y-2 text-xs text-muted">
      <p>
        Run v{run.version} · {formatDate(run.created_at)} · consent{' '}
        <strong className={run.consent.granted ? 'text-ok' : 'text-accent'}>
          {run.consent.granted ? 'granted' : 'declined'}
        </strong>{' '}
        ({run.consent.source === 'upload' ? 'at upload' : 'on demand'}, {formatDate(run.consent.decided_at)})
        {run.offline ? ' · offline mode' : ''}
      </p>
      <p>
        {run.counts.total} indicators found: {run.counts.looked_up} looked up, {run.counts.rejected} not eligible,{' '}
        {run.counts.cap_skipped} over the cap of {run.ioc_cap}.
      </p>
      <ul className="flex flex-wrap gap-x-4 gap-y-1" aria-label="Results by provider">
        {providers.map((p) => (
          <li key={p} className="flex flex-wrap items-center gap-1">
            <span className="font-medium text-fg">{p.replace(/_/g, ' ')}:</span>
            {Object.entries(run.provider_summary[p]).map(([s, n]) => (
              <span key={s} className="inline-flex items-center gap-0.5">
                <IntelStatusChip status={s} />
                <span className="text-muted">×{n}</span>
              </span>
            ))}
          </li>
        ))}
      </ul>
      {idle.length > 0 && (
        <p className="text-xs text-muted">
          No applicable indicators for: {idle.map((p) => p.replace(/_/g, ' ')).join(', ')}.
        </p>
      )}
    </div>
  )
}

export default function ThreatIntelPanel({
  run,
  status,
  loading,
  error,
  running,
  runError,
  onRun,
  canRun = true,
  onDismissError,
}: {
  run: ThreatIntelRun | null
  status: IntelServiceStatus | null
  loading: boolean
  error: string | null
  running: boolean
  runError: string | null
  onRun: (consent: boolean) => void
  canRun?: boolean
  onDismissError?: () => void
}) {
  const simulated = run?.simulated || status?.simulated
  return (
    <div className="space-y-4">
      <Disclaimer />
      {simulated && (
        <div className=" border-2 border-dashed border-warn bg-warn-weak px-3 py-2 text-xs font-semibold text-warn">
          SIMULATED providers: these results come from a local stub, not from real provider data.
        </div>
      )}
      <ProviderStatusChips status={status} />
      {canRun ? (
        <ConsentCard status={status} running={running} hasRun={!!run} onRun={onRun} />
      ) : (
        <p className=" border border-line bg-surface px-3 py-2 text-xs text-muted" data-testid="intel-readonly">
          Your role can view stored threat-intel results but cannot run external lookups.
        </p>
      )}
      {runError && <ErrorAlert message={runError} onDismiss={onDismissError} />}
      {running && <Spinner label="Running threat-intel lookups. Each provider is bounded by timeouts and rate limits…" />}
      {loading && !running && <Spinner label="Loading stored threat-intel results…" />}
      {error && !loading && <ErrorAlert message={`Could not load threat-intel results: ${error}`} />}
      {!loading && !error && !run && (
        <EmptyState
          title="No threat-intel lookup has been run"
          hint="Nothing has been sent to any external provider for this analysis."
        />
      )}
      {run && (
        <Panel title="Threat-intelligence results" status={<span className="text-xs text-muted">Informational only: not part of the score or verdict</span>}>
          <RunSummary run={run} />
          {!run.consent.granted && (
            <p className="mt-2 bg-accent-weak px-2 py-1 text-xs text-accent">
              External lookups were declined for this run. Nothing was sent to any provider.
            </p>
          )}
          <div className="mt-3 grid gap-3">
            {run.indicators.length === 0 ? (
              <p className="text-sm text-muted">No indicators were extracted from this analysis.</p>
            ) : (
              run.indicators.map((ind) => <IndicatorCard key={`${ind.indicator_type}:${ind.indicator}`} ind={ind} />)
            )}
          </div>
          <p className="mt-3 text-xs text-muted">
            Not configured (out of scope): {Object.values(run.not_configured).join(' · ')}
          </p>
        </Panel>
      )}
    </div>
  )
}
