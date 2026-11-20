import type { ReactNode } from 'react'
import { LED, type Tone } from './primitives'

// ── Status semantics ───────────────────────────────────────────────────────
// These map to what the backend can honestly assert about a value:
//   verified     — independently re-derived from the evidence (DNS checks, hashes)
//   claimed      — stated by the email's own headers (untrustworthy by definition)
//   inferred     — derived by a heuristic (relay-chain reconstruction)
//   available    — data exists and is shown alongside
//   unavailable  — the data was requested but could not be obtained
//   unknown      — no signal either way; nothing was inferable
export type StatusKind =
  | 'verified'
  | 'verified_fail'
  | 'verified_softfail'
  | 'verified_none'
  | 'claimed'
  | 'inferred'
  | 'available'
  | 'unavailable'
  | 'unknown'
  | 'match'
  | 'mismatch'
  | 'neutral'

const STATUS_META: Record<StatusKind, { label: string; tone: Tone; hint: string }> = {
  verified:           { label: 'Verified',        tone: 'ok', hint: 'Independently re-derived from the evidence' },
  verified_fail:      { label: 'Verified — fail',   tone: 'danger', hint: 'Independently checked and failed' },
  verified_softfail:  { label: 'Verified — softfail', tone: 'warn', hint: 'Independently checked — soft fail' },
  verified_none:      { label: 'Verified — none',   tone: 'neutral', hint: 'Independently checked — no policy record' },
  claimed:            { label: 'Claimed',         tone: 'accent', hint: 'Stated by the email\u2019s own headers — not independently confirmed' },
  inferred:           { label: 'Inferred',        tone: 'accent', hint: 'Derived by a heuristic from the available evidence' },
  available:          { label: 'Available',       tone: 'ok', hint: 'Data exists and is shown' },
  unavailable:        { label: 'Unavailable',     tone: 'warn', hint: 'Provider or data source could not be reached' },
  unknown:            { label: 'Unknown',         tone: 'neutral', hint: 'No signal; nothing could be determined' },
  match:              { label: 'Match',           tone: 'ok', hint: '' },
  mismatch:           { label: 'Mismatch',        tone: 'danger', hint: '' },
  neutral:            { label: '—',               tone: 'neutral', hint: '' },
}

const TONE_TAG: Record<Tone, string> = {
  neutral: 'border-line-strong text-muted bg-surface-2',
  accent: 'border-accent-line text-accent bg-accent-weak',
  ok: 'border-ok-line text-ok bg-ok-weak',
  warn: 'border-warn-line text-warn bg-warn-weak',
  danger: 'border-danger-line text-danger bg-danger-weak',
}

export function StatusBadge({ kind, title }: { kind: string; title?: string }) {
  const meta = STATUS_META[(kind as StatusKind)] ?? STATUS_META.neutral
  if (kind === 'neutral') return null
  return (
    <span
      title={title ?? (meta.hint || undefined)}
      data-tone={meta.tone}
      className={`inline-flex h-5 items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 font-mono text-xs uppercase tracking-wide ${TONE_TAG[meta.tone]}`}
    >
      <LED tone={meta.tone} />
      {meta.label}
    </span>
  )
}

/**
 * Classify an auth/enrichment status string from the backend into a badge.
 * - Values beginning "verified_" (e.g. verified_pass) → verified family
 * - pass from a header claim → claimed
 * - provider statuses: ok → available, error/unavailable/timeout → unavailable,
 *   not_found/none → unknown
 */
export function classifyStatus(raw: string): string {
  const v = (raw || '').toLowerCase()
  if (v.startsWith('verified_pass')) return 'verified'
  if (v.startsWith('verified_')) return v
  if (v === 'pass') return 'claimed'
  if (v === 'ok') return 'available'
  if (['error', 'unavailable', 'timeout', 'degraded'].includes(v)) return 'unavailable'
  if (['not_found', 'none', 'missing'].includes(v)) return 'unknown'
  return v === '' ? 'unknown' : 'neutral'
}

// ── Severity ───────────────────────────────────────────────────────────────
export type Severity = 'low' | 'medium' | 'high'

const SEV_TONE: Record<string, Tone> = { low: 'neutral', medium: 'warn', high: 'danger' }

export function SeverityChip({ severity }: { severity: string | null | undefined }) {
  if (!severity) return null
  const key = (severity in SEV_TONE ? severity : 'low')
  const cap = key as Severity
  const cap_form = cap.charAt(0).toUpperCase() + cap.slice(1)
  return (
    <span
      data-tone={SEV_TONE[key]}
      className={`inline-flex h-5 items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 font-mono text-xs uppercase tracking-wide ${TONE_TAG[SEV_TONE[key]]}`}
    >
      <LED tone={SEV_TONE[key]} />
      {cap_form}
    </span>
  )
}

// ── Score ring ─────────────────────────────────────────────────────────────
export function scoreTone(score: number): Tone {
  if (score >= 70) return 'danger'
  if (score >= 40) return 'warn'
  if (score > 0) return 'neutral'
  return 'ok'
}

export function scoreColor(score: number): { text: string; bar: string; banner: string } {
  if (score >= 70) return { text: 'text-danger', bar: 'bg-danger', banner: 'bg-danger-weak border-danger-line' }
  if (score >= 40) return { text: 'text-warn', bar: 'bg-warn', banner: 'bg-warn-weak border-warn-line' }
  if (score > 0) return { text: 'text-fg', bar: 'bg-muted', banner: 'bg-surface-2 border-line' }
  return { text: 'text-ok', bar: 'bg-ok', banner: 'bg-ok-weak border-ok-line' }
}

export function ScoreBadge({ score, verdict }: { score: number; verdict?: string | null }) {
  // Quiet by design: the verdict strip at the top of the analysis is the focal element.
  return (
    <div className="flex items-center gap-4 border-b border-line pb-3">
      <div className="flex items-center gap-2">
        <LED tone={scoreTone(score)} />
        <span className="font-mono text-lg font-semibold leading-none text-fg">{score}</span>
        <span className="font-mono text-xs uppercase text-muted">/ 100 score</span>
      </div>
      <div className="min-w-0">
        {verdict && <div className="text-base font-medium capitalize text-fg">{verdict}</div>}
        <p className="text-sm text-muted">
          Heuristic risk score (0–100) — see Findings for the evidence behind each point.
        </p>
      </div>
    </div>
  )
}

// ── Layout primitives ──────────────────────────────────────────────────────
export function Panel({
  title,
  status,
  children,
  className = '',
  bodyClassName = '',
}: {
  title: string
  status?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={`flex min-w-0 flex-col border border-line bg-surface ${className}`} aria-label={title}>
      <header className="flex min-h-[34px] flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-line px-3 py-1.5">
        <h2 className="font-mono text-xs font-medium uppercase tracking-wider text-muted">{title}</h2>
        {status && <div className="flex flex-wrap items-center gap-2 text-sm text-muted">{status}</div>}
      </header>
      <div className={`flex-1 p-3 ${bodyClassName}`}>{children}</div>
    </section>
  )
}

/** Compact one-line empty state (icon prop kept for API compatibility; not rendered). */
export function EmptyState({ title, hint }: { icon?: string; title: string; hint: string }) {
  return (
    <p className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 py-1 text-sm" data-testid="empty-state">
      <span className="font-mono text-xs text-muted" aria-hidden>--</span>
      <span className="font-medium text-fg">{title}</span>
      <span className="text-muted">{hint}</span>
    </p>
  )
}

export function ErrorAlert({ message, code, onDismiss }: { message: string; code?: string; onDismiss?: () => void }) {
  return (
    <div className="flex items-start justify-between gap-3 border border-danger-line bg-danger-weak px-3 py-2 text-sm" role="alert">
      <div className="flex min-w-0 items-start gap-2">
        <LED tone="danger" className="mt-1.5" />
        <div className="min-w-0">
          <p className="font-medium text-danger">Something went wrong</p>
          <p className="text-fg">{message}</p>
          {code && <p className="font-mono text-xs text-muted">Error code: {code}</p>}
        </div>
      </div>
      {onDismiss && (
        <button onClick={onDismiss} aria-label="Dismiss error"
                className="px-1 font-mono text-xs uppercase text-muted hover:bg-surface-3 hover:text-fg">
          close
        </button>
      )}
    </div>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted">
      <span className="inline-block h-2 w-2 animate-pulse bg-accent" role="status" aria-label="loading" />
      {label && <span>{label}</span>}
    </div>
  )
}

export function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(7rem,10rem)_1fr] gap-3 border-b border-line py-1.5 last:border-0">
      <span className="font-mono text-xs uppercase leading-5 tracking-wider text-muted">{label}</span>
      <span className="min-w-0 break-words text-sm text-fg">{children}</span>
    </div>
  )
}

export function DemoDataBanner() {
  return (
    <div className="mb-4 flex items-center gap-2 border border-warn-line bg-warn-weak px-3 py-1.5 text-sm text-fg">
      <LED tone="warn" />
      <strong className="text-warn">Demo data:</strong>&nbsp;this content is sample material for interface demonstration only —
      it is not real analysis output.
    </div>
  )
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return iso
  }
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
