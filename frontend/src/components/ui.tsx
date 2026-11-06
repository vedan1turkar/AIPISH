import type { ReactNode } from 'react'

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

const STATUS_META: Record<StatusKind, { label: string; className: string; hint: string }> = {
  verified:           { label: 'Verified',        className: 'bg-emerald-100 text-emerald-800 ring-emerald-300', hint: 'Independently re-derived from the evidence' },
  verified_fail:      { label: 'Verified — fail',   className: 'bg-red-100 text-red-800 ring-red-300', hint: 'Independently checked and failed' },
  verified_softfail:  { label: 'Verified — softfail', className: 'bg-amber-100 text-amber-800 ring-amber-300', hint: 'Independently checked — soft fail' },
  verified_none:      { label: 'Verified — none',   className: 'bg-gray-100 text-gray-600 ring-gray-300', hint: 'Independently checked — no policy record' },
  claimed:            { label: 'Claimed',         className: 'bg-sky-100 text-sky-800 ring-sky-300', hint: 'Stated by the email\u2019s own headers — not independently confirmed' },
  inferred:           { label: 'Inferred',        className: 'bg-indigo-100 text-indigo-800 ring-indigo-300', hint: 'Derived by a heuristic from the available evidence' },
  available:          { label: 'Available',       className: 'bg-teal-100 text-teal-800 ring-teal-300', hint: 'Data exists and is shown' },
  unavailable:        { label: 'Unavailable',     className: 'bg-orange-100 text-orange-800 ring-orange-300', hint: 'Provider or data source could not be reached' },
  unknown:            { label: 'Unknown',         className: 'bg-gray-100 text-gray-600 ring-gray-300', hint: 'No signal; nothing could be determined' },
  match:              { label: 'Match',           className: 'bg-emerald-100 text-emerald-800 ring-emerald-300', hint: '' },
  mismatch:           { label: 'Mismatch',        className: 'bg-red-100 text-red-800 ring-red-300', hint: '' },
  neutral:            { label: '—',               className: 'bg-gray-100 text-gray-600 ring-gray-300', hint: '' },
}

export function StatusBadge({ kind, title }: { kind: string; title?: string }) {
  const meta = STATUS_META[(kind as StatusKind)] ?? STATUS_META.neutral
  if (kind === 'neutral') return null
  return (
    <span
      title={title ?? (meta.hint || undefined)}
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset whitespace-nowrap ${meta.className}`}
    >
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

const SEV_CLASS: Record<string, string> = {
  low: 'bg-gray-100 text-gray-700 ring-gray-300',
  medium: 'bg-amber-100 text-amber-800 ring-amber-300',
  high: 'bg-red-100 text-red-800 ring-red-300',
}

export function SeverityChip({ severity }: { severity: string | null | undefined }) {
  if (!severity) return null
  const key = (severity in SEV_CLASS ? severity : 'low')
  const cap = key as Severity
  const cap_form = cap.charAt(0).toUpperCase() + cap.slice(1)
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${SEV_CLASS[key]}`}
    >
      {cap_form}
    </span>
  )
}

// ── Score ring ─────────────────────────────────────────────────────────────
export function scoreColor(score: number): { text: string; bar: string; banner: string } {
  if (score >= 70) return { text: 'text-red-600', bar: 'bg-red-500', banner: 'bg-red-50 border-red-200' }
  if (score >= 40) return { text: 'text-amber-600', bar: 'bg-amber-500', banner: 'bg-amber-50 border-amber-200' }
  if (score > 0) return { text: 'text-sky-600', bar: 'bg-sky-500', banner: 'bg-sky-50 border-sky-200' }
  return { text: 'text-emerald-600', bar: 'bg-emerald-500', banner: 'bg-emerald-50 border-emerald-200' }
}

export function ScoreBadge({ score, verdict }: { score: number; verdict?: string | null }) {
  const c = scoreColor(score)
  return (
    <div className={`flex items-center gap-4 rounded-xl border p-4 ${c.banner}`}>
      <div
        className={`flex h-16 w-16 shrink-0 flex-col items-center justify-center rounded-full bg-white shadow-sm ring-2 ${
          score >= 70 ? 'ring-red-400' : score >= 40 ? 'ring-amber-400' : score > 0 ? 'ring-sky-400' : 'ring-emerald-400'
        }`}
      >
        <span className={`text-xl font-bold leading-none ${c.text}`}>{score}</span>
        <span className="text-[10px] uppercase text-gray-400">score</span>
      </div>
      <div className="min-w-0">
        {verdict && (
          <div className="text-sm font-semibold capitalize text-gray-900">{verdict}</div>
        )}
        <p className="mt-0.5 text-xs text-gray-500">
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
}: {
  title: string
  status?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`rounded-xl border border-gray-200 bg-white shadow-sm ${className}`}>
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-100 px-4 py-3">
        <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
        {status}
      </header>
      <div className="p-4">{children}</div>
    </section>
  )
}

export function EmptyState({ icon, title, hint }: { icon: string; title: string; hint: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-gray-300 px-6 py-10 text-center">
      <span className="text-2xl text-gray-400" aria-hidden>
        {icon}
      </span>
      <p className="mt-2 text-sm font-medium text-gray-600">{title}</p>
      <p className="mt-1 max-w-sm text-xs text-gray-400">{hint}</p>
    </div>
  )
}

export function ErrorAlert({ message, code, onDismiss }: { message: string; code?: string; onDismiss?: () => void }) {
  return (
    <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-medium">Something went wrong</p>
          <p className="mt-0.5 text-red-700">{message}</p>
          {code && <p className="mt-1 text-[11px] text-red-400">Error code: {code}</p>}
        </div>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="rounded p-1 text-red-400 hover:bg-red-100 hover:text-red-600"
            aria-label="Dismiss error"
          >
            ✕
          </button>
        )}
      </div>
    </div>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-gray-500">
      <span
        className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-gray-600"
        role="status"
        aria-label="loading"
      />
      {label && <span>{label}</span>}
    </div>
  )
}

export function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-2 border-b border-gray-100 py-1.5 last:border-0">
      <span className="w-36 shrink-0 text-xs text-gray-400">{label}</span>
      <span className="min-w-0 flex-1 break-words text-sm text-gray-800">{children}</span>
    </div>
  )
}

export function DemoDataBanner() {
  return (
    <div className="mb-4 rounded-lg border border-dashed border-indigo-300 bg-indigo-50 px-4 py-2 text-xs text-indigo-800">
      <strong>Demo data:</strong>&nbsp;this content is sample material for interface demonstration only —
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
