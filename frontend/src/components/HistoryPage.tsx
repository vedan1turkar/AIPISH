import { useCallback, useEffect, useState } from 'react'
import {
  listAnalyses,
  listInvestigations,
  getAnalysis,
  ApiError,
  type AnalysisSummary,
  type InvestigationCase,
} from '../api/client'
import { EmptyState, ErrorAlert, Spinner, SeverityChip, formatDate, formatBytes } from './ui'

type View = 'analyses' | 'cases'

export default function HistoryPage({ onOpenAnalysis }: { onOpenAnalysis: (id: string) => void }) {
  const [view, setView] = useState<View>('analyses')
  const [analyses, setAnalyses] = useState<AnalysisSummary[] | null>(null)
  const [cases, setCases] = useState<InvestigationCase[] | null>(null)
  const [error, setError] = useState<{ message: string; code?: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [opening, setOpening] = useState<string | null>(null)

  const load = useCallback(async (which: View) => {
    setBusy(true)
    setError(null)
    try {
      if (which === 'analyses') {
        setAnalyses(await listAnalyses())
      } else {
        setCases(await listInvestigations())
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        setError({ message: err.message, code: err.code })
      } else {
        setError({ message: err instanceof Error ? err.message : 'Loading failed' })
      }
    } finally {
      setBusy(false)
    }
  }, [])

  useEffect(() => {
    void load(view)
  }, [view, load])

  async function open(id: string) {
    setOpening(id)
    try {
      await getAnalysis(id) // confirm it still exists before navigating
      onOpenAnalysis(id)
    } catch (err) {
      setError({
        message: err instanceof ApiError && err.status === 404
          ? 'That analysis no longer exists on the backend.'
          : err instanceof Error
            ? err.message
            : 'Could not open the analysis.',
      })
    } finally {
      setOpening(null)
    }
  }

  return (
    <div className="mx-auto max-w-6xl">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">Investigation history</h2>
          <p className="text-xs text-gray-400">Everything stored by the connected backend.</p>
        </div>
        <div className="flex gap-1 rounded-lg bg-gray-100 p-1">
          {(['analyses', 'cases'] as View[]).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium ${
                view === v ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-500 hover:text-gray-800'
              }`}
            >
              {v === 'analyses' ? 'Analyses' : 'Investigation cases'}
            </button>
          ))}
        </div>
      </div>

      {busy && (
        <div className="mb-3">
          <Spinner label="Loading from backend…" />
        </div>
      )}

      {error && (
        <div className="mb-3">
          <ErrorAlert message={error.message} code={error.code} onDismiss={() => setError(null)} />
        </div>
      )}

      {!busy && !error && view === 'analyses' && (analyses?.length ?? 0) === 0 && (
        <EmptyState
          icon="📭"
          title="No analyses yet"
          hint="Upload an .eml file to run your first forensic analysis — it will appear here afterwards."
        />
      )}

      {!busy && !error && view === 'cases' && (cases?.length ?? 0) === 0 && (
        <EmptyState
          icon="📁"
          title="No investigation cases yet"
          hint="Cases are created from an analysis in the results dashboard, to enable PDF reporting and integrity checks."
        />
      )}

      {view === 'analyses' && (analyses?.length ?? 0) > 0 && (
        <ul className="grid gap-3 md:grid-cols-2">
          {analyses!.map((a) => (
            <li key={a.id}>
              <button
                onClick={() => void open(a.id)}
                disabled={opening !== null}
                className="w-full rounded-xl border border-gray-200 bg-white p-4 text-left shadow-sm transition-shadow hover:shadow-md"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-gray-900">
                      {a.subject || '(no subject)'}
                    </p>
                    <p className="mt-0.5 truncate text-xs text-gray-400">
                      {a.sender?.email ?? 'sender unknown'} · {formatDate(a.created_at)}
                    </p>
                  </div>
                  <SeverityChip severity={a.detection_score >= 70 ? 'high' : a.detection_score >= 40 ? 'medium' : a.detection_score > 0 ? 'low' : null} />
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-gray-500">
                  <span className="rounded bg-gray-100 px-1.5 py-0.5">score {a.detection_score}</span>
                  {a.detection_verdict && (
                    <span className="rounded bg-gray-100 px-1.5 py-0.5 capitalize">{a.detection_verdict}</span>
                  )}
                  <span className="rounded bg-gray-100 px-1.5 py-0.5">{a.received_count} hops</span>
                  <span className="rounded bg-gray-100 px-1.5 py-0.5">{a.url_count} URLs</span>
                  <span className="rounded bg-gray-100 px-1.5 py-0.5">{formatBytes(a.size_bytes)}</span>
                  {a.has_defects && (
                    <span className="rounded bg-amber-50 px-1.5 py-0.5 text-amber-700">parse defects</span>
                  )}
                </div>
                <p className="mt-2 text-[11px] font-mono text-gray-300">{a.sha256.slice(0, 24)}…</p>
                {opening === a.id && <p className="mt-1 text-xs text-gray-400">Opening…</p>}
              </button>
            </li>
          ))}
        </ul>
      )}

      {view === 'cases' && (cases?.length ?? 0) > 0 && (
        <ul className="space-y-3">
          {cases!.map((c) => (
            <li key={c.id} className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-gray-900">
                    <span className="font-mono text-indigo-600">{c.case_number}</span>
                    {c.title && <span className="ml-2">{c.title}</span>}
                  </p>
                  <p className="mt-0.5 text-xs text-gray-400">{formatDate(c.created_at)}</p>
                </div>
                <div className="flex gap-2 text-[11px]">
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 text-gray-600">{c.analyses.length} message{c.analyses.length === 1 ? '' : 's'}</span>
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 text-gray-600">evidence: {c.evidence_policy.store_mode}</span>
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 capitalize text-gray-600">{c.status}</span>
                </div>
              </div>
              {c.analyses.length > 0 && (
                <ul className="mt-3 divide-y divide-gray-100">
                  {c.analyses.map((row) => (
                    <li key={row.analysis_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-xs">
                      <button
                        onClick={() => void open(row.analysis_id)}
                        className="font-mono text-indigo-600 hover:underline"
                      >
                        {row.analysis_id.slice(0, 8)}
                      </button>
                      <span className="min-w-0 flex-1 truncate text-gray-700">
                        {row.subject || '(no subject)'}
                      </span>
                      <span className="rounded bg-gray-100 px-1.5 py-0.5 text-gray-600">score {row.threat_score}</span>
                      <span className="text-gray-400">
                        SPF {row.authentication_status.spf} · DKIM {row.authentication_status.dkim} · DMARC {row.authentication_status.dmarc}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
