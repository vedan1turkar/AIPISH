import { useCallback, useEffect, useState } from 'react'
import {
  listAnalyses,
  listInvestigations,
  getAnalysis,
  ApiError,
  type AnalysisSummary,
  type InvestigationCase,
} from '../api/client'
import {
  DataTable, ErrorAlert, Mono, Panel, SkeletonRows, Spinner, StatusTag, Tabs, formatBytes, formatDate, verdictTone,
} from './ui'

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
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-fg">Investigation history</h1>
          <p className="text-sm text-muted">Everything stored by the connected backend.</p>
        </div>
        {busy && <Spinner label="Loading from backend…" />}
      </div>

      <Tabs<View> label="History views" active={view} onChange={setView}
                  items={[{ id: 'analyses', label: 'Analyses' }, { id: 'cases', label: 'Investigation cases' }]} />

      {error && <ErrorAlert message={error.message} code={error.code} onDismiss={() => setError(null)} />}

      {view === 'analyses' && (
        <Panel title="Analyses" bodyClassName="p-0"
               status={analyses ? <span className="font-mono text-xs">{analyses.length} most recent{opening ? ' · opening…' : ''}</span> : undefined}>
          {!analyses && !error ? <div className="p-3"><SkeletonRows rows={6} /></div> : (
            <DataTable<AnalysisSummary>
              label="Analyses"
              rows={analyses ?? []}
              rowKey={(a) => a.id}
              pageSize={25}
              empty="No analyses yet. Upload an .eml file to run your first forensic analysis — it will appear here afterwards."
              columns={[
                { key: 'verdict', header: 'Verdict', sortValue: (a) => a.detection_score,
                  render: (a) => <StatusTag tone={verdictTone(a.detection_verdict)}>{(a.detection_verdict ?? 'unknown').replace(/_/g, ' ')}</StatusTag> },
                { key: 'score', header: 'Score', align: 'right', mono: true, sortValue: (a) => a.detection_score, render: (a) => a.detection_score },
                { key: 'subject', header: 'Subject', className: 'max-w-0 w-full', sortValue: (a) => (a.subject ?? '').toLowerCase(),
                  render: (a) => (
                    <button onClick={() => void open(a.id)} disabled={opening !== null}
                            className="block w-full truncate text-left text-accent hover:underline disabled:text-muted">
                      {a.subject || '(no subject)'}
                    </button>) },
                { key: 'sender', header: 'Sender', mono: true, className: 'whitespace-nowrap', sortValue: (a) => a.sender?.email ?? '',
                  render: (a) => a.sender?.email ?? 'sender unknown' },
                { key: 'hops', header: 'Hops', hideBelow: 'xl', align: 'right', mono: true, render: (a) => a.received_count },
                { key: 'urls', header: 'URLs', hideBelow: 'xl', align: 'right', mono: true, render: (a) => a.url_count },
                { key: 'size', header: 'Size', hideBelow: 'xl', align: 'right', mono: true, className: 'whitespace-nowrap', render: (a) => formatBytes(a.size_bytes) },
                { key: 'sha', header: 'SHA-256', render: (a) => <Mono display={`${a.sha256.slice(0, 12)}…`}>{a.sha256}</Mono> },
                { key: 'flags', header: 'Flags', hideBelow: 'xl', render: (a) => a.has_defects ? <StatusTag tone="warn">parse defects</StatusTag> : <span className="text-muted">—</span> },
                { key: 'time', header: 'Received', mono: true, className: 'whitespace-nowrap text-muted', sortValue: (a) => a.created_at,
                  render: (a) => formatDate(a.created_at) },
              ]}
            />
          )}
        </Panel>
      )}

      {view === 'cases' && (
        <Panel title="Investigation cases" bodyClassName="p-0"
               status={cases ? <span className="font-mono text-xs">{cases.length} cases</span> : undefined}>
          {!cases && !error ? <div className="p-3"><SkeletonRows rows={4} /></div> : (
            <DataTable<InvestigationCase>
              label="Investigation cases"
              rows={cases ?? []}
              rowKey={(c) => c.id}
              pageSize={25}
              empty="No investigation cases yet. Cases are created from an analysis in the results dashboard, to enable PDF reporting and integrity checks."
              columns={[
                { key: 'num', header: 'Case', mono: true, className: 'whitespace-nowrap', sortValue: (c) => c.case_number,
                  render: (c) => <a href={`#case/${c.id}`} className="text-accent hover:underline">{c.case_number}</a> },
                { key: 'title', header: 'Title', className: 'max-w-0 w-full', render: (c) => <span className="block truncate">{c.title || '—'}</span> },
                { key: 'status', header: 'Status', render: (c) => <StatusTag tone={c.status === 'open' ? 'accent' : 'neutral'}>{c.status}</StatusTag> },
                { key: 'msgs', header: 'Messages', align: 'right', mono: true, sortValue: (c) => c.analyses.length,
                  render: (c) => c.analyses.length },
                { key: 'evidence', header: 'Evidence', hideBelow: 'xl', mono: true, render: (c) => c.evidence_policy.store_mode },
                { key: 'created', header: 'Opened', mono: true, className: 'whitespace-nowrap text-muted', sortValue: (c) => c.created_at,
                  render: (c) => formatDate(c.created_at) },
              ]}
            />
          )}
        </Panel>
      )}
    </div>
  )
}
