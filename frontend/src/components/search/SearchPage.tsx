// Search (P5c): analyses, cases, indicators and candidate campaigns. Never shows email bodies.
import { useState, type FormEvent } from 'react'
import { search, type SearchKind, type SearchResponse } from '../../api/client'
import { EmptyState, ErrorAlert, Panel, Spinner, formatDate } from '../ui'
import { typeLabel } from '../correlation/model'

const PAGE = 20

export default function SearchPage() {
  const [q, setQ] = useState('')
  const [type, setType] = useState<SearchKind>('all')
  const [verdict, setVerdict] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [offset, setOffset] = useState(0)
  const [res, setRes] = useState<SearchResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function run(nextOffset = 0) {
    setBusy(true)
    setError(null)
    try {
      setRes(await search({ q, type, verdict, date_from: dateFrom, date_to: dateTo, limit: PAGE, offset: nextOffset }))
      setOffset(nextOffset)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed.')
    } finally {
      setBusy(false)
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    void run(0)
  }

  const r = res?.results
  const total = r ? Object.values(r).reduce((n, x) => n + (x?.total ?? 0), 0) : 0
  const maxTotal = r ? Math.max(0, ...Object.values(r).map((x) => x?.total ?? 0)) : 0
  const field = 'mt-1 block border border-gray-300 px-2 py-1.5 text-sm'

  return (
    <div className="space-y-4" data-testid="search-page">
      <h2 className="text-lg font-semibold text-gray-900">Search</h2>
      <form onSubmit={onSubmit} aria-label="Search" className="flex flex-wrap items-end gap-2 border border-gray-200 bg-white p-3">
        <label className="text-xs font-medium text-gray-700">
          Domain, IP, hash, case or analysis ID, subject…
          <input name="q" value={q} maxLength={200} onChange={(e) => setQ(e.target.value)} className={`${field} w-72`} />
        </label>
        <label className="text-xs font-medium text-gray-700">
          In
          <select name="type" value={type} onChange={(e) => setType(e.target.value as SearchKind)} className={field}>
            <option value="all">everything</option>
            <option value="analysis">analyses</option>
            <option value="case">cases</option>
            <option value="entity">indicators</option>
            <option value="campaign">campaigns</option>
          </select>
        </label>
        <label className="text-xs font-medium text-gray-700">
          Verdict
          <select name="verdict" value={verdict} onChange={(e) => setVerdict(e.target.value)} className={field}>
            <option value="">any</option>
            <option value="phishing_fraud_likely">phishing_fraud_likely</option>
            <option value="suspicious">suspicious</option>
            <option value="low_risk">low_risk</option>
            <option value="clean">clean</option>
          </select>
        </label>
        <label className="text-xs font-medium text-gray-700">
          From
          <input type="date" name="date_from" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} className={field} />
        </label>
        <label className="text-xs font-medium text-gray-700">
          To
          <input type="date" name="date_to" value={dateTo} onChange={(e) => setDateTo(e.target.value)} className={field} />
        </label>
        <button type="submit" disabled={busy} className=" bg-indigo-600 px-3 py-2 text-xs font-semibold text-white disabled:bg-gray-300">
          Search
        </button>
      </form>
      {error && <ErrorAlert message={error} />}
      {busy && <Spinner label="Searching…" />}
      {res && !busy && total === 0 && <EmptyState title="No results" hint="Try a shorter value or another filter." />}
      {r?.analysis && r.analysis.total > 0 && (
        <Panel title={`Analyses (${r.analysis.total})`}>
          <ul className="divide-y divide-gray-100" data-testid="search-analyses">
            {r.analysis.items.map((a) => (
              <li key={a.id} className="py-1.5 text-xs">
                <a href={`#analysis/${a.id}`} className="font-medium text-indigo-700 hover:underline">{a.subject || '(no subject)'}</a>
                <span className="ml-2 font-mono text-gray-400">{a.id.slice(0, 8)}</span>
                <span className="ml-2 text-gray-500">{a.from_domain} · {a.detection_verdict} · {formatDate(a.created_at)}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {r?.case && r.case.total > 0 && (
        <Panel title={`Cases (${r.case.total})`}>
          <ul className="divide-y divide-gray-100">
            {r.case.items.map((c) => (
              <li key={c.id} className="py-1.5 text-xs">
                <a href={`#case/${c.id}`} className="font-mono font-medium text-indigo-700 hover:underline">{c.case_number}</a>
                {c.title && <span className="ml-2 text-gray-600">{c.title}</span>}
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {r?.entity && r.entity.total > 0 && (
        <Panel title={`Indicators (${r.entity.total})`}>
          <ul className="divide-y divide-gray-100" data-testid="search-entities">
            {r.entity.items.map((e) => (
              <li key={e.id} className="py-1.5 text-xs">
                <span className="text-gray-500">{typeLabel(e.type)}</span>
                <span className="ml-2 font-mono break-all">{e.value}</span>
                <span className="ml-2 text-gray-400">seen in {e.analyses} analys{e.analyses === 1 ? 'is' : 'es'}</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {r?.campaign && r.campaign.total > 0 && (
        <Panel title={`Candidate campaigns (${r.campaign.total})`}>
          <ul className="divide-y divide-gray-100">
            {r.campaign.items.map((c) => (
              <li key={c.id} className="py-1.5 text-xs">
                <a href={`#campaign/${c.id}`} className="font-medium text-indigo-700 hover:underline">{c.label}</a>
                <span className="ml-2 text-gray-500">{c.confidence} · {c.member_count} analyses</span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {res && maxTotal > PAGE && (
        <div className="flex items-center gap-2 text-xs">
          <button disabled={offset === 0 || busy} onClick={() => run(Math.max(0, offset - PAGE))}
                  className=" border border-gray-300 bg-white px-2 py-1 disabled:opacity-50">Previous</button>
          <span className="text-gray-500">results {offset + 1}–{Math.min(offset + PAGE, maxTotal)}</span>
          <button disabled={offset + PAGE >= maxTotal || busy} onClick={() => run(offset + PAGE)}
                  className=" border border-gray-300 bg-white px-2 py-1 disabled:opacity-50">Next</button>
        </div>
      )}
    </div>
  )
}
