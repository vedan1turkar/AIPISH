// Search (P5c): analyses, cases, indicators and candidate campaigns. Never shows email bodies.
import { useState, type FormEvent } from 'react'
import { search, type AnalysisBrief, type SearchKind, type SearchResponse } from '../../api/client'
import {
  Button, DataTable, EmptyLine, ErrorAlert, Field, Input, Mono, Panel, Select, Spinner, StatusTag, formatDate, verdictTone,
} from '../ui'
import { CONFIDENCE_TONE, typeLabel } from '../correlation/model'
import { RiskLevelTag } from '../risk/level'

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
  const qLabel = 'Domain, IP, hash, case or analysis ID, subject…'

  return (
    <div className="space-y-4" data-testid="search-page">
      <div>
        <h1 className="text-xl font-semibold text-fg">Search</h1>
        <p className="text-sm text-muted">Analyses, cases, indicators and candidate campaigns. Email bodies are never searched or shown.</p>
      </div>
      <form onSubmit={onSubmit} aria-label="Search" className="border border-line bg-surface p-3">
        <div className="grid items-end gap-3 md:grid-cols-6 xl:grid-cols-12">
          <div className="md:col-span-6 xl:col-span-4">
            <Field label="Query">
              <Input name="q" placeholder={qLabel} value={q} maxLength={200} onChange={(e) => setQ(e.target.value)} />
            </Field>
          </div>
          <div className="md:col-span-2 xl:col-span-2">
            <Field label="In">
              <Select name="type" value={type} onChange={(e) => setType(e.target.value as SearchKind)}>
                <option value="all">everything</option>
                <option value="analysis">analyses</option>
                <option value="case">cases</option>
                <option value="entity">indicators</option>
                <option value="campaign">campaigns</option>
              </Select>
            </Field>
          </div>
          <div className="md:col-span-2 xl:col-span-2">
            <Field label="Verdict">
              <Select name="verdict" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
                <option value="">any</option>
                <option value="phishing_fraud_likely">phishing_fraud_likely</option>
                <option value="suspicious">suspicious</option>
                <option value="low_risk">low_risk</option>
                <option value="clean">clean</option>
              </Select>
            </Field>
          </div>
          <div className="md:col-span-1 xl:col-span-2">
            <Field label="From">
              <Input type="date" name="date_from" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
            </Field>
          </div>
          <div className="md:col-span-1 xl:col-span-2">
            <Field label="To">
              <Input type="date" name="date_to" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
            </Field>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button type="submit" variant="primary" disabled={busy}>Search</Button>
          {busy && <Spinner label="Searching…" />}
          {res && !busy && <span className="font-mono text-xs text-muted">{total} result{total === 1 ? '' : 's'}</span>}
        </div>
      </form>
      {error && <ErrorAlert message={error} />}
      {!res && !busy && !error && <EmptyLine>Enter a value and press Search. Results are grouped by kind.</EmptyLine>}
      {res && !busy && total === 0 && <EmptyLine>No results. Try a shorter value or another filter.</EmptyLine>}
      {r?.analysis && r.analysis.total > 0 && (
        <Panel title={`Analyses (${r.analysis.total})`} bodyClassName="p-0">
          <div data-testid="search-analyses">
            <DataTable<AnalysisBrief>
              label="Analyses"
              rows={r.analysis.items}
              rowKey={(a) => a.id}
              columns={[
                { key: 'v', header: 'Verdict', render: (a) => (
                  <StatusTag tone={verdictTone(a.detection_verdict)}>{(a.detection_verdict ?? 'unknown').replace(/_/g, ' ')}</StatusTag>) },
                { key: 's', header: 'Score', align: 'right', mono: true, sortValue: (a) => a.detection_score, render: (a) => a.detection_score },
                { key: 'cr', header: 'Combined risk', className: 'whitespace-nowrap', render: (a) => <RiskLevelTag level={a.combined_level} score={a.combined_score} /> },
                { key: 'subj', header: 'Subject', className: 'max-w-0 w-full', render: (a) => (
                  <a href={`#analysis/${a.id}`} className="block truncate font-medium text-accent hover:underline">{a.subject || '(no subject)'}</a>) },
                { key: 'd', header: 'Sender domain', mono: true, className: 'whitespace-nowrap', render: (a) => a.from_domain ?? '—' },
                { key: 'id', header: 'ID', render: (a) => <Mono display={a.id.slice(0, 8)}>{a.id}</Mono> },
                { key: 't', header: 'Received', mono: true, className: 'whitespace-nowrap text-muted',
                  sortValue: (a) => a.created_at ?? '', render: (a) => formatDate(a.created_at) },
              ]}
            />
          </div>
        </Panel>
      )}
      {r?.case && r.case.total > 0 && (
        <Panel title={`Cases (${r.case.total})`} bodyClassName="p-0">
          <DataTable
            label="Cases"
            rows={r.case.items}
            rowKey={(c) => c.id}
            columns={[
              { key: 'n', header: 'Case', mono: true, sortValue: (c) => c.case_number, render: (c) => (
                <a href={`#case/${c.id}`} className="font-medium text-accent hover:underline">{c.case_number}</a>) },
              { key: 'title', header: 'Title', className: 'w-full', render: (c) => c.title ?? <span className="text-muted">—</span> },
              { key: 'st', header: 'Status', render: (c) => <StatusTag tone={c.status === 'open' ? 'accent' : 'neutral'}>{c.status}</StatusTag> },
              { key: 't', header: 'Opened', mono: true, className: 'whitespace-nowrap text-muted', render: (c) => formatDate(c.created_at) },
            ]}
          />
        </Panel>
      )}
      {r?.entity && r.entity.total > 0 && (
        <Panel title={`Indicators (${r.entity.total})`} bodyClassName="p-0">
          <div data-testid="search-entities">
            <DataTable
              label="Indicators"
              rows={r.entity.items}
              rowKey={(e) => e.id}
              columns={[
                { key: 'type', header: 'Type', className: 'whitespace-nowrap text-muted', sortValue: (e) => e.type, render: (e) => typeLabel(e.type) },
                { key: 'v', header: 'Value', mono: true, className: 'w-full break-all', sortValue: (e) => e.value, render: (e) => e.value },
                { key: 'n', header: 'Seen in', align: 'right', className: 'whitespace-nowrap', sortValue: (e) => e.analyses,
                  render: (e) => <span className="text-muted">seen in {e.analyses} analys{e.analyses === 1 ? 'is' : 'es'}</span> },
              ]}
            />
          </div>
        </Panel>
      )}
      {r?.campaign && r.campaign.total > 0 && (
        <Panel title={`Candidate campaigns (${r.campaign.total})`} bodyClassName="p-0">
          <DataTable
            label="Candidate campaigns"
            rows={r.campaign.items}
            rowKey={(c) => c.id}
            columns={[
              { key: 'l', header: 'Campaign', className: 'w-full', render: (c) => (
                <a href={`#campaign/${c.id}`} className="font-medium text-accent hover:underline">{c.label}</a>) },
              { key: 'c', header: 'Confidence', render: (c) => <StatusTag tone={CONFIDENCE_TONE[c.confidence] ?? 'neutral'}>{c.confidence}</StatusTag> },
              { key: 'm', header: 'Members', align: 'right', mono: true, render: (c) => `${c.member_count} analyses` },
            ]}
          />
        </Panel>
      )}
      {res && maxTotal > PAGE && (
        <nav aria-label="Search results pagination" className="flex items-center gap-2 font-mono text-xs text-muted">
          <Button size="sm" disabled={offset === 0 || busy} onClick={() => run(Math.max(0, offset - PAGE))}>Previous</Button>
          <span>results {offset + 1}–{Math.min(offset + PAGE, maxTotal)}</span>
          <Button size="sm" disabled={offset + PAGE >= maxTotal || busy} onClick={() => run(offset + PAGE)}>Next</Button>
        </nav>
      )}
    </div>
  )
}
