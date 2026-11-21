// P5e Audit page (admin): chain status + verify, checkpoint, filterable server-paginated events, export.
import { useCallback, useEffect, useState } from 'react'
import {
  createAuditCheckpoint, exportAudit, getAuditCheckpoint, getAuditEvents, verifyAudit,
  type AuditCheckpoint, type AuditEventRow, type AuditFilters, type AuditPage as AuditPageData, type AuditVerify,
} from '../../api/client'
import { Button, DataTable, EmptyLine, ErrorAlert, Field, Input, KV, LED, Mono, Panel, Select, SkeletonRows, StatusTag, formatDate } from '../ui'

const PAGE_SIZE = 50
const human = (s: string) => s.replace(/_/g, ' ')

function ChainStatus({ v }: { v: AuditVerify | null }) {
  if (!v) return <StatusTag tone="neutral">not verified</StatusTag>
  return v.ok ? <StatusTag tone="ok">chain OK</StatusTag> : <StatusTag tone="danger">chain BROKEN</StatusTag>
}

export default function AuditPage() {
  const [verify, setVerify] = useState<AuditVerify | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [cp, setCp] = useState<AuditCheckpoint | null | undefined>(undefined)
  const [advice, setAdvice] = useState('')
  const [guarantee, setGuarantee] = useState('')
  const [draft, setDraft] = useState<AuditFilters>({})
  const [filters, setFilters] = useState<AuditFilters>({})
  const [page, setPage] = useState(1)
  const [data, setData] = useState<AuditPageData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const runVerify = useCallback(async () => {
    setVerifying(true)
    try {
      const v = await verifyAudit()
      setVerify(v)
      setGuarantee(v.guarantee)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed.')
    } finally {
      setVerifying(false)
    }
  }, [])

  useEffect(() => { void runVerify() }, [runVerify])
  useEffect(() => {
    getAuditCheckpoint().then((c) => { setCp(c.latest); setAdvice(c.advice); setGuarantee(c.guarantee) })
      .catch(() => setCp(null))
  }, [])
  useEffect(() => {
    const ctl = new AbortController()
    setData(null)
    getAuditEvents(filters, page, PAGE_SIZE, ctl.signal).then(setData).catch((err) => {
      if (!(err instanceof DOMException && err.name === 'AbortError'))
        setError(err instanceof Error ? err.message : 'Audit events could not be loaded.')
    })
    return () => ctl.abort()
  }, [filters, page])

  async function checkpoint() {
    try {
      const r = await createAuditCheckpoint()
      setCp(r.latest)
      setNotice(`Checkpoint recorded at seq ${r.checkpoint.seq}. Copy the seq and hash to a place outside this system.`)
      setPage(1)
      setFilters({ ...filters })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Checkpoint failed.')
    }
  }

  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1
  const set = (k: keyof AuditFilters) => (e: { target: { value: string } }) => setDraft({ ...draft, [k]: e.target.value || undefined })

  return (
    <div className="space-y-4" data-testid="audit-page">
      <div>
        <h1 className="text-xl font-semibold text-fg">Audit log</h1>
        <p className="text-sm text-muted">{guarantee || 'Tamper-evident (HMAC hash chain), not tamper-proof.'}</p>
      </div>
      {error && <ErrorAlert message={error} onDismiss={() => setError(null)} />}
      {notice && <p className="flex items-center gap-2 border border-line bg-surface px-3 py-1.5 text-sm text-fg" role="status"><LED tone="ok" />{notice}</p>}

      <div className="grid items-stretch gap-4 xl:grid-cols-12">
        <Panel title="Chain integrity" className="xl:col-span-6" status={<ChainStatus v={verify} />}>
          <dl>
            <KV label="Events checked" mono>{verify ? verify.checked : '—'}</KV>
            <KV label="Last seq" mono>{verify ? verify.last_seq : '—'}</KV>
            <KV label="First broken seq" mono>{verify?.first_broken_seq ?? 'none'}</KV>
            <KV label="Reason">{verify?.reason ?? (verify ? 'every HMAC, link and the chain head match' : 'not verified yet')}</KV>
          </dl>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void runVerify()} disabled={verifying}>{verifying ? 'Verifying…' : 'Verify now'}</Button>
          </div>
        </Panel>
        <Panel title="External checkpoint" className="xl:col-span-6">
          {cp === undefined ? <SkeletonRows rows={3} label="Loading checkpoint…" /> : cp === null ? (
            <EmptyLine>No checkpoint recorded yet. Create one and keep its seq and hash outside this system.</EmptyLine>
          ) : (
            <dl>
              <KV label="Seq" mono>{cp.seq}</KV>
              <KV label="Hash"><Mono display={`${cp.event_hash.slice(0, 20)}…`}>{cp.event_hash}</Mono></KV>
              <KV label="Recorded" mono>{cp.created_at ? formatDate(cp.created_at) : '—'}{cp.by ? ` by ${cp.by}` : ''}</KV>
            </dl>
          )}
          {advice && <p className="mt-2 text-sm text-muted">{advice}</p>}
          <div className="mt-3 flex flex-wrap gap-2">
            <Button onClick={() => void checkpoint()}>Create checkpoint</Button>
            <Button variant="ghost" onClick={() => void exportAudit('csv', filters).catch((e) => setError(String(e?.message ?? e)))}>Export CSV</Button>
            <Button variant="ghost" onClick={() => void exportAudit('json', filters).catch((e) => setError(String(e?.message ?? e)))}>Export JSON</Button>
          </div>
        </Panel>
      </div>

      <Panel title="Events" bodyClassName="p-0" status={data ? <span className="font-mono text-xs">{data.total} events</span> : undefined}>
        <form className="grid gap-3 border-b border-line p-3 md:grid-cols-4 xl:grid-cols-7" aria-label="Audit filters"
              onSubmit={(e) => { e.preventDefault(); setPage(1); setFilters(draft) }}>
          <Field label="Actor"><Input value={draft.actor ?? ''} onChange={set('actor')} placeholder="username" /></Field>
          <Field label="Action">
            <Select value={draft.action ?? ''} onChange={set('action')}>
              <option value="">any</option>
              {(data?.actions ?? []).map((a) => <option key={a} value={a}>{human(a)}</option>)}
            </Select>
          </Field>
          <Field label="Target type">
            <Select value={draft.target_type ?? ''} onChange={set('target_type')}>
              <option value="">any</option>
              {['analysis', 'case', 'user', 'search', 'audit', 'retention', 'file'].map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </Field>
          <Field label="Target id"><Input value={draft.target_id ?? ''} onChange={set('target_id')} /></Field>
          <Field label="Outcome">
            <Select value={draft.outcome ?? ''} onChange={set('outcome')}>
              <option value="">any</option>
              {['success', 'failure', 'denied'].map((t) => <option key={t} value={t}>{t}</option>)}
            </Select>
          </Field>
          <Field label="From"><Input type="date" value={draft.date_from ?? ''} onChange={set('date_from')} /></Field>
          <Field label="To"><Input type="date" value={draft.date_to ?? ''} onChange={set('date_to')} /></Field>
          <div className="flex items-end gap-2 md:col-span-4 xl:col-span-7">
            <Button type="submit" variant="primary">Apply filters</Button>
            <Button type="button" variant="ghost" onClick={() => { setDraft({}); setFilters({}); setPage(1) }}>Clear</Button>
          </div>
        </form>
        {!data ? <div className="p-3"><SkeletonRows rows={8} label="Loading audit events…" /></div> : (
          <>
            <DataTable<AuditEventRow>
              label="Audit events"
              rows={data.items}
              rowKey={(e) => e.id}
              rowTestId={() => 'audit-row'}
              empty="No audit events match these filters."
              columns={[
                { key: 'seq', header: 'Seq', align: 'right', mono: true, render: (e) => e.seq ?? '—' },
                { key: 'at', header: 'When', mono: true, className: 'whitespace-nowrap text-muted', render: (e) => (e.at ? formatDate(e.at) : '—') },
                { key: 'action', header: 'Action', className: 'whitespace-nowrap', render: (e) => human(e.action) },
                { key: 'actor', header: 'Actor', mono: true, className: 'whitespace-nowrap', render: (e) => e.actor ?? <span className="text-muted">{e.actor_id ? e.actor_id.slice(0, 8) : 'system'}</span> },
                { key: 'target', header: 'Target', mono: true, className: 'whitespace-nowrap', render: (e) => e.target_type ? `${e.target_type}${e.target_id ? ` ${e.target_id.slice(0, 10)}` : ''}` : '—' },
                { key: 'outcome', header: 'Outcome', render: (e) => (
                  <StatusTag tone={e.outcome === 'success' ? 'ok' : e.outcome === 'failure' || e.outcome === 'denied' ? 'warn' : 'neutral'}>{e.outcome ?? 'n/a'}</StatusTag>) },
                { key: 'ip', header: 'Source IP', mono: true, className: 'whitespace-nowrap text-muted', hideBelow: 'xl', render: (e) => e.source_ip ?? '—' },
                { key: 'detail', header: 'Detail', className: 'max-w-0 w-full', render: (e) => {
                  const t = JSON.stringify(e.detail)
                  return <span className="block truncate font-mono text-xs text-muted" title={t}>{t === '{}' ? '—' : t}</span>
                } },
                { key: 'hash', header: 'Hash', mono: true, className: 'whitespace-nowrap text-muted', render: (e) => e.hash_prefix || '—' },
              ]}
            />
            {data.total > PAGE_SIZE && (
              <nav aria-label="Audit events pagination" className="flex items-center justify-between border-t border-line px-3 py-1.5 font-mono text-xs text-muted">
                <span>page {page} of {pages} · newest first</span>
                <span className="flex gap-1">
                  <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => setPage(page - 1)}>Newer</Button>
                  <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => setPage(page + 1)}>Older</Button>
                </span>
              </nav>
            )}
          </>
        )}
      </Panel>
    </div>
  )
}
