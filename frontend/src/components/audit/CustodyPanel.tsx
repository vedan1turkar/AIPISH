// P5e: Custody tab — who did what to this analysis and when (from the tamper-evident audit log), plus
// the evidence-integrity facts and an honest statement of what they do and do not guarantee.
import { useEffect, useState } from 'react'
import { getCustody, type Custody, type CustodyEntry } from '../../api/client'
import { DataTable, ErrorAlert, KV, Mono, Panel, SkeletonRows, StatusTag, formatDate } from '../ui'
import { RetentionTags } from './badges'

const human = (s: string) => s.replace(/_/g, ' ')

function summary(e: CustodyEntry): string {
  const d = e.detail || {}
  const parts: string[] = []
  for (const [k, v] of Object.entries(d)) {
    if (v === null || v === undefined || v === '') continue
    parts.push(`${human(k)}: ${typeof v === 'object' ? JSON.stringify(v) : String(v)}`)
  }
  return parts.join(' · ')
}

export default function CustodyPanel({ analysisId }: { analysisId: string }) {
  const [data, setData] = useState<Custody | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    const ctl = new AbortController()
    setData(null)
    setError(null)
    getCustody(analysisId, ctl.signal).then(setData).catch((err) => {
      if (!(err instanceof DOMException && err.name === 'AbortError'))
        setError(err instanceof Error ? err.message : 'Custody timeline could not be loaded.')
    })
    return () => ctl.abort()
  }, [analysisId])

  if (error) return <ErrorAlert message={`Custody timeline could not be loaded: ${error}`} />
  if (!data) return <Panel title="Custody timeline"><SkeletonRows rows={6} label="Loading custody timeline…" /></Panel>

  return (
    <div className="grid items-stretch gap-4 xl:grid-cols-12" data-testid="custody-panel">
      <Panel title="Custody timeline" className="xl:col-span-8" bodyClassName="p-0 flex flex-col"
             status={<span className="font-mono text-xs">{data.timeline.length} events</span>}>
        <DataTable<CustodyEntry>
          label="Custody timeline"
          rows={data.timeline}
          rowKey={(e) => `${e.at}-${e.action}-${e.actor}`}
          empty="No audit events reference this analysis yet."
          pageSize={25}
          columns={[
            { key: 'at', header: 'When', mono: true, className: 'whitespace-nowrap text-muted', render: (e) => (e.at ? formatDate(e.at) : '—') },
            { key: 'action', header: 'Action', className: 'whitespace-nowrap', render: (e) => human(e.action) },
            { key: 'actor', header: 'Actor', mono: true, className: 'whitespace-nowrap', render: (e) => e.actor ?? <span className="text-muted">system</span> },
            { key: 'outcome', header: 'Outcome', render: (e) => (
              <StatusTag tone={e.outcome === 'success' ? 'ok' : e.outcome ? 'warn' : 'neutral'}>{e.outcome ?? 'n/a'}</StatusTag>) },
            { key: 'detail', header: 'Detail', className: 'max-w-0 w-full', render: (e) => (
              <span className="block truncate text-muted" title={summary(e)}>{summary(e) || '—'}</span>) },
          ]}
        />
        <p className="mt-auto border-t border-line px-3 py-2 text-sm text-muted" data-testid="audit-guarantee">
          {data.audit_guarantee}
        </p>
      </Panel>
      <div className="xl:col-span-4">
        <Panel title="Evidence integrity" className="h-full" status={<RetentionTags state={data.retention_state} held={data.legal_hold} />}>
          <dl>
            <KV label="SHA-256"><Mono display={`${data.sha256.slice(0, 16)}…`}>{data.sha256}</Mono></KV>
            <KV label="Size" mono>{data.size_bytes} bytes</KV>
            <KV label="Stored bytes">{data.evidence_bytes_stored ? 'retained (integrity re-check possible)' : 'not stored (hash only)'}</KV>
            <KV label="Retention">{data.retention_state === 'redacted' ? `redacted ${data.redacted_at ? formatDate(data.redacted_at) : ''}`
              : data.retention_state === 'evidence_purged' ? 'evidence bytes purged' : 'active'}</KV>
            <KV label="Legal hold">{data.legal_hold ? 'yes' : 'no'}</KV>
          </dl>
          <p className="mt-2 text-sm text-muted" data-testid="integrity-note">{data.integrity_note}</p>
        </Panel>
      </div>
    </div>
  )
}
