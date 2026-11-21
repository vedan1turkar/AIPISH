// P5e Retention page (admin): policy, dry-run preview, apply with explicit confirmation, legal holds,
// last-run summary. Nothing is purged unless a retention period is configured and a run is applied.
import { useCallback, useEffect, useState } from 'react'
import {
  clearLegalHold, getRetentionStatus, runRetention, setLegalHold,
  type LegalHoldRow, type RetentionRunResult, type RetentionStatus,
} from '../../api/client'
import {
  Button, DataTable, EmptyLine, ErrorAlert, Field, Input, KV, LED, Mono, Panel, Select, SkeletonRows, StatCell,
  StatusTag, formatDate,
} from '../ui'

function ConfirmApply({ result, mode, onCancel, onConfirm, busy }: {
  result: RetentionRunResult; mode: string; onCancel: () => void; onConfirm: () => void; busy: boolean
}) {
  const [typed, setTyped] = useState('')
  const n = result.eligible_analyses.length
  const ev = result.eligible_evidence_only.length
  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-[rgba(10,14,19,0.85)] p-4"
         onKeyDown={(e) => { if (e.key === 'Escape') onCancel() }}>
      <div role="dialog" aria-modal="true" aria-labelledby="apply-title" className="w-full max-w-[520px] border border-line-strong bg-surface">
        <div className="flex h-8 items-center border-b border-line px-3">
          <h2 id="apply-title" className="font-mono text-xs uppercase tracking-wider text-muted">Apply retention policy</h2>
        </div>
        <div className="space-y-3 p-4 text-sm text-fg">
          <p>
            This will <strong className="font-semibold">{mode === 'delete' ? 'permanently delete' : 'redact'}</strong> {n} analys{n === 1 ? 'is' : 'es'}
            {ev ? ` and remove stored evidence bytes from ${ev} more` : ''}. Items under legal hold are skipped. Audit events are kept.
            {mode === 'delete' ? ' Deleted analyses cannot be restored.' : ' Redacted content cannot be restored.'}
          </p>
          <Field label='Type "APPLY" to confirm'>
            <Input autoFocus value={typed} onChange={(e) => setTyped(e.target.value)} aria-label="Confirmation text" />
          </Field>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={onCancel}>Cancel</Button>
            <Button variant="danger" disabled={typed !== 'APPLY' || busy} onClick={onConfirm}>{busy ? 'Applying…' : 'Apply now'}</Button>
          </div>
        </div>
      </div>
    </div>
  )
}

function HoldRow({ h, onCleared }: { h: LegalHoldRow; onCleared: () => void }) {
  const [reason, setReason] = useState('')
  const [err, setErr] = useState<string | null>(null)
  return (
    <form className="flex items-center gap-2" onSubmit={async (e) => {
      e.preventDefault()
      try { await clearLegalHold(h.id, reason); onCleared() } catch (x) { setErr(x instanceof Error ? x.message : 'failed') }
    }}>
      <Input className="!h-7 !w-48" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="reason to clear"
             aria-label={`Reason to clear hold on ${h.target_type} ${h.target_id}`} />
      <Button size="sm" type="submit" disabled={reason.trim().length < 3}>Clear</Button>
      {err && <span className="text-xs text-danger">{err}</span>}
    </form>
  )
}

export default function RetentionPage() {
  const [st, setSt] = useState<RetentionStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [preview, setPreview] = useState<RetentionRunResult | null>(null)
  const [applied, setApplied] = useState<RetentionRunResult | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [hold, setHold] = useState<{ type: 'analysis' | 'case'; id: string; reason: string }>({ type: 'analysis', id: '', reason: '' })

  const load = useCallback(() => {
    getRetentionStatus().then(setSt).catch((err) => setError(err instanceof Error ? err.message : 'Status could not be loaded.'))
  }, [])
  useEffect(load, [load])

  async function dryRun() {
    setBusy(true)
    setApplied(null)
    try { setPreview(await runRetention(true)) } catch (err) { setError(err instanceof Error ? err.message : 'Dry run failed.') }
    finally { setBusy(false) }
  }
  async function apply() {
    setBusy(true)
    try {
      setApplied(await runRetention(false))
      setPreview(null)
      setConfirming(false)
      load()
    } catch (err) { setError(err instanceof Error ? err.message : 'Apply failed.') } finally { setBusy(false) }
  }

  if (!st && !error) return <div className="space-y-4"><h1 className="text-xl font-semibold text-fg">Retention</h1><Panel title="Policy"><SkeletonRows rows={5} label="Loading retention status…" /></Panel></div>
  const p = st?.policy

  return (
    <div className="space-y-4" data-testid="retention-page">
      <div>
        <h1 className="text-xl font-semibold text-fg">Retention</h1>
        <p className="text-sm text-muted">Nothing is purged unless a retention period is configured and a run is applied. Audit events are never purged. There is no built-in scheduler.</p>
      </div>
      {error && <ErrorAlert message={error} onDismiss={() => setError(null)} />}
      {st && p && (
        <>
          <section aria-label="Retention totals" className="grid grid-cols-2 divide-x divide-y divide-line border border-line bg-surface md:grid-cols-4 md:divide-y-0">
            <StatCell label="Eligible now" value={st.eligible_analyses} sub={p.enabled ? `mode: ${p.mode}` : 'policy disabled'} />
            <StatCell label="Evidence bytes only" value={st.eligible_evidence_only} sub="raw bytes past evidence period" />
            <StatCell label="Held (skipped)" value={st.held_skipped} sub={`${st.holds.length} active holds`} tone={st.holds.length ? 'accent' : undefined} />
            <StatCell label="Redacted total" value={st.redacted_total} sub="content removed, record kept" />
          </section>
          <div className="grid items-stretch gap-4 xl:grid-cols-12">
            <Panel title="Policy" className="xl:col-span-5" status={p.enabled ? <StatusTag tone="warn">enabled</StatusTag> : <StatusTag tone="neutral">disabled</StatusTag>}>
              <dl>
                <KV label="Mode">{p.mode === 'delete' ? 'delete: analysis and every dependent row' : 'redact: remove personal content, keep hashes, IOCs and scores'}</KV>
                <KV label="Analysis period" mono>{p.analysis_days ? `${p.analysis_days} days` : 'disabled (0)'}</KV>
                <KV label="Evidence period" mono>{p.evidence_days ? `${p.evidence_days} days` : 'disabled (0)'}</KV>
                <KV label="Grace" mono>{p.grace_days} days</KV>
                <KV label="Audit events">never purged</KV>
                <KV label="Scheduler">{st.scheduler}</KV>
              </dl>
            </Panel>
            <Panel title="Run" className="xl:col-span-7">
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => void dryRun()} disabled={busy}>Preview (dry run)</Button>
                <Button variant="danger" disabled={busy || !p.enabled || !preview || (preview.eligible_analyses.length + preview.eligible_evidence_only.length === 0)}
                        onClick={() => setConfirming(true)}>Apply…</Button>
              </div>
              {!p.enabled && <p className="mt-2 text-sm text-muted">Set RETENTION_ANALYSIS_DAYS or RETENTION_EVIDENCE_DAYS to enable applying.</p>}
              {preview && (
                <div className="mt-3" data-testid="retention-preview">
                  <p className="flex items-center gap-2 text-sm text-fg"><LED tone="accent" />Dry run: nothing changed. {preview.eligible_analyses.length} eligible, {preview.eligible_evidence_only.length} evidence-only, {preview.held_skipped.length} held.</p>
                  {preview.eligible_analyses.length > 0 && (
                    <p className="mt-1 break-all font-mono text-xs text-muted">{preview.eligible_analyses.slice(0, 20).join(' · ')}{preview.eligible_analyses.length > 20 ? ' …' : ''}</p>
                  )}
                </div>
              )}
              {applied && (
                <p className="mt-3 flex items-center gap-2 text-sm text-fg" role="status" data-testid="retention-applied">
                  <LED tone="ok" />Applied: {applied.redacted.length} redacted, {applied.deleted.length} deleted, {applied.evidence_purged.length} evidence purged, {applied.held_skipped.length} held, {applied.errors.length} errors.
                </p>
              )}
              <div className="mt-3 border-t border-line pt-2">
                {st.last_run ? (
                  <dl>
                    <KV label="Last run" mono>{formatDate(st.last_run.at)}</KV>
                    <KV label="Type">{st.last_run.detail.dry_run ? 'dry run' : 'applied'} · {String(st.last_run.detail.source ?? '')}</KV>
                  </dl>
                ) : <EmptyLine>No retention run recorded yet.</EmptyLine>}
              </div>
            </Panel>
          </div>
          <Panel title="Legal holds" bodyClassName="p-0" status={<span className="font-mono text-xs">{st.holds.length} active</span>}>
            <form className="grid items-end gap-3 border-b border-line p-3 md:grid-cols-12" aria-label="Set legal hold"
                  onSubmit={async (e) => {
                    e.preventDefault()
                    try { await setLegalHold(hold.type, hold.id.trim(), hold.reason); setHold({ ...hold, id: '', reason: '' }); load() }
                    catch (x) { setError(x instanceof Error ? x.message : 'Hold failed.') }
                  }}>
              <div className="md:col-span-2"><Field label="Target"><Select value={hold.type} onChange={(e) => setHold({ ...hold, type: e.target.value as 'analysis' | 'case' })}>
                <option value="analysis">analysis</option><option value="case">case</option></Select></Field></div>
              <div className="md:col-span-4"><Field label="Id"><Input value={hold.id} onChange={(e) => setHold({ ...hold, id: e.target.value })} /></Field></div>
              <div className="md:col-span-4"><Field label="Reason (required)"><Input value={hold.reason} onChange={(e) => setHold({ ...hold, reason: e.target.value })} /></Field></div>
              <div className="md:col-span-2"><Button type="submit" className="w-full" disabled={!hold.id.trim() || hold.reason.trim().length < 3}>Set hold</Button></div>
            </form>
            <DataTable<LegalHoldRow>
              label="Active legal holds"
              rows={st.holds}
              rowKey={(h) => h.id}
              empty="No active legal holds."
              columns={[
                { key: 'type', header: 'Target', className: 'whitespace-nowrap', render: (h) => <StatusTag tone="accent">{h.target_type}</StatusTag> },
                { key: 'id', header: 'Id', render: (h) => <Mono display={h.target_id.slice(0, 12)}>{h.target_id}</Mono> },
                { key: 'reason', header: 'Reason', className: 'max-w-0 w-full', render: (h) => <span className="block truncate" title={h.reason}>{h.reason}</span> },
                { key: 'at', header: 'Since', mono: true, className: 'whitespace-nowrap text-muted', render: (h) => formatDate(h.created_at) },
                { key: 'clear', header: 'Clear', render: (h) => <HoldRow h={h} onCleared={load} /> },
              ]}
            />
          </Panel>
        </>
      )}
      {confirming && preview && p && (
        <ConfirmApply result={preview} mode={p.mode} busy={busy} onCancel={() => setConfirming(false)} onConfirm={() => void apply()} />
      )}
    </div>
  )
}
