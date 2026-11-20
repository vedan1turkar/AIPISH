// Investigation case page (P5c): member analyses, add/remove (analyst+), aggregated indicators.
import { useCallback, useEffect, useState, type FormEvent } from 'react'
import {
  addCaseAnalysis,
  getCaseIndicators,
  getInvestigation,
  listAnalyses,
  listCaseAnalyses,
  removeCaseAnalysis,
  type AnalysisSummary,
  type CaseIndicator,
  type CaseMember,
  type InvestigationCase,
} from '../../api/client'
import { useAuth } from '../../auth/AuthContext'
import { Button, EmptyLine, ErrorAlert, Panel, Select, Spinner, StatusTag, formatDate } from '../ui'
import { CampaignBadge, Disclaimer, TierChip } from '../correlation/RelatedPanel'
import { typeLabel } from '../correlation/model'

export default function CasePage({ id }: { id: string }) {
  const { can } = useAuth()
  const canWrite = can('case:write')
  const [info, setInfo] = useState<InvestigationCase | null>(null)
  const [members, setMembers] = useState<CaseMember[] | null>(null)
  const [indicators, setIndicators] = useState<CaseIndicator[]>([])
  const [disclaimer, setDisclaimer] = useState('')
  const [recent, setRecent] = useState<AnalysisSummary[]>([])
  const [pick, setPick] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [c, m, ind] = await Promise.all([getInvestigation(id), listCaseAnalyses(id), getCaseIndicators(id)])
      setInfo(c)
      setMembers(m)
      setIndicators(ind.indicators)
      setDisclaimer(ind.disclaimer)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load the case.')
    }
  }, [id])

  useEffect(() => {
    void refresh()
    if (canWrite) listAnalyses().then(setRecent).catch(() => setRecent([]))
  }, [refresh, canWrite])

  async function act(fn: () => Promise<unknown>) {
    setBusy(true)
    setError(null)
    try {
      await fn()
      await refresh()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.')
    } finally {
      setBusy(false)
    }
  }

  async function onAdd(e: FormEvent) {
    e.preventDefault()
    const analysisId = pick.trim()
    if (!analysisId) return
    await act(async () => {
      await addCaseAnalysis(id, analysisId)
      setPick('')
    })
  }

  if (error && !info) return <ErrorAlert message={error} />
  if (!info || !members) return <Spinner label="Loading case…" />
  const memberIds = new Set(members.map((m) => m.analysis.id))
  const candidates = recent.filter((a) => !memberIds.has(a.id))
  const shared = indicators.filter((i) => i.case_count > 1)

  return (
    <div className="space-y-4" data-testid="case-page">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <a href="#history" className="font-mono text-xs uppercase text-accent hover:underline">History</a>
          <h1 className="text-xl font-semibold text-fg">
            <span className="font-mono">{info.case_number}</span>
            {info.title && <span className="ml-2 font-normal text-muted">{info.title}</span>}
          </h1>
        </div>
        <span className="flex items-center gap-3 text-sm text-muted">
          <StatusTag tone={info.status === 'open' ? 'accent' : 'neutral'}>{info.status}</StatusTag>
          opened <span className="font-mono">{formatDate(info.created_at)}</span>
        </span>
      </div>
      {error && <ErrorAlert message={error} onDismiss={() => setError(null)} />}

      <div className="space-y-4">
        <Panel title={`Analyses in this case (${members.length})`} >
          {members.length === 0 ? (
            <EmptyLine>This case has no analyses.</EmptyLine>
          ) : (
            <ul className="divide-y divide-line">
              {members.map((m) => (
                <li key={m.analysis.id} className="flex flex-wrap items-center justify-between gap-2 py-2 first:pt-0" data-testid="case-member">
                  <div className="min-w-0">
                    <a href={`#analysis/${m.analysis.id}`} className="text-sm text-accent hover:underline">
                      {m.analysis.subject || '(no subject)'}
                    </a>
                    <span className="ml-2 font-mono text-sm text-muted">{m.analysis.id.slice(0, 8)}</span>
                    <span className="ml-2 font-mono text-sm text-muted">score {m.analysis.detection_score}</span>
                    {m.campaigns.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {m.campaigns.map((c) => <CampaignBadge key={c.id} id={c.id} label={c.label} confidence={c.confidence} />)}
                      </div>
                    )}
                  </div>
                  {canWrite && (
                    <Button size="sm" disabled={busy} onClick={() => act(() => removeCaseAnalysis(id, m.analysis.id))}>
                      Remove from case
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {canWrite ? (
            <form onSubmit={onAdd} className="mt-3 flex flex-wrap items-end gap-2 border-t border-line pt-3" aria-label="Add analysis to case">
              <label className="min-w-[16rem] max-w-[40rem] flex-1">
                <span className="mb-1 block font-mono text-xs uppercase tracking-wider text-muted">Add analysis</span>
                <Select value={pick} onChange={(e) => setPick(e.target.value)}>
                  <option value="">Choose a stored analysis…</option>
                  {candidates.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.id.slice(0, 8)} · {(a.subject || '(no subject)').slice(0, 60)}
                    </option>
                  ))}
                </Select>
              </label>
              <Button type="submit" variant="primary" disabled={busy || !pick}>Add to case</Button>
            </form>
          ) : (
            <p className="mt-3 border-t border-line pt-3 text-sm text-muted" data-testid="case-readonly">Your role can view this case but not change its analyses.</p>
          )}
        </Panel>

        <Panel title="Aggregated indicators" bodyClassName="p-0"
               status={shared.length > 0 ? <span className="font-mono text-xs">{shared.length} shared within case</span> : undefined}>
          <div className="border-b border-line p-3"><Disclaimer text={disclaimer} /></div>
          {indicators.length === 0 ? (
            <div className="p-3"><EmptyLine>No indicators recorded for this case's analyses.</EmptyLine></div>
          ) : (
            <div className="max-h-[32rem] overflow-auto">
              <table className="w-full text-sm" aria-label="Aggregated indicators">
                <thead className="sticky top-0 bg-surface">
                  <tr className="whitespace-nowrap font-mono text-xs uppercase tracking-wider text-muted">
                    <th className="h-8 border-b border-line px-3 text-left font-normal">Indicator</th>
                    <th className="h-8 border-b border-line px-3 text-left font-normal">Type</th>
                    <th className="h-8 border-b border-line px-3 text-right font-normal">In case</th>
                    <th className="h-8 border-b border-line px-3 text-right font-normal">All</th>
                    <th className="h-8 border-b border-line px-3 text-left font-normal">Link strength</th>
                  </tr>
                </thead>
                <tbody>
                  {indicators.slice(0, 60).map((i) => (
                    <tr key={i.entity_id} className="h-row border-b border-line last:border-0 hover:bg-surface-2" data-testid="case-indicator">
                      <td className="break-all px-3 py-1 font-mono">{i.value}</td>
                      <td className="whitespace-nowrap px-3 py-1 text-muted">{typeLabel(i.type)}</td>
                      <td className="px-3 py-1 text-right font-mono">{i.case_count}</td>
                      <td className="px-3 py-1 text-right font-mono">{i.df}</td>
                      <td className="px-3 py-1">{i.generic_reason ? <span className="text-muted">generic: {i.generic_reason}</span> : <TierChip tier={i.tier} />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}
