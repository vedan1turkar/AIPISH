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
import { ErrorAlert, Panel, Spinner, formatDate } from '../ui'
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
      <div className="flex flex-wrap items-center gap-2">
        <a href="#history" className="text-xs text-indigo-600 hover:underline">← History</a>
        <h2 className="text-lg font-semibold text-gray-900">
          <span className="font-mono">{info.case_number}</span>
          {info.title && <span className="ml-2 text-base font-normal text-gray-600">{info.title}</span>}
        </h2>
        <span className="text-[11px] text-gray-400">{info.status} · opened {formatDate(info.created_at)}</span>
      </div>
      {error && <ErrorAlert message={error} onDismiss={() => setError(null)} />}

      <Panel title={`Analyses in this case (${members.length})`}>
        {members.length === 0 ? (
          <p className="text-sm text-gray-500">This case has no analyses.</p>
        ) : (
          <ul className="divide-y divide-gray-100">
            {members.map((m) => (
              <li key={m.analysis.id} className="flex flex-wrap items-center justify-between gap-2 py-2" data-testid="case-member">
                <div className="min-w-0">
                  <a href={`#analysis/${m.analysis.id}`} className="text-sm font-medium text-indigo-700 hover:underline">
                    {m.analysis.subject || '(no subject)'}
                  </a>
                  <span className="ml-2 font-mono text-[11px] text-gray-400">{m.analysis.id.slice(0, 8)}</span>
                  <span className="ml-2 text-[11px] text-gray-400">score {m.analysis.detection_score}</span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {m.campaigns.map((c) => <CampaignBadge key={c.id} id={c.id} label={c.label} confidence={c.confidence} />)}
                  </div>
                </div>
                {canWrite && (
                  <button
                    disabled={busy}
                    onClick={() => act(() => removeCaseAnalysis(id, m.analysis.id))}
                    className="rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:opacity-50"
                  >
                    Remove from case
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {canWrite ? (
          <form onSubmit={onAdd} className="mt-3 flex flex-wrap items-end gap-2" aria-label="Add analysis to case">
            <label className="text-xs font-medium text-gray-700">
              Add analysis
              <select
                value={pick}
                onChange={(e) => setPick(e.target.value)}
                className="mt-1 block max-w-md rounded-lg border border-gray-300 px-2 py-1.5 text-sm"
              >
                <option value="">Choose a stored analysis…</option>
                {candidates.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.id.slice(0, 8)} · {(a.subject || '(no subject)').slice(0, 60)}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="submit"
              disabled={busy || !pick}
              className="rounded-lg bg-indigo-600 px-3 py-2 text-xs font-semibold text-white disabled:bg-gray-300"
            >
              Add to case
            </button>
          </form>
        ) : (
          <p className="mt-3 text-xs text-gray-400" data-testid="case-readonly">Your role can view this case but not change its analyses.</p>
        )}
      </Panel>

      <Panel title="Aggregated indicators">
        <Disclaimer text={disclaimer} />
        {indicators.length === 0 ? (
          <p className="mt-2 text-sm text-gray-500">No indicators recorded for this case's analyses.</p>
        ) : (
          <table className="mt-2 min-w-full text-left text-xs">
            <thead className="text-gray-500">
              <tr><th className="py-1 pr-3">Indicator</th><th className="py-1 pr-3">Type</th><th className="py-1 pr-3">In case</th><th className="py-1 pr-3">All analyses</th><th className="py-1">Link strength</th></tr>
            </thead>
            <tbody>
              {indicators.slice(0, 60).map((i) => (
                <tr key={i.entity_id} className="border-t border-gray-100" data-testid="case-indicator">
                  <td className="py-1 pr-3 font-mono break-all">{i.value}</td>
                  <td className="py-1 pr-3 text-gray-500">{typeLabel(i.type)}</td>
                  <td className="py-1 pr-3">{i.case_count}</td>
                  <td className="py-1 pr-3">{i.df}</td>
                  <td className="py-1">{i.generic_reason ? <span className="text-gray-400">generic: {i.generic_reason}</span> : <TierChip tier={i.tier} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {shared.length > 0 && (
          <p className="mt-2 text-[11px] text-gray-500">{shared.length} indicator(s) appear in more than one analysis of this case.</p>
        )}
      </Panel>
    </div>
  )
}
