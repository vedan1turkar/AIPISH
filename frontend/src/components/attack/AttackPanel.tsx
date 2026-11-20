// ATT&CK tab (P5d): techniques by tactic, observed/inferred basis, evidence navigation,
// source-type hypotheses. Informational only: never part of the score or verdict.
import type { AttackEvidence, AttackHistoryItem, AttackMappingResult, AttackTechniqueMapping, SourceTypeHypothesis } from '../../api/client'
import { EmptyState, ErrorAlert, Panel, Spinner, formatDate } from '../ui'
import { EvidenceChip } from '../assessment/AssessmentPanels'

// ATT&CK Enterprise tactic order (v20).
export const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Stealth', 'Defense Impairment', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
  'Command and Control', 'Exfiltration', 'Impact',
]

export const BAND_LABEL: Record<string, string> = {
  likely: 'Likely',
  possible: 'Possible',
  not_indicated: 'Not indicated (not proof of safety)',
  undetermined: 'Undetermined: insufficient evidence',
  not_assessed: 'Not assessed',
}

const BAND_STYLE: Record<string, string> = {
  likely: 'bg-rose-50 text-rose-800 ring-rose-200',
  possible: 'bg-amber-50 text-amber-800 ring-amber-200',
  not_indicated: 'bg-slate-50 text-slate-700 ring-slate-200',
  undetermined: 'bg-gray-50 text-gray-600 ring-gray-200',
  not_assessed: 'bg-indigo-50 text-indigo-800 ring-indigo-200',
}

const TAB_LABEL: Record<string, string> = {
  findings: 'Findings', auth: 'Authentication', headers: 'Headers & relay', intel: 'IP & domain intel',
  threat: 'Threat intel', ai: 'AI assessment', overview: 'Overview',
}

export function groupByTactic(mappings: AttackTechniqueMapping[]): [string, AttackTechniqueMapping[]][] {
  const groups = new Map<string, AttackTechniqueMapping[]>()
  for (const m of mappings) {
    const t = m.tactics[0] ?? 'Other'
    groups.set(t, [...(groups.get(t) ?? []), m])
  }
  const rank = (t: string) => (TACTIC_ORDER.indexOf(t) === -1 ? 99 : TACTIC_ORDER.indexOf(t))
  return Array.from(groups.entries()).sort((a, b) => rank(a[0]) - rank(b[0]))
}

function Chips({ ids, label }: { ids: string[]; label: string }) {
  if (ids.length === 0) return null
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className="text-xs text-gray-500">{label}:</span>
      {ids.map((id) => <EvidenceChip key={id} id={id} title={`Go to evidence ${id}`} />)}
    </span>
  )
}

function TechniqueCard({ m }: { m: AttackTechniqueMapping }) {
  return (
    <li className="py-2.5 first:pt-0 last:pb-0" data-testid="attack-technique">
      <div className="flex flex-wrap items-center gap-2">
        <a href={m.url} target="_blank" rel="noopener noreferrer" className="font-mono text-sm font-semibold text-indigo-700 hover:underline">
          {m.technique_id}
        </a>
        <span className="text-sm font-medium text-gray-900">{m.name}</span>
        <span
          data-testid="basis-badge"
          className={` px-1.5 py-0.5 text-xs font-bold uppercase ring-1 ${
 m.basis === 'observed' ? 'bg-emerald-50 text-emerald-800 ring-emerald-300' : 'bg-sky-50 text-sky-800 ring-sky-300'
 }`}
        >
          {m.basis === 'observed' ? 'Observed' : 'Inferred'}
        </span>
        <span className="text-xs text-gray-600">confidence: <strong>{m.confidence}</strong></span>
        <span className="font-mono text-xs text-gray-400">{m.mapping_rule_id}</span>
      </div>
      <p className="mt-1 text-sm text-fg">{m.rationale}</p>
      {m.limitations && <p className="mt-0.5 text-sm text-muted">Limitation: {m.limitations}</p>}
      <div className="mt-1.5 flex flex-wrap gap-3">
        <Chips ids={m.evidence_ids} label="Evidence" />
        <Chips ids={m.supporting_evidence_ids} label="Supporting (not basis)" />
      </div>
    </li>
  )
}

function HypothesisRow({ h }: { h: SourceTypeHypothesis }) {
  const band = h.band === 'not_assessed' && h.reason ? `Not assessed: ${h.reason}` : BAND_LABEL[h.band] ?? h.band
  return (
    <li className="py-2" data-testid="hypothesis">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-gray-900">{h.label}</span>
        <span className={` px-2 py-0.5 text-xs font-semibold ring-1 ${BAND_STYLE[h.band] ?? BAND_STYLE.undetermined}`} data-testid="band">
          {band}
        </span>
      </div>
      <p className="mt-0.5 text-xs text-gray-600">{h.rationale}</p>
      {h.missing_data.length > 0 && h.band !== 'not_assessed' && (
        <p className="mt-0.5 text-xs text-gray-500">Missing data: {h.missing_data.join('; ')}</p>
      )}
      <div className="mt-1"><Chips ids={h.evidence_ids} label="Evidence" /></div>
    </li>
  )
}

function EvidenceList({ items, onNavigate }: { items: AttackEvidence[]; onNavigate?: (tab: string) => void }) {
  return (
    <ul className="space-y-1.5">
      {items.map((e) => (
        <li
          key={e.id}
          id={`evidence-${e.id}`}
          tabIndex={-1}
          className=" border border-gray-100 bg-gray-50 px-2 py-1.5 text-xs transition-shadow"
          data-testid="attack-evidence"
        >
          <span className="mr-2 font-mono font-semibold text-indigo-700">{e.id}</span>
          <span className="mr-2 bg-white px-1 py-0.5 text-xs uppercase text-gray-500 ring-1 ring-gray-200">{e.category}</span>
          <span className="text-gray-800">{e.statement}</span>
          <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-gray-400">
            <span className="font-mono">{e.source_field}</span>
            {onNavigate && TAB_LABEL[e.tab] && (
              <button onClick={() => onNavigate(e.tab)} className="text-indigo-600 hover:underline" data-testid="evidence-open-tab">
                Open in {TAB_LABEL[e.tab]} tab
              </button>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}

export default function AttackPanel({
  data,
  loading,
  error,
  history,
  canRecompute,
  recomputing,
  recomputeError,
  onRecompute,
  onSelectVersion,
  onNavigate,
}: {
  data: AttackMappingResult | null
  loading: boolean
  error: string | null
  history: AttackHistoryItem[]
  canRecompute: boolean
  recomputing: boolean
  recomputeError: string | null
  onRecompute: () => void
  onSelectVersion: (version: number) => void
  onNavigate?: (tab: string) => void
}) {
  if (loading) return <Spinner label="Loading ATT&CK mapping…" />
  if (error) return <ErrorAlert message={`Could not load the ATT&CK mapping: ${error}`} />
  const recompute = canRecompute && (
    <button
      onClick={onRecompute}
      disabled={recomputing}
      data-testid="attack-recompute"
      className="h-8 border border-line-strong bg-surface-2 px-3 text-sm font-medium text-fg hover:bg-surface-3 disabled:text-muted"
    >
      {recomputing ? 'Recomputing…' : 'Recompute (uses latest intel run and ML assessment)'}
    </button>
  )
  if (!data)
    return (
      <div className="space-y-3">
        <EmptyState title="No ATT&CK mapping has been computed yet" hint="It is computed automatically for new analyses." />
        {recompute}
        {recomputeError && <ErrorAlert message={recomputeError} />}
      </div>
    )
  const grouped = groupByTactic(data.mappings)
  return (
    <div className="space-y-4" data-testid="attack-panel">
      <p className=" border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600" data-testid="attack-disclaimer">
        {data.disclaimer}
      </p>
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-gray-500">
        <span>
          MITRE ATT&amp;CK Enterprise {data.attack_version} · {data.catalog_version}
          {data.catalog_verified ? ' · IDs verified against official data' : ' · IDs NOT verified against official data'} · {data.engine_version} ·
          version {data.version} ({data.source}) · {formatDate(data.created_at)}
          {data.inputs.intel_run_id ? ` · intel run ${data.inputs.intel_run_id.slice(0, 8)}` : ' · no intel run'}
          {data.inputs.intel_simulated && <strong className="ml-1 text-fuchsia-700">SIMULATED provider data</strong>}
        </span>
        <span className="flex items-center gap-2">
          {history.length > 1 && (
            <select
              aria-label="ATT&CK mapping version"
              value={data.version}
              onChange={(e) => onSelectVersion(Number(e.target.value))}
              className=" border border-gray-300 px-1 py-0.5 text-xs"
            >
              {history.map((h) => (
                <option key={h.version} value={h.version}>v{h.version} · {h.source} · {h.technique_count} techniques</option>
              ))}
            </select>
          )}
          {recompute}
        </span>
      </div>
      {recomputeError && <ErrorAlert message={recomputeError} />}
      {data.new_version === false && <p className="text-xs text-gray-500">Recomputed: no change, so no new version was stored.</p>}

      <Panel title={`ATT&CK techniques (${data.mappings.length})`}>
        {data.mappings.length === 0 ? (
          <EmptyState title={data.empty_state ?? 'No ATT&CK techniques could be mapped from the available evidence.'}
                      hint="Nothing is mapped without evidence." />
        ) : (
          <div className="space-y-3">
            {grouped.map(([tactic, items]) => (
              <section key={tactic} data-testid="tactic-group">
                <h4 className="mb-1 border-b border-line pb-1 font-mono text-xs uppercase tracking-wider text-muted">{tactic}</h4>
                <ul className="divide-y divide-line">{items.map((m) => <TechniqueCard key={m.technique_id} m={m} />)}</ul>
              </section>
            ))}
          </div>
        )}
        <p className="mt-2 text-xs text-gray-500">{data.note} Observed = directly present in the message; inferred = a reasoned interpretation. ML output can only support a mapping.</p>
      </Panel>

      <Panel title="Source type (independent hypotheses, not a verdict)">
        <ul className="divide-y divide-gray-100">{data.source_type.map((h) => <HypothesisRow key={h.hypothesis} h={h} />)}</ul>
        <p className="mt-2 text-xs text-gray-500">Infrastructure and account hypotheses only. Absence of reports is not evidence of safety.</p>
      </Panel>

      {data.evidence.length > 0 && (
        <Panel title="Evidence cited above">
          <EvidenceList items={data.evidence} onNavigate={onNavigate} />
        </Panel>
      )}
    </div>
  )
}
