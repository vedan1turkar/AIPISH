import { useState, type ReactNode } from 'react'
import type {
  Assessment,
  AssessmentSummary,
  ForensicSummary,
  LlmStatus,
  MlStatus,
  ShapExplanation,
  MlResult,
  Recommendation,
} from '../../api/client'
import { EmptyState, ErrorAlert, Panel, Spinner, StatusBadge, formatDate } from '../ui'
import {
  basisKind,
  categoryMeta,
  componentName,
  componentState,
  evidenceIndex,
  findingRefs,
  formatScore,
  isHashOnly,
  mlView,
  PRIVACY_NOTE,
  recommendationGroups,
  financialWarning,
  shapComponentView,
  shapCoverage,
  shapRows,
  type ComponentState,
} from './model'

// ── shared bits ────────────────────────────────────────────────────────────
export function RunStatus({ state }: { state: ComponentState }) {
  const cls = state.ran
    ? 'bg-emerald-100 text-emerald-800 ring-emerald-300'
    : state.status === 'missing'
      ? 'bg-gray-100 text-gray-600 ring-gray-300'
      : 'bg-orange-100 text-orange-800 ring-orange-300'
  return (
    <span
      data-testid="run-status"
      data-status={state.status}
      className={`inline-flex items-center px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}
    >
      {state.title}
    </span>
  )
}

function NotRun({ state, children }: { state: ComponentState; children?: ReactNode }) {
  return (
    <div className=" border border-orange-200 bg-orange-50 px-3 py-2 text-sm text-orange-900" role="status">
      <p>{state.message || 'This component did not produce a result.'}</p>
      {children}
    </div>
  )
}

const HASH_ONLY_NOTE =
  'The original email bytes were not kept for this analysis, because the evidence policy is hash_only ' +
  '(only the SHA-256 is stored). The ML classifier and SHAP must read the original bytes, so they cannot ' +
  'run on this stored analysis. To include them, upload the .eml again with "Run AI assessment" selected.'

/** Scroll to, focus and briefly highlight an evidence row. Never changes the URL. */
export function scrollToEvidence(id: string): boolean {
  const el = document.getElementById(`evidence-${id}`)
  if (!el) return false
  el.scrollIntoView?.({ behavior: 'smooth', block: 'center' })
  el.focus({ preventScroll: true })
  el.classList.add('ring-2', 'ring-indigo-400')
  el.setAttribute('data-highlighted', 'true')
  window.setTimeout(() => {
    el.classList.remove('ring-2', 'ring-indigo-400')
    el.removeAttribute('data-highlighted')
  }, 1600)
  return true
}

export function EvidenceChip({ id, title }: { id: string; title: string }) {
  return (
    <a
      href={`#evidence-${id}`}
      onClick={(e) => {
        e.preventDefault()
        scrollToEvidence(id)
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault() // handled here once; also stops Enter from navigating
          scrollToEvidence(id)
        }
      }}
      title={title}
      aria-label={`Go to evidence ${id}`}
      className=" bg-gray-100 px-1.5 py-0.5 font-mono text-xs text-indigo-700 hover:bg-indigo-50 focus:outline-none focus:ring-2 focus:ring-indigo-400"
    >
      {id}
    </a>
  )
}

// ── A. ML classification ──────────────────────────────────────────────────
export function MlPanel({ ml, mlStatus }: { ml: MlResult | null | undefined; mlStatus?: MlStatus | null }) {
  const v = mlView(ml)
  const weights = mlStatus?.ensemble_weights
  const parts = weights
    ? Object.entries(weights).filter(([, w]) => w > 0).map(([k, w]) => `${componentName(k)} ${w}`).join(' + ')
    : null
  return (
    <Panel title="ML classification" status={<RunStatus state={v.state} />}>
      <p className="mb-3 text-xs text-gray-500">
        A statistical classifier{parts ? ` (ensemble: ${parts})` : ''}. It is separate from the 18-rule
        verdict and does not replace it.
      </p>
      {v.ok ? (
        <div data-testid="ml-result">
          <div className="flex flex-wrap items-baseline gap-3">
            <span className="text-xs uppercase tracking-wide text-gray-400">Predicted class</span>
            <span className="text-lg font-semibold text-gray-900">{v.label}</span>
            {v.score !== undefined && (
              <span className="text-sm text-gray-600">
                ensemble score <strong>{formatScore(v.score)}</strong>
              </span>
            )}
          </div>
          <p className="mt-1 text-xs text-gray-500">
            The score is the model's uncalibrated probability for this class. It is not a certainty or a
            likelihood that the email is malicious.
          </p>
          {v.probabilities.length > 0 && (
            <table className="mt-3 w-full text-sm" aria-label="Class scores">
              <tbody>
                {v.probabilities.map((p) => (
                  <tr key={p.label}>
                    <td className="w-32 py-0.5 pr-2 text-gray-700">{p.label}</td>
                    <td className="py-0.5">
                      <div className="h-2 bg-gray-100">
                        <div
                          className="h-2 bg-indigo-500"
                          style={{ width: `${Math.round(Math.max(0, Math.min(1, p.value)) * 100)}%` }}
                        />
                      </div>
                    </td>
                    <td className="w-16 py-0.5 pl-2 text-right font-mono text-xs text-gray-600">{formatScore(p.value)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="mt-2 text-xs text-gray-400">
            Model {v.modelVersion ?? 'version not reported'}
            {v.untrained.length > 0 && ` · never predicted (no training data): ${v.untrained.join(', ')}`}
          </p>
        </div>
      ) : (
        <NotRun state={v.state}>
          {isHashOnly(ml) && <p className="mt-1 text-xs">{HASH_ONLY_NOTE}</p>}
          <p className="mt-1 text-xs font-medium">No classification was produced. This does not mean "legitimate".</p>
        </NotRun>
      )}
    </Panel>
  )
}

// ── B. SHAP ───────────────────────────────────────────────────────────────
export function ShapPanel({ explanation, ml }: { explanation: ShapExplanation | null | undefined; ml?: MlResult | null }) {
  const state = componentState(explanation)
  const cov = shapCoverage(explanation)
  const comps = Object.entries(explanation?.components ?? {})
  return (
    <Panel title="SHAP feature contributions" status={<RunStatus state={state} />}>
      {state.ran && comps.length > 0 ? (
        <div data-testid="shap-result">
          <p className="mb-2 bg-amber-50 px-3 py-2 text-xs text-amber-900" data-testid="shap-coverage">
            {cov.sentence}
            {!cov.notExplained.some((n) => n.component === 'transformer') && ' SHAP does not explain the DistilRoBERTa component.'}
          </p>
          {comps.map(([name, c]) => {
            const v = shapComponentView(name, c, explanation?.explained_label, ml)
            return (
            <div key={name} className="mt-3" data-testid={`shap-component-${name}`}>
              <p className="text-xs text-gray-500">
                <strong>{componentName(name)}</strong> ({c.explainer}) for class{' '}
                <strong>{explanation?.explained_label ?? 'not reported'}</strong>. Values are in the raw-margin space
                ({c.output_space}); they are not probabilities.
              </p>
              <p className="mt-1 text-xs text-gray-700" data-testid="shap-net">{v.netSentence}</p>
              {v.divergenceNote && (
                <p className="mt-1 bg-amber-50 px-3 py-2 text-xs text-amber-900" data-testid="shap-divergence">
                  <strong>Why the ensemble still predicts this class:</strong> {v.divergenceNote}
                </p>
              )}
              <div className="mt-2 grid grid-cols-[minmax(8rem,14rem)_1fr_1fr_4.5rem] items-center gap-x-2 gap-y-1 text-xs">
                <span className="font-semibold text-gray-500">Feature (value)</span>
                <span className="text-right font-semibold text-blue-700">← away from class</span>
                <span className="font-semibold text-red-700">toward class →</span>
                <span className="text-right font-semibold text-gray-500">SHAP</span>
                {shapRows(c).map((r) => (
                  <ShapBar key={r.feature} row={r} />
                ))}
                {v.hasRemainder && v.remainder !== undefined && (
                  <>
                    <span className="italic text-gray-500">other features (not listed)</span>
                    <span />
                    <span />
                    <span className="text-right font-mono text-gray-700">
                      {v.remainder > 0 ? '+' : ''}
                      {v.remainder.toFixed(3)}
                    </span>
                  </>
                )}
              </div>
              <p className="mt-2 text-xs text-gray-500" data-testid="shap-additivity">
                Additivity: base {formatScore(v.base)} + sum of contributions{' '}
                {formatScore(v.shownSum + (v.hasRemainder ? (v.remainder ?? 0) : 0))} = output {formatScore(v.output)}{' '}
                (check {v.displayedAdditivityOk || v.hasRemainder ? 'passed' : 'FAILED'}; backend check{' '}
                {c.additivity_ok ? 'passed' : 'FAILED'}).
              </p>
            </div>
            )
          })}
          {cov.notExplained.length > 0 && (
            <ul className="mt-3 space-y-0.5 text-xs text-gray-500">
              {cov.notExplained.map((n) => (
                <li key={n.component}>
                  Not explained: <strong>{componentName(n.component)}</strong>. {n.reason}
                </li>
              ))}
            </ul>
          )}
          {explanation?.disclaimer && (
            <p className="mt-3 text-xs italic text-gray-500" data-testid="shap-disclaimer">{explanation.disclaimer}</p>
          )}
        </div>
      ) : (
        <NotRun state={state.ran ? { ...state, message: 'SHAP returned no explained components.' } : state}>
          {isHashOnly(explanation) && <p className="mt-1 text-xs">{HASH_ONLY_NOTE}</p>}
        </NotRun>
      )}
    </Panel>
  )
}

function ShapBar({ row }: { row: ReturnType<typeof shapRows>[number] }) {
  const bar = (side: 'away' | 'toward') =>
    (row.shap < 0 ? 'away' : 'toward') === side ? (
      <div
        className={`h-3 ${side === 'away' ? 'ml-auto bg-blue-500' : 'bg-red-500'} ${row.aggregated ? 'opacity-50' : ''}`}
        style={{ width: `${Math.max(2, row.magnitudePct)}%` }}
        title={`${row.shap > 0 ? '+' : ''}${row.shap.toFixed(4)}`}
      />
    ) : null
  return (
    <>
      <span className={row.aggregated ? 'break-words italic text-gray-500' : 'truncate text-gray-800'} title={row.value}>
        <span className="font-mono">{row.feature}</span>
        {row.aggregated ? (
          <span className="text-gray-400"> (aggregate of {row.value || 'components'}; not an individual word or phrase)</span>
        ) : (
          row.value !== '' && <span className="text-gray-400"> ({row.value})</span>
        )}
      </span>
      <div data-direction={row.shap < 0 ? 'away' : 'toward'}>{bar('away')}</div>
      <div>{bar('toward')}</div>
      <span className="text-right font-mono text-gray-700">
        {row.shap > 0 ? '+' : ''}
        {row.shap.toFixed(3)}
      </span>
    </>
  )
}

// ── C. LLM forensic summary ───────────────────────────────────────────────
export function SummaryPanel({ fs, llmStatus }: { fs: ForensicSummary | null | undefined; llmStatus?: LlmStatus | null }) {
  const state = componentState(fs)
  const index = evidenceIndex(fs)
  const model = fs?.model
  return (
    <Panel
      title="AI-generated forensic interpretation"
      status={
        <span className="flex items-center gap-2">
          <span className=" bg-fuchsia-100 px-2 py-0.5 text-xs font-semibold text-fuchsia-800 ring-1 ring-inset ring-fuchsia-300">
            AI-generated
          </span>
          <RunStatus state={state} />
        </span>
      }
    >
      <p className="mb-3 bg-fuchsia-50 px-3 py-2 text-xs text-fuchsia-900" data-testid="ai-label">
        {fs?.label ?? 'AI-generated interpretation by a local language model. It may be wrong.'} It never
        replaces the rule-engine verdict or the ML classification.
      </p>
      <p className="mb-3 text-xs text-gray-500">
        Model: {model ? `${model.provider} / ${model.name}` : (llmStatus?.model ?? 'not reported')}
        {model?.digest && ` · digest ${model.digest.slice(0, 12)}`}
        {model?.local && ' · runs locally'}
        {typeof fs?.latency_ms === 'number' && ` · ${(fs.latency_ms / 1000).toFixed(1)} s`}
        {typeof fs?.attempts === 'number' && ` · attempts ${fs.attempts}`}
      </p>

      {!state.ran ? (
        <NotRun state={state} />
      ) : (
        <div className="space-y-4" data-testid="summary-result">
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Summary</h3>
            {fs?.summary ? (
              <p className="mt-1 whitespace-pre-line text-sm text-gray-800">{fs.summary}</p>
            ) : (
              <p className="mt-1 text-sm text-orange-800">The summary was withheld because it failed evidence validation.</p>
            )}
          </section>
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Assessment</h3>
            {fs?.assessment ? (
              <p className="mt-1 text-sm text-gray-800">{fs.assessment}</p>
            ) : (
              <p className="mt-1 text-sm text-orange-800">The assessment was withheld because it failed evidence validation.</p>
            )}
          </section>
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Findings (each cites evidence)</h3>
            {(fs?.findings ?? []).length === 0 ? (
              <p className="mt-1 text-sm text-gray-500">No findings passed validation.</p>
            ) : (
              <ol className="mt-1 space-y-2">
                {(fs?.findings ?? []).map((f, i) => (
                  <li key={i} className=" border border-gray-100 px-3 py-2" data-testid="summary-finding">
                    <div className="flex flex-wrap items-center gap-2">
                      <StatusBadge
                        kind={basisKind(f.basis)}
                        title={basisKind(f.basis) === 'verified'
                          ? 'Every cited item is observed/verified or a provider result'
                          : 'Rests on heuristic, header-claim or model evidence, or is an interpretation'}
                      />
                      <span className="text-sm text-gray-800">{f.statement}</span>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1" aria-label="Cited evidence">
                      {findingRefs(f, index).map((ref) =>
                        ref.item ? (
                          <EvidenceChip key={ref.id} id={ref.id} title={ref.item.statement} />
                        ) : (
                          <span key={ref.id} className=" bg-red-50 px-1.5 py-0.5 font-mono text-xs text-red-700">
                            {ref.id} (not in evidence list)
                          </span>
                        ),
                      )}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </section>
          {(fs?.rejected_findings ?? []).length > 0 && (
            <details className=" bg-gray-50 px-3 py-2" data-testid="rejected-findings">
              <summary className="cursor-pointer text-xs font-semibold text-gray-600">
                {fs?.rejected_findings?.length} model statement(s) rejected by validation. These are not evidence.
              </summary>
              <ul className="mt-2 space-y-1 text-xs text-gray-600">
                {(fs?.rejected_findings ?? []).map((r, i) => (
                  <li key={i}>
                    <span className="line-through decoration-gray-400">{r.statement}</span>{' '}
                    <span className="text-red-700">({r.reason})</span>
                  </li>
                ))}
              </ul>
            </details>
          )}

          <BulletList title="Limitations (stated by the model)" items={fs?.limitations} />
          {(fs?.validation?.flags ?? []).length > 0 && (
            <BulletList
              title="Validation flags"
              items={(fs?.validation?.flags ?? []).map((f) => `${f.field}: ${f.problems.join('; ')}`)}
            />
          )}
        </div>
      )}

      <div className="mt-4">
        <Recommendations fs={fs} index={index} />
      </div>
      <p className="mt-4 text-xs text-gray-500" data-testid="privacy-note">{PRIVACY_NOTE}</p>
      {(fs?.security?.injection_patterns_detected ?? []).length > 0 && (
        <p className="mt-4 bg-red-50 px-3 py-2 text-xs text-red-800" data-testid="injection-warning">
          The email contains text that looks like a prompt-injection attempt (
          {fs?.security?.injection_patterns_detected.join(', ')}). It was treated as data, not as instructions.
        </p>
      )}
      {fs?.security && (
        <p className="mt-2 text-xs text-gray-400">
          Sent to the local model: {fs.security.body_chars_sent} characters of redacted body text
          {Object.keys(fs.security.redactions).length > 0 &&
            ` · redacted: ${Object.entries(fs.security.redactions).map(([k, n]) => `${k} ×${n}`).join(', ')}`}
          {fs.security.endpoint_local_only && ' · local endpoint only'}
        </p>
      )}
    </Panel>
  )
}

export function FinancialWarning({ fs }: { fs: ForensicSummary | null | undefined }) {
  const w = financialWarning(fs)
  if (!w) return null
  return (
    <div role="alert" data-testid="financial-warning"
      className=" border-2 border-red-300 bg-red-50 px-4 py-3 text-sm text-red-900">
      <p className="font-semibold">Independent verification required</p>
      <p className="mt-1">{w.text}</p>
      {w.signals.length > 0 && <p className="mt-1 text-xs text-red-700">Signals: {w.signals.join(', ')}</p>}
    </div>
  )
}

function Recommendations({ fs, index }: { fs: ForensicSummary | null | undefined; index: Map<string, unknown> }) {
  const g = recommendationGroups(fs)
  if (!g.graded) {
    if (!componentState(fs).ran) return null
    return (
      <BulletList
        title="Recommended actions (model; generated before recommendation grounding, not checked against the evidence)"
        items={g.legacy}
      />
    )
  }
  const chips = (r: Recommendation) =>
    r.evidence_ids.length > 0 && (
      <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
        {r.evidence_ids.map((id) =>
          index.has(id) ? <EvidenceChip key={id} id={id} title="Supporting evidence" /> : (
            <span key={id} className=" bg-red-50 px-1.5 py-0.5 font-mono text-xs text-red-700">{id} (not in evidence list)</span>
          ),
        )}
      </span>
    )
  return (
    <section data-testid="recommendations" className="space-y-3">
      {g.linked.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">
            {g.constrained
              ? 'Evidence-linked recommendations (system template; evidence IDs chosen deterministically, not by the model)'
              : 'Evidence-linked recommendations (model; each relies on the cited items)'}
          </h3>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-gray-700">
            {g.linked.map((r, i) => (
              <li key={i} data-testid="rec-evidence_linked">
                {r.text}
                {chips(r)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {g.general.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">
            {g.constrained
              ? 'General recommendations (system templates: standard practice, not findings, not AI-discovered)'
              : 'General investigative recommendations (not established by a specific evidence item)'}
          </h3>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-gray-700">
            {g.general.map((r, i) => (
              <li key={i} data-testid="rec-general">
                {r.text}
                {!g.constrained && (
                  <span className="ml-1 text-xs text-gray-400">({r.origin === 'system' ? 'system' : 'model'})</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {g.rejected.length > 0 && (
        <details open className=" border border-red-200 bg-red-50 px-3 py-2" data-testid="rejected-recommendations">
          <summary className="cursor-pointer text-xs font-semibold text-red-800">
            {g.rejected.length} model suggestion(s) rejected as unsafe or unsupported. Shown for transparency; do not follow.
          </summary>
          <ul className="mt-2 space-y-1 text-xs text-gray-700">
            {g.rejected.map((r, i) => (
              <li key={i}>
                <span className="line-through decoration-red-400">{r.text}</span>{' '}
                <span className="text-red-700">({r.reason})</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  )
}

function BulletList({ title, items }: { title: string; items?: string[] }) {
  if (!items || items.length === 0) return null
  return (
    <section>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">{title}</h3>
      <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm text-gray-700">
        {items.map((x, i) => (
          <li key={i}>{x}</li>
        ))}
      </ul>
    </section>
  )
}

// ── D. Deterministic evidence list (shared by findings) ───────────────────
export function EvidencePanel({ fs }: { fs: ForensicSummary | null | undefined }) {
  const evidence = fs?.evidence ?? []
  const unavailable = fs?.unavailable_information ?? []
  return (
    <Panel title="Evidence list (deterministic)">
      <p className="mb-3 text-xs text-gray-500">
        The analysis pipeline builds this list; the language model does not. Findings above cite these IDs.
      </p>
      {evidence.length === 0 ? (
        <p className="text-sm text-gray-500">No evidence list was returned.</p>
      ) : (
        <ul className="space-y-1.5">
          {evidence.map((e) => {
            const meta = categoryMeta(e.category)
            return (
              <li
                key={e.id}
                id={`evidence-${e.id}`}
                tabIndex={-1}
                className="flex flex-wrap items-start gap-2 px-1 py-0.5 text-sm transition-shadow focus:outline-none"
              >
                <span className="w-9 shrink-0 font-mono text-xs text-gray-500">{e.id}</span>
                <span title={meta.hint} className={`shrink-0 px-2 py-0.5 text-xs ring-1 ring-inset ${meta.className}`}>
                  {meta.label}
                </span>
                <span className="shrink-0 font-mono text-xs text-gray-400">{e.source}</span>
                <span className="min-w-0 flex-1 break-words text-gray-800">{e.statement}</span>
              </li>
            )
          })}
        </ul>
      )}
      {unavailable.length > 0 && (
        <div className="mt-4 bg-gray-50 px-3 py-2" data-testid="unavailable-info">
          <p className="text-xs font-semibold text-gray-600">Checks that did not run or returned nothing (not passed)</p>
          <ul className="mt-1 space-y-0.5 text-xs text-gray-600">
            {unavailable.map((u, i) => (
              <li key={i}>
                <span className="font-mono">{u.check}</span>: {u.reason} <StatusBadge kind="unavailable" />
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  )
}

// ── Tab container ─────────────────────────────────────────────────────────
export function AssessmentView({
  assessment,
  loading,
  error,
  generating,
  generateError,
  onGenerate,
  canGenerate = true,
  mlStatus,
  llmStatus,
  history = [],
  onSelectVersion,
  elapsedSeconds = 0,
}: {
  assessment: Assessment | null
  loading: boolean
  error: string | null
  generating: boolean
  generateError: string | null
  onGenerate: () => void
  canGenerate?: boolean
  mlStatus?: MlStatus | null
  llmStatus?: LlmStatus | null
  history?: AssessmentSummary[]
  onSelectVersion?: (assessmentId: string) => void
  elapsedSeconds?: number
}) {
  const [showStatus, setShowStatus] = useState(false)
  if (loading) return <Spinner label="Loading AI assessment…" />
  const latestId = history[0]?.assessment_id
  const viewingOld = Boolean(assessment?.assessment_id && latestId && assessment.assessment_id !== latestId)
  const generateButton = (label: string, primary: boolean) => !canGenerate ? (
    <span className="text-xs text-gray-400" data-testid="generate-not-permitted">Your role cannot generate AI assessments.</span>
  ) : (
    <button
      onClick={onGenerate}
      disabled={generating}
      aria-busy={generating}
      data-testid="generate-button"
      className={
        primary
          ? ' bg-indigo-600 px-3 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-gray-300'
          : ' border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:text-gray-300'
      }
    >
      {generating ? 'Generating…' : label}
    </button>
  )
  return (
    <div className="space-y-4">
      <div className=" border border-gray-200 bg-white px-4 py-3 text-xs text-gray-600 ">
        <p>
          This tab holds three <strong>separate</strong> assessments: an ML classification, a SHAP explanation
          of part of that classifier, and a language-model interpretation. The deterministic rule-engine
          verdict and evidence on the Overview and Findings tabs remain the primary record. Nothing here
          overrides them.
        </p>
        <button className="mt-1 text-indigo-700 underline" onClick={() => setShowStatus((s) => !s)}>
          {showStatus ? 'Hide' : 'Show'} model availability
        </button>
        {showStatus && (
          <ul className="mt-1 space-y-0.5" data-testid="model-availability">
            <li>
              ML models: <RunStatus state={componentState(mlStatus ?? undefined)} />{' '}
              {mlStatus?.model_version ?? mlStatus?.reason ?? ''}
            </li>
            <li>
              Local LLM: <RunStatus state={componentState(llmStatus ?? undefined)} />{' '}
              {llmStatus?.status === 'ok' ? `${llmStatus.model} (local only)` : (llmStatus?.reason ?? '')}
            </li>
          </ul>
        )}
      </div>

      {generating && (
        <div className=" border border-indigo-200 bg-indigo-50 px-4 py-3 text-sm text-indigo-900" role="status" data-testid="generating">
          <div className="flex items-center gap-2">
            <Spinner />
            <span>
              Generating the AI assessment locally… <strong data-testid="elapsed">{elapsedSeconds}s</strong> elapsed.
            </span>
          </div>
          <p className="mt-1 text-xs">
            Local analysis usually takes about 1–2 minutes. The backend runs forensics, then ML and SHAP when the
            original bytes are available, then the local Mistral model. It does not report which stage is running,
            so no progress percentage is shown. The rule-based analysis on the other tabs stays available.
          </p>
        </div>
      )}

      {error && <ErrorAlert message={`Could not load the stored assessment: ${error}`} />}
      {generateError && (
        <div data-testid="generate-error">
          <ErrorAlert message={`Generation failed: ${generateError}`} />
          {!generating && <div className="mt-2">{generateButton('Retry', false)}</div>}
        </div>
      )}

      {!assessment && !error ? (
        <div className="space-y-3">
          <EmptyState
            title="No AI assessment has been generated for this analysis"
            hint="You can generate the local-LLM forensic summary now. It takes about 1–2 minutes. ML and SHAP need the original email bytes, which a stored analysis keeps only under the raw evidence policy."
          />
          <div className="text-center">{generateButton('Generate AI forensic summary', true)}</div>
        </div>
      ) : assessment ? (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-gray-500">
            <span data-testid="assessment-version">
              {assessment.version !== undefined ? `Version v${assessment.version}` : 'Unversioned assessment'}
              {latestId && assessment.assessment_id === latestId && ' (latest)'} · generated{' '}
              {assessment.generated_at ? formatDate(assessment.generated_at) : 'at an unknown time'} · source{' '}
              {assessment.source === 'upload'
                ? 'upload (original bytes available)'
                : assessment.source === 'stored_analysis'
                  ? 'stored analysis (original bytes not retained unless the evidence policy is raw)'
                  : (assessment.source ?? 'unknown')}
            </span>
            <span className="flex items-center gap-2">
              {history.length > 1 && onSelectVersion && (
                <label className="flex items-center gap-1">
                  History
                  <select
                    data-testid="version-select"
                    className=" border border-gray-300 bg-white px-1 py-0.5 text-xs"
                    value={assessment.assessment_id ?? ''}
                    onChange={(e) => onSelectVersion(e.target.value)}
                    disabled={generating}
                  >
                    {history.map((h, i) => (
                      <option key={h.assessment_id} value={h.assessment_id}>
                        v{h.version}
                        {i === 0 ? ' (latest)' : ''} · {h.generated_at ? formatDate(h.generated_at) : 'unknown time'}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {generateButton('Regenerate (new version)', false)}
            </span>
          </div>
          <FinancialWarning fs={assessment.forensic_summary} />
          {viewingOld && (
            <p className=" bg-amber-50 px-3 py-2 text-xs text-amber-900" data-testid="old-version-banner">
              You are viewing an earlier version (v{assessment.version}). The latest is v{history[0]?.version}. A PDF
              downloaded now will contain this version.
            </p>
          )}
          <div className="grid items-start gap-4 lg:grid-cols-2">
            <MlPanel ml={assessment.ml} mlStatus={mlStatus} />
            <ShapPanel explanation={assessment.explanation} ml={assessment.ml} />
          </div>
          <SummaryPanel fs={assessment.forensic_summary} llmStatus={llmStatus} />
          <EvidencePanel fs={assessment.forensic_summary} />
        </>
      ) : null}
    </div>
  )
}

// ── Compact overview card (kept visually separate from the rule verdict) ──
export function AssessmentOverviewCard({
  assessment,
  loading,
  onOpen,
}: {
  assessment: Assessment | null
  loading: boolean
  onOpen: () => void
}) {
  const v = mlView(assessment?.ml)
  const fsState = componentState(assessment?.forensic_summary)
  return (
    <Panel title="Other assessments (separate from the rule verdict)">
      {loading ? (
        <Spinner label="Loading…" />
      ) : !assessment ? (
        <p className="text-sm text-gray-500">No ML / SHAP / AI assessment has been generated.</p>
      ) : (
        <ul className="space-y-1 text-sm" data-testid="overview-assessment">
          <li className="flex flex-wrap items-center gap-2">
            <span className="text-gray-500">ML classification:</span>
            {v.ok ? (
              <strong>
                {v.label} ({formatScore(v.score)} score)
              </strong>
            ) : (
              <RunStatus state={v.state} />
            )}
          </li>
          <li className="flex flex-wrap items-center gap-2">
            <span className="text-gray-500">AI-generated summary:</span>
            <RunStatus state={fsState} />
          </li>
        </ul>
      )}
      <button onClick={onOpen} className="mt-2 text-xs text-indigo-700 underline">
        Open AI assessment
      </button>
    </Panel>
  )
}
